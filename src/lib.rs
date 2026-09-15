// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

//! Continuous admission and streaming enforcement driven by an external policy authority.
//!
//! A [`PolicyGate`] answers one question about a caller-chosen subject type: is this subject
//! allowed right now? Verdicts come from a caller-supplied [`DecisionSource`] bound to a single
//! policy scope, and are cached in a bounded, TTL-evicted subject map that one [`DecisionWatcher`]
//! keeps current from the authority's change stream.
//!
//! Admission is continuous rather than one-shot: [`PolicyGate::admit`] hands back a [`Permit`]
//! that keeps observing its subject, so work that was allowed when it started can be stopped once
//! the authority denies it.
//!
//! # Runtime contract
//!
//! [`PolicyGate::new`] returns three values that belong to one decision source: the gate, its
//! watcher, and a health handle. The watcher is a future that must be polled continuously —
//! normally by spawning it — for as long as the gate is used.
//!
//! While the watch is down the gate serves no cached state: existing permits report
//! [`PermitState::Stale`], and new admissions wait for reconnection and then fail with
//! [`AdmissionUnavailable`] once [`PolicyGateConfig::admission_timeout`] elapses. Dropping the
//! watcher stops new admissions permanently and leaves every permit stale.
//!
//! Absolute decision freshness is opt-in. When configured, ordinary cache access never extends a
//! decision's deadline, and the watcher marks it stale at expiry. An optional refresh-ahead setting
//! proactively refreshes subjects with live permits. [`PolicyGateConfig::subject_ttl`] remains the
//! separate sliding idle-cache eviction policy.
//!
//! # Example
//!
//! ```
//! # #[cfg(feature = "tokio")]
//! # {
//! use std::sync::Arc;
//!
//! use policy_gate::{Admission, DecisionSource, PermitState, PolicyGate, PolicyGateConfig};
//!
//! async fn run<S>(source: Arc<S>) -> Result<(), Box<dyn std::error::Error>>
//! where
//!     S: DecisionSource<String>,
//! {
//!     let config = PolicyGateConfig::builder().build()?;
//!     let (gate, watcher, _health) = PolicyGate::new(&config, source);
//!     tokio::spawn(watcher);
//!
//!     match gate.admit("organization-123".to_owned()).await? {
//!         Admission::Allowed(mut permit) => {
//!             // The permit keeps tracking the subject for as long as the work runs.
//!             if permit.changed().await == PermitState::Denied {
//!                 // Abort the admitted work.
//!             }
//!         }
//!         Admission::Denied => {}
//!     }
//!     Ok(())
//! }
//! # }
//! ```
//!
//! ## HTTP middleware
//!
//! Authenticate first, place a trusted subject in the request extensions, and let the policy
//! layer enforce the authority's decision for that subject:
//!
//! ```no_run
//! # use core::future::Future;
//! # use core::pin::Pin;
//! # use core::task::{Context, Poll};
//! # use std::sync::Arc;
//! # use axum::extract::Request;
//! # use axum::http::{StatusCode, header};
//! # use axum::middleware::{self, Next};
//! # use axum::response::Response;
//! # use axum::{Router, routing::get};
//! # use futures_core::Stream;
//! # use policy_gate::{Decision, DecisionChange, DecisionSource, DecisionSourceError};
//! use policy_gate::{
//!     AxumBodyAdapter, PolicyGate, PolicyGateConfig, PolicyGateLayer,
//!     PolicyGateLayerConfig, RequestPolicy,
//! };
//!
//! #[derive(Clone)]
//! struct AuthenticatedUser(String);
//!
//! #[derive(Clone, Copy)]
//! struct UserFromAuth;
//! impl RequestPolicy<String> for UserFromAuth {
//!     fn subject<B>(&self, request: &http::Request<B>) -> Option<String> {
//!         request.extensions().get::<AuthenticatedUser>().map(|u| u.0.clone())
//!     }
//!     fn enforce_request_body<B>(&self, _: &http::Request<B>) -> bool { false }
//! }
//!
//! async fn authenticate(mut request: Request, next: Next) -> Result<Response, StatusCode> {
//!     let token = request.headers().get(header::AUTHORIZATION)
//!         .and_then(|value| value.to_str().ok())
//!         .ok_or(StatusCode::UNAUTHORIZED)?;
//!     let user = validate_token(token).ok_or(StatusCode::UNAUTHORIZED)?;
//!     request.extensions_mut().insert(AuthenticatedUser(user));
//!     Ok(next.run(request).await)
//! }
//! # fn validate_token(_: &str) -> Option<String> { Some("user-123".into()) }
//! # struct Never;
//! # impl Stream for Never {
//! #     type Item = Result<DecisionChange<String>, DecisionSourceError>;
//! #     fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
//! #         Poll::Pending
//! #     }
//! # }
//! # struct Authority;
//! # impl DecisionSource<String> for Authority {
//! #     type Changes = Never;
//! #     fn get_subject_decision(&self, _: &String)
//! #         -> impl Future<Output = Result<Decision, DecisionSourceError>> + Send {
//! #         core::future::ready(Ok(Decision::Allowed))
//! #     }
//! #     fn watch_subject_decisions(&self)
//! #         -> impl Future<Output = Result<Self::Changes, DecisionSourceError>> + Send {
//! #         core::future::ready(Ok(Never))
//! #     }
//! # }
//! # #[tokio::main]
//! # async fn main() {
//! let config = PolicyGateConfig::builder().build().unwrap();
//! let (gate, watcher, _) = PolicyGate::new(&config, Arc::new(Authority));
//! tokio::spawn(watcher);
//! let policy = PolicyGateLayer::new(
//!     gate,
//!     &PolicyGateLayerConfig::new("access denied", "missing authenticated user"),
//!     UserFromAuth,
//!     AxumBodyAdapter,
//! );
//!
//! // Axum applies layers bottom-to-top, so authentication runs before policy enforcement.
//! let app = Router::new()
//!     .route("/", get(|| async { "allowed" }))
//!     .layer(policy)
//!     .layer(middleware::from_fn(authenticate));
//! # let _: Router = app;
//! # }
//! ```
//!
//! # Feature flags
//!
//! The core gate, its configuration, the watcher, and the metrics trait are always available. Each
//! transport adapter is optional:
//!
//! | Feature | Enables |
//! | --- | --- |
//! | `tokio` | `TokioTimeDriver`, used by the convenience constructors (default) |
//! | `tower-layer` | `PolicyGateLayer`, `PolicyGateRuntime`, and streaming body enforcement |
//! | `axum-body` | `AxumBodyAdapter`, for type-erased Axum bodies; implies `tower-layer` |
//! | `tonic-client` | `TonicDecisionSource` over the bundled policy-authority protocol (default) |
//! | `tonic-layer` | `TonicRejectionResponse`, for gRPC status rendering; implies `tower-layer` |

use core::fmt;
use core::time::Duration;
use std::time::Instant;

mod gate;
#[cfg(feature = "tonic-layer")]
mod grpc;
#[cfg(feature = "tower-layer")]
mod layer;
mod metrics;
#[cfg(feature = "tonic-client")]
#[allow(unknown_lints, unused_qualifications, clippy::all, clippy::pedantic)]
mod policy_proto;
#[cfg(feature = "tower-layer")]
mod runtime;
#[cfg(feature = "tower-layer")]
mod stream;
mod time;
#[cfg(feature = "tonic-client")]
mod tonic_source;
mod watcher;

pub use gate::{
    Admission, AdmissionUnavailable, DecisionSource, Permit, PermitState, PolicyGate, Subject,
};
#[cfg(feature = "tonic-layer")]
pub use grpc::TonicRejectionResponse;
#[cfg(feature = "axum-body")]
pub use layer::AxumBodyAdapter;
#[cfg(feature = "tower-layer")]
pub use layer::{
    BodyAdapter, BodySide, BoxBodyError, HttpRejectionResponse, PolicyGateLayer,
    PolicyGateLayerConfig, PolicyGateMiddleware, RejectionResponse, RequestPolicy, StreamRejection,
    StreamRejectionResponse, UnavailableResponse, UnavailableResponseAdapter,
};
pub use metrics::{NoopPolicyGateMetrics, PolicyGateMetrics};
#[cfg(feature = "tower-layer")]
pub use runtime::PolicyGateRuntime;
pub use time::{TimeDriver, TimeoutElapsed, TokioTimeDriver};
#[cfg(feature = "tonic-client")]
pub use tonic_source::{
    ScopeEchoPolicy, TonicDecisionSource, TonicDecisionSourceConfig,
    TonicDecisionSourceConfigError, TonicDecisionStream,
};
pub use watcher::{DecisionSourceHealth, DecisionSourceHealthStatus, DecisionWatcher};

/// Gate, watcher, and health handle created for one decision source.
pub type PolicyGateParts<T, C, M = NoopPolicyGateMetrics, D = TokioTimeDriver> = (
    PolicyGate<T, C, M, D>,
    DecisionWatcher<T, C, M, D>,
    std::sync::Arc<DecisionSourceHealth<D>>,
);

/// Default [`PolicyGateConfigBuilder::unary_timeout`].
pub const DEFAULT_UNARY_TIMEOUT: Duration = Duration::from_secs(2);
/// Default [`PolicyGateConfigBuilder::admission_timeout`].
pub const DEFAULT_ADMISSION_TIMEOUT: Duration = Duration::from_secs(10);
/// Default [`PolicyGateConfigBuilder::initial_admission_retry_delay`].
pub const DEFAULT_INITIAL_ADMISSION_RETRY_DELAY: Duration = Duration::from_millis(100);
/// Default [`PolicyGateConfigBuilder::max_admission_retry_delay`].
pub const DEFAULT_MAX_ADMISSION_RETRY_DELAY: Duration = Duration::from_secs(1);
/// Default [`PolicyGateConfigBuilder::permanent_failure_cooldown`].
pub const DEFAULT_PERMANENT_FAILURE_COOLDOWN: Duration = Duration::from_secs(1);
/// Default [`PolicyGateConfigBuilder::snapshot_republish_interval`].
pub const DEFAULT_SNAPSHOT_REPUBLISH_INTERVAL: Duration = Duration::from_millis(10);
/// Default [`PolicyGateConfigBuilder::initial_reconnect_delay`].
pub const DEFAULT_INITIAL_RECONNECT_DELAY: Duration = Duration::from_millis(100);
/// Default [`PolicyGateConfigBuilder::max_reconnect_delay`].
pub const DEFAULT_MAX_RECONNECT_DELAY: Duration = Duration::from_secs(5);
/// Default [`PolicyGateConfigBuilder::watch_events_per_yield`].
pub const DEFAULT_WATCH_EVENTS_PER_YIELD: usize = 64;
/// Default [`PolicyGateConfigBuilder::max_subjects`].
pub const DEFAULT_MAX_SUBJECTS: usize = 65_536;
/// Default [`PolicyGateConfigBuilder::subject_ttl`].
pub const DEFAULT_SUBJECT_TTL: Duration = Duration::from_secs(3_600);

/// Authoritative decision returned for one subject.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    /// The authority holds no decision for this subject.
    ///
    /// As a watch change it drops the subject from the gate's cache and marks its permits stale.
    /// As a lookup result it is not authoritative, so the gate retries within its deadline.
    Unspecified,
    /// The subject may start and continue work.
    Allowed,
    /// The subject may not start work, and admitted work must stop.
    Denied,
}

/// One normalized authoritative subject-state update.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionChange<T> {
    /// Subject the update applies to.
    pub subject: T,
    /// Decision now in force for the subject.
    pub decision: Decision,
}

/// How the runtime should handle a decision-source failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionSourceErrorKind {
    /// Retryable failure, such as a timeout or an unavailable authority.
    ///
    /// Admission retries with backoff until its deadline expires.
    Transient,
    /// The request cannot succeed as issued, such as an unknown scope or a rejected credential.
    ///
    /// Admission fails immediately; a later admission for the same subject waits out
    /// [`PolicyGateConfig::permanent_failure_cooldown`] before calling the source again.
    Permanent,
    /// The response violated the protocol contract, such as a mismatched scope echo or an
    /// undecodable decision or subject identifier.
    ///
    /// Handled like [`DecisionSourceErrorKind::Permanent`] and additionally reported through
    /// [`PolicyGateMetrics::wire_failure`].
    Wire,
}

/// Decision source request or protocol failure.
///
/// The [`Display`](fmt::Display) output is the message supplied by the source adapter; the
/// [`kind`](DecisionSourceError::kind) is what decides how the runtime reacts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionSourceError {
    kind: DecisionSourceErrorKind,
    message: String,
}

impl DecisionSourceError {
    /// Creates a failure of `kind` whose `message` is surfaced through [`fmt::Display`] and logs.
    #[must_use]
    pub fn new(kind: DecisionSourceErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Returns how the runtime treats this failure.
    #[must_use]
    pub const fn kind(&self) -> DecisionSourceErrorKind {
        self.kind
    }
}

impl fmt::Display for DecisionSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl core::error::Error for DecisionSourceError {}

/// Timing and cache configuration owned by the transport-neutral gate.
///
/// Build one with [`PolicyGateConfig::builder`]; every field defaults to the matching
/// `DEFAULT_*` constant, and [`PolicyGateConfigBuilder::build`] enforces the cross-field rules
/// the runtime relies on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyGateConfig {
    unary_timeout: Duration,
    admission_timeout: Duration,
    initial_admission_retry_delay: Duration,
    max_admission_retry_delay: Duration,
    permanent_failure_cooldown: Duration,
    snapshot_republish_interval: Duration,
    initial_reconnect_delay: Duration,
    max_reconnect_delay: Duration,
    watch_events_per_yield: usize,
    max_subjects: usize,
    subject_ttl: Duration,
    decision_freshness_ttl: Option<Duration>,
    decision_refresh_ahead: Option<Duration>,
}

impl PolicyGateConfig {
    /// Starts a builder with the default timing and capacity values.
    #[must_use]
    pub const fn builder() -> PolicyGateConfigBuilder {
        PolicyGateConfigBuilder {
            unary_timeout: DEFAULT_UNARY_TIMEOUT,
            admission_timeout: DEFAULT_ADMISSION_TIMEOUT,
            initial_admission_retry_delay: DEFAULT_INITIAL_ADMISSION_RETRY_DELAY,
            max_admission_retry_delay: DEFAULT_MAX_ADMISSION_RETRY_DELAY,
            permanent_failure_cooldown: DEFAULT_PERMANENT_FAILURE_COOLDOWN,
            snapshot_republish_interval: DEFAULT_SNAPSHOT_REPUBLISH_INTERVAL,
            initial_reconnect_delay: DEFAULT_INITIAL_RECONNECT_DELAY,
            max_reconnect_delay: DEFAULT_MAX_RECONNECT_DELAY,
            watch_events_per_yield: DEFAULT_WATCH_EVENTS_PER_YIELD,
            max_subjects: DEFAULT_MAX_SUBJECTS,
            subject_ttl: DEFAULT_SUBJECT_TTL,
            decision_freshness_ttl: None,
            decision_refresh_ahead: None,
        }
    }

    /// Per-attempt budget for one [`DecisionSource::get_subject_decision`] call.
    #[must_use]
    pub const fn unary_timeout(&self) -> Duration {
        self.unary_timeout
    }

    /// Total budget for one [`PolicyGate::admit`] call.
    ///
    /// It covers waiting for the watch, every lookup attempt, and every retry. It is also the
    /// window after which [`DecisionSourceHealth::status`] reports
    /// [`DecisionSourceHealthStatus::Failed`], and the minimum spacing between readmission
    /// attempts made by an enforced stream.
    #[must_use]
    pub const fn admission_timeout(&self) -> Duration {
        self.admission_timeout
    }

    /// First delay in the admission retry backoff after a transient failure.
    #[must_use]
    pub const fn initial_admission_retry_delay(&self) -> Duration {
        self.initial_admission_retry_delay
    }

    /// Ceiling for the doubling admission retry backoff.
    #[must_use]
    pub const fn max_admission_retry_delay(&self) -> Duration {
        self.max_admission_retry_delay
    }

    /// Minimum spacing between lookups for a subject whose last lookup failed permanently.
    #[must_use]
    pub const fn permanent_failure_cooldown(&self) -> Duration {
        self.permanent_failure_cooldown
    }

    /// Minimum interval between rebuilds of the cached decision snapshot read by
    /// [`PolicyGate::try_cached`].
    ///
    /// Until a rebuild runs, a newly cached subject is served through the slower map path in
    /// [`PolicyGate::admit`].
    #[must_use]
    pub const fn snapshot_republish_interval(&self) -> Duration {
        self.snapshot_republish_interval
    }

    /// First delay before the watcher reopens a lost watch, before jitter.
    #[must_use]
    pub const fn initial_reconnect_delay(&self) -> Duration {
        self.initial_reconnect_delay
    }

    /// Ceiling for the doubling reconnect backoff.
    ///
    /// It doubles as the stability threshold: a watch that stays open this long resets the backoff
    /// and reports healthy.
    #[must_use]
    pub const fn max_reconnect_delay(&self) -> Duration {
        self.max_reconnect_delay
    }

    /// Number of watch changes the watcher applies before yielding to the async runtime.
    #[must_use]
    pub const fn watch_events_per_yield(&self) -> usize {
        self.watch_events_per_yield
    }

    /// Capacity of the cached subject map.
    ///
    /// Inserting past it evicts the least recently used subject and marks that subject's permits
    /// stale.
    #[must_use]
    pub const fn max_subjects(&self) -> usize {
        self.max_subjects
    }

    /// Idle time after which a cached subject is evicted and its permits are marked stale.
    #[must_use]
    pub const fn subject_ttl(&self) -> Duration {
        self.subject_ttl
    }

    /// Absolute age after which an authoritative decision is no longer usable.
    ///
    /// Unlike [`PolicyGateConfig::subject_ttl`], ordinary access does not extend this deadline.
    /// `None` disables decision freshness checks and preserves the original cache behavior.
    #[must_use]
    pub const fn decision_freshness_ttl(&self) -> Option<Duration> {
        self.decision_freshness_ttl
    }

    /// How long before freshness expiry a subject with a live permit is refreshed.
    ///
    /// `None` disables proactive refresh while allowing absolute expiry to remain enabled.
    #[must_use]
    pub const fn decision_refresh_ahead(&self) -> Option<Duration> {
        self.decision_refresh_ahead
    }
}

/// Builds one validated gate configuration.
///
/// Each setter documents only its default; see the matching [`PolicyGateConfig`] accessor for what
/// the value controls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyGateConfigBuilder {
    unary_timeout: Duration,
    admission_timeout: Duration,
    initial_admission_retry_delay: Duration,
    max_admission_retry_delay: Duration,
    permanent_failure_cooldown: Duration,
    snapshot_republish_interval: Duration,
    initial_reconnect_delay: Duration,
    max_reconnect_delay: Duration,
    watch_events_per_yield: usize,
    max_subjects: usize,
    subject_ttl: Duration,
    decision_freshness_ttl: Option<Duration>,
    decision_refresh_ahead: Option<Duration>,
}

impl PolicyGateConfigBuilder {
    /// Sets [`PolicyGateConfig::unary_timeout`]. Defaults to [`DEFAULT_UNARY_TIMEOUT`].
    #[must_use]
    pub const fn unary_timeout(mut self, timeout: Duration) -> Self {
        self.unary_timeout = timeout;
        self
    }

    /// Sets [`PolicyGateConfig::admission_timeout`]. Defaults to [`DEFAULT_ADMISSION_TIMEOUT`].
    #[must_use]
    pub const fn admission_timeout(mut self, timeout: Duration) -> Self {
        self.admission_timeout = timeout;
        self
    }

    /// Sets [`PolicyGateConfig::initial_admission_retry_delay`]. Defaults to
    /// [`DEFAULT_INITIAL_ADMISSION_RETRY_DELAY`].
    #[must_use]
    pub const fn initial_admission_retry_delay(mut self, delay: Duration) -> Self {
        self.initial_admission_retry_delay = delay;
        self
    }

    /// Sets [`PolicyGateConfig::max_admission_retry_delay`]. Defaults to
    /// [`DEFAULT_MAX_ADMISSION_RETRY_DELAY`].
    #[must_use]
    pub const fn max_admission_retry_delay(mut self, delay: Duration) -> Self {
        self.max_admission_retry_delay = delay;
        self
    }

    /// Sets [`PolicyGateConfig::permanent_failure_cooldown`]. Defaults to
    /// [`DEFAULT_PERMANENT_FAILURE_COOLDOWN`].
    #[must_use]
    pub const fn permanent_failure_cooldown(mut self, cooldown: Duration) -> Self {
        self.permanent_failure_cooldown = cooldown;
        self
    }

    /// Sets [`PolicyGateConfig::snapshot_republish_interval`]. Defaults to
    /// [`DEFAULT_SNAPSHOT_REPUBLISH_INTERVAL`].
    #[must_use]
    pub const fn snapshot_republish_interval(mut self, interval: Duration) -> Self {
        self.snapshot_republish_interval = interval;
        self
    }

    /// Sets [`PolicyGateConfig::initial_reconnect_delay`]. Defaults to
    /// [`DEFAULT_INITIAL_RECONNECT_DELAY`].
    #[must_use]
    pub const fn initial_reconnect_delay(mut self, delay: Duration) -> Self {
        self.initial_reconnect_delay = delay;
        self
    }

    /// Sets [`PolicyGateConfig::max_reconnect_delay`]. Defaults to
    /// [`DEFAULT_MAX_RECONNECT_DELAY`].
    #[must_use]
    pub const fn max_reconnect_delay(mut self, delay: Duration) -> Self {
        self.max_reconnect_delay = delay;
        self
    }

    /// Sets [`PolicyGateConfig::watch_events_per_yield`]. Defaults to
    /// [`DEFAULT_WATCH_EVENTS_PER_YIELD`].
    #[must_use]
    pub const fn watch_events_per_yield(mut self, events: usize) -> Self {
        self.watch_events_per_yield = events;
        self
    }

    /// Sets [`PolicyGateConfig::max_subjects`]. Defaults to [`DEFAULT_MAX_SUBJECTS`].
    #[must_use]
    pub const fn max_subjects(mut self, max_subjects: usize) -> Self {
        self.max_subjects = max_subjects;
        self
    }

    /// Sets [`PolicyGateConfig::subject_ttl`]. Defaults to [`DEFAULT_SUBJECT_TTL`].
    #[must_use]
    pub const fn subject_ttl(mut self, subject_ttl: Duration) -> Self {
        self.subject_ttl = subject_ttl;
        self
    }

    /// Enables absolute decision freshness with the supplied TTL.
    ///
    /// This setting is independently useful for absolute expiry. Pair it with
    /// [`PolicyGateConfigBuilder::decision_refresh_ahead`] to proactively refresh live permits.
    #[must_use]
    pub const fn decision_freshness_ttl(mut self, ttl: Duration) -> Self {
        self.decision_freshness_ttl = Some(ttl);
        self
    }

    /// Sets how long before decision freshness expiry a live permit triggers a refresh.
    ///
    /// This requires [`PolicyGateConfigBuilder::decision_freshness_ttl`] and must be strictly less
    /// than that TTL.
    #[must_use]
    pub const fn decision_refresh_ahead(mut self, refresh_ahead: Duration) -> Self {
        self.decision_refresh_ahead = Some(refresh_ahead);
        self
    }

    /// Normalizes fields and checks cross-field rules.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] when the candidate settings cannot provide the runtime's timing
    /// and capacity guarantees.
    pub fn build(self) -> Result<PolicyGateConfig, ConfigError> {
        if self.unary_timeout > self.admission_timeout {
            return Err(ConfigError::UnaryExceedsAdmission);
        }
        if self.initial_admission_retry_delay.is_zero() {
            return Err(ConfigError::InitialAdmissionRetryDelayZero);
        }
        if self.initial_admission_retry_delay > self.max_admission_retry_delay {
            return Err(ConfigError::InitialRetryExceedsMaximum);
        }
        if self.initial_reconnect_delay.is_zero() {
            return Err(ConfigError::InitialReconnectDelayZero);
        }
        if self.initial_reconnect_delay > self.max_reconnect_delay {
            return Err(ConfigError::InitialReconnectExceedsMaximum);
        }
        if self.watch_events_per_yield == 0 {
            return Err(ConfigError::WatchEventsPerYieldZero);
        }
        let now = Instant::now();
        if now.checked_add(self.admission_timeout).is_none() {
            return Err(ConfigError::AdmissionDeadlineOverflow);
        }
        for (name, duration) in [
            (
                "initial admission retry delay",
                self.initial_admission_retry_delay,
            ),
            (
                "maximum admission retry delay",
                self.max_admission_retry_delay,
            ),
            (
                "permanent failure cooldown",
                self.permanent_failure_cooldown,
            ),
            (
                "snapshot republish interval",
                self.snapshot_republish_interval,
            ),
            ("initial reconnect delay", self.initial_reconnect_delay),
            ("maximum reconnect delay", self.max_reconnect_delay),
        ] {
            if now.checked_add(duration).is_none() {
                return Err(ConfigError::DurationOverflow(name));
            }
        }
        if self.max_subjects == 0 {
            return Err(ConfigError::MaxSubjectsZero);
        }
        if self.decision_freshness_ttl.is_some_and(|ttl| ttl.is_zero()) {
            return Err(ConfigError::DecisionFreshnessTtlZero);
        }
        if self
            .decision_freshness_ttl
            .is_some_and(|ttl| now.checked_add(ttl).is_none())
        {
            return Err(ConfigError::DurationOverflow("decision freshness TTL"));
        }
        match (self.decision_freshness_ttl, self.decision_refresh_ahead) {
            (None | Some(_), None) => {}
            (Some(_), Some(refresh_ahead)) if refresh_ahead.is_zero() => {
                return Err(ConfigError::DecisionRefreshAheadZero);
            }
            (Some(ttl), Some(refresh_ahead)) if refresh_ahead < ttl => {}
            (Some(_), Some(_)) => return Err(ConfigError::DecisionRefreshAheadNotLessThanTtl),
            (None, Some(_)) => return Err(ConfigError::DecisionFreshnessIncomplete),
        }
        Ok(PolicyGateConfig {
            unary_timeout: self.unary_timeout,
            admission_timeout: self.admission_timeout,
            initial_admission_retry_delay: self.initial_admission_retry_delay,
            max_admission_retry_delay: self.max_admission_retry_delay,
            permanent_failure_cooldown: self.permanent_failure_cooldown,
            snapshot_republish_interval: self.snapshot_republish_interval,
            initial_reconnect_delay: self.initial_reconnect_delay,
            max_reconnect_delay: self.max_reconnect_delay,
            watch_events_per_yield: self.watch_events_per_yield,
            max_subjects: self.max_subjects,
            subject_ttl: self.subject_ttl,
            decision_freshness_ttl: self.decision_freshness_ttl,
            decision_refresh_ahead: self.decision_refresh_ahead,
        })
    }
}

/// Invalid caller-supplied policy-gate configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// The unary timeout exceeds the admission timeout, so one lookup could outlive admission.
    UnaryExceedsAdmission,
    /// The initial admission retry delay is zero, which would retry without backoff.
    InitialAdmissionRetryDelayZero,
    /// The initial admission retry delay exceeds its own maximum.
    InitialRetryExceedsMaximum,
    /// The initial reconnect delay is zero, which would reconnect without backoff.
    InitialReconnectDelayZero,
    /// The initial reconnect delay exceeds its own maximum.
    InitialReconnectExceedsMaximum,
    /// The watch would never yield to the runtime because its event budget is zero.
    WatchEventsPerYieldZero,
    /// The admission timeout cannot be represented as a deadline on this platform.
    AdmissionDeadlineOverflow,
    /// The named duration cannot be represented as a deadline on this platform.
    DurationOverflow(&'static str),
    /// The subject-map capacity is zero, so no subject could ever be cached.
    MaxSubjectsZero,
    /// A zero freshness TTL would make every authoritative decision immediately unusable.
    DecisionFreshnessTtlZero,
    /// Decision refresh-ahead was configured without a freshness TTL.
    DecisionFreshnessIncomplete,
    /// A zero refresh-ahead would wait until the decision is already expired.
    DecisionRefreshAheadZero,
    /// Decision refresh-ahead must be strictly less than the freshness TTL.
    DecisionRefreshAheadNotLessThanTtl,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnaryExceedsAdmission => {
                f.write_str("unary timeout must not exceed admission timeout")
            }
            Self::InitialAdmissionRetryDelayZero => {
                f.write_str("initial admission retry delay must be greater than zero")
            }
            Self::InitialRetryExceedsMaximum => {
                f.write_str("initial admission retry delay must not exceed its maximum")
            }
            Self::InitialReconnectDelayZero => {
                f.write_str("initial reconnect delay must be greater than zero")
            }
            Self::InitialReconnectExceedsMaximum => {
                f.write_str("initial reconnect delay must not exceed its maximum")
            }
            Self::WatchEventsPerYieldZero => {
                f.write_str("watch events per yield must be greater than zero")
            }
            Self::AdmissionDeadlineOverflow => {
                f.write_str("admission timeout is too large to represent as an Instant deadline")
            }
            Self::DurationOverflow(name) => {
                write!(f, "{name} is too large to represent as an Instant deadline")
            }
            Self::MaxSubjectsZero => f.write_str("maximum subject count must be greater than zero"),
            Self::DecisionFreshnessTtlZero => {
                f.write_str("decision freshness TTL must be greater than zero")
            }
            Self::DecisionFreshnessIncomplete => {
                f.write_str("decision refresh-ahead requires a decision freshness TTL")
            }
            Self::DecisionRefreshAheadZero => {
                f.write_str("decision refresh-ahead must be greater than zero")
            }
            Self::DecisionRefreshAheadNotLessThanTtl => {
                f.write_str("decision refresh-ahead must be less than decision freshness TTL")
            }
        }
    }
}

impl core::error::Error for ConfigError {}

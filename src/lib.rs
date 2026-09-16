// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

//! Continuous admission and streaming enforcement driven by an external policy authority.
//!
//! A [`PolicyGate`] answers one question about a caller-chosen subject type: is this subject
//! allowed right now? Decisions come from a caller-supplied [`DecisionSource`] bound to a single
//! policy scope, and are cached in a bounded, TTL-evicted subject map that one [`DecisionWatcher`]
//! keeps current from the authority's change stream.
//!
//! [`PolicyGate::admit`] returns an [`Admission`] handle whose synchronous state checks read the
//! subject's current decision. Middleware checks the handle on each request or response body poll.
//! Authority changes do not wake idle connections; denial takes effect on the next poll.
//!
//! # Runtime contract
//!
//! `PolicyGate::new` returns three values that belong to one decision source: the gate, its
//! watcher, and a health handle. The watcher is a future that must be polled continuously —
//! normally by spawning it — for as long as the gate is used. Aborting the task drops the watcher;
//! dropping its `JoinHandle` only detaches the still-running task.
//!
//! While the watch is down the gate serves no cached state: existing admission handles report
//! [`AdmissionState::Stale`], and new admissions wait for reconnection and then fail with
//! [`AdmissionUnavailable`] once [`PolicyGateConfig::admission_timeout`] elapses. Dropping the
//! watcher stops new admissions permanently and leaves every admission stale.
//!
//! Absolute decision freshness is opt-in. A finite freshness TTL enables it; the default
//! [`DEFAULT_DECISION_FRESHNESS_TTL`] sentinel never expires. When enabled, ordinary cache access
//! never extends a decision's deadline. Handles and admissions check expiry on access; stream bodies
//! cut off expired decisions on their next poll. A configured refresh window starts one background
//! refresh when a cached decision is read shortly before expiry. Time alone never wakes an idle
//! stream.
//! [`PolicyGateConfig::subject_ttl`] remains the separate sliding idle-cache eviction policy.
//!
//! # Example
//!
//! ```
//! # #[cfg(feature = "tokio")]
//! # {
//! use std::sync::Arc;
//!
//! use policy_gate::{DecisionSource, PolicyGate, PolicyGateConfig};
//!
//! async fn run<S>(source: Arc<S>) -> Result<(), Box<dyn std::error::Error>>
//! where
//!     S: DecisionSource<String>,
//! {
//!     let config = PolicyGateConfig::builder().build()?;
//!     let (gate, watcher, _health) = PolicyGate::new(&config, source);
//!     tokio::spawn(watcher);
//!
//!     let admission = gate.admit(&"organization-123".to_owned()).await?;
//!     if admission.is_allowed() {
//!         // Start work, then recheck before each subsequent activity.
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
//! #         -> impl Future<Output = Result<Option<Decision>, DecisionSourceError>> + Send {
//! #         core::future::ready(Ok(Some(Decision::Allowed)))
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
//! | `tower-layer` | `PolicyGateLayer` and streaming body enforcement |
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
mod stream;
mod time;
#[cfg(feature = "tonic-client")]
mod tonic_source;
mod watcher;

pub use gate::{
    Admission, AdmissionState, AdmissionUnavailable, DecisionSource, PolicyGate, Subject,
};
#[cfg(feature = "tonic-layer")]
pub use grpc::TonicRejectionResponse;
#[cfg(feature = "axum-body")]
pub use layer::AxumBodyAdapter;
#[cfg(feature = "tower-layer")]
pub use layer::{
    BodyAdapter, BodySide, BoxBodyError, HttpRejectionResponse, PolicyGateLayer,
    PolicyGateLayerConfig, PolicyGateMiddleware, RejectionResponse, RequestPolicy, StreamRejection,
    StreamRejectionResponse, UnavailableResponseAdapter,
};
pub use metrics::{NoopPolicyGateMetrics, PolicyGateMetrics};
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
    DecisionWatcher,
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
/// Default [`PolicyGateConfigBuilder::decision_freshness_ttl`].
///
/// This exact value is the never-expire sentinel; the runtime does not turn it into a deadline.
pub const DEFAULT_DECISION_FRESHNESS_TTL: Duration = Duration::MAX;
/// Default [`PolicyGateConfigBuilder::refresh_before_expiry`].
pub const DEFAULT_REFRESH_BEFORE_EXPIRY: Duration = Duration::ZERO;
/// Default [`PolicyGateConfigBuilder::refresh_enqueue_timeout`].
pub const DEFAULT_REFRESH_ENQUEUE_TIMEOUT: Duration = Duration::from_millis(100);
/// Number of background decision refreshes that may wait for the watcher.
pub const DEFAULT_REFRESH_QUEUE_CAPACITY: usize = 1_024;

/// Authoritative decision returned for one subject.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
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
    /// Decision now in force, or `None` when the authority withdrew its decision.
    ///
    /// Withdrawal drops the subject from the cache and marks its admission handles stale.
    pub decision: Option<Decision>,
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
    decision_freshness_ttl: Duration,
    refresh_before_expiry: Duration,
    refresh_enqueue_timeout: Duration,
    refresh_queue_capacity: usize,
}

impl PolicyGateConfig {
    /// Starts a builder with the default timing and capacity values.
    #[must_use]
    pub const fn builder() -> PolicyGateConfigBuilder {
        PolicyGateConfigBuilder {
            candidate: Self {
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
                decision_freshness_ttl: DEFAULT_DECISION_FRESHNESS_TTL,
                refresh_before_expiry: DEFAULT_REFRESH_BEFORE_EXPIRY,
                refresh_enqueue_timeout: DEFAULT_REFRESH_ENQUEUE_TIMEOUT,
                refresh_queue_capacity: DEFAULT_REFRESH_QUEUE_CAPACITY,
            },
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
    /// Inserting past it evicts the least recently used subject and marks that subject's admission handles
    /// stale.
    #[must_use]
    pub const fn max_subjects(&self) -> usize {
        self.max_subjects
    }

    /// Idle time after which a cached subject is evicted and its admission handles are marked stale.
    #[must_use]
    pub const fn subject_ttl(&self) -> Duration {
        self.subject_ttl
    }

    /// Absolute age after which an authoritative decision is no longer usable.
    ///
    /// Unlike [`PolicyGateConfig::subject_ttl`], ordinary access does not extend this deadline.
    /// [`DEFAULT_DECISION_FRESHNESS_TTL`] disables decision freshness checks and preserves the
    /// original cache behavior. The sentinel is never converted into an [`Instant`] deadline.
    /// Pair a finite TTL with [`PolicyGateConfig::refresh_before_expiry`] to refresh cached
    /// decisions on access before this deadline.
    #[must_use]
    pub const fn decision_freshness_ttl(&self) -> Duration {
        self.decision_freshness_ttl
    }

    /// Window before decision expiry in which a cached subject read starts a background refresh.
    /// Zero disables background refresh.
    #[must_use]
    pub const fn refresh_before_expiry(&self) -> Duration {
        self.refresh_before_expiry
    }

    /// Maximum time a cached access waits to hand a refresh to the background watcher.
    /// Admission also caps this wait at its remaining admission budget.
    #[must_use]
    pub const fn refresh_enqueue_timeout(&self) -> Duration {
        self.refresh_enqueue_timeout
    }

    /// Maximum number of decision refreshes waiting for the background watcher.
    #[must_use]
    pub const fn refresh_queue_capacity(&self) -> usize {
        self.refresh_queue_capacity
    }
}

/// Builds one validated gate configuration.
///
/// Each setter documents only its default; see the matching [`PolicyGateConfig`] accessor for what
/// the value controls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyGateConfigBuilder {
    candidate: PolicyGateConfig,
}

impl PolicyGateConfigBuilder {
    /// Sets [`PolicyGateConfig::unary_timeout`]. Defaults to [`DEFAULT_UNARY_TIMEOUT`].
    #[must_use]
    pub const fn unary_timeout(mut self, timeout: Duration) -> Self {
        self.candidate.unary_timeout = timeout;
        self
    }

    /// Sets [`PolicyGateConfig::admission_timeout`]. Defaults to [`DEFAULT_ADMISSION_TIMEOUT`].
    #[must_use]
    pub const fn admission_timeout(mut self, timeout: Duration) -> Self {
        self.candidate.admission_timeout = timeout;
        self
    }

    /// Sets [`PolicyGateConfig::initial_admission_retry_delay`]. Defaults to
    /// [`DEFAULT_INITIAL_ADMISSION_RETRY_DELAY`].
    #[must_use]
    pub const fn initial_admission_retry_delay(mut self, delay: Duration) -> Self {
        self.candidate.initial_admission_retry_delay = delay;
        self
    }

    /// Sets [`PolicyGateConfig::max_admission_retry_delay`]. Defaults to
    /// [`DEFAULT_MAX_ADMISSION_RETRY_DELAY`].
    #[must_use]
    pub const fn max_admission_retry_delay(mut self, delay: Duration) -> Self {
        self.candidate.max_admission_retry_delay = delay;
        self
    }

    /// Sets [`PolicyGateConfig::permanent_failure_cooldown`]. Defaults to
    /// [`DEFAULT_PERMANENT_FAILURE_COOLDOWN`].
    #[must_use]
    pub const fn permanent_failure_cooldown(mut self, cooldown: Duration) -> Self {
        self.candidate.permanent_failure_cooldown = cooldown;
        self
    }

    /// Sets [`PolicyGateConfig::snapshot_republish_interval`]. Defaults to
    /// [`DEFAULT_SNAPSHOT_REPUBLISH_INTERVAL`].
    #[must_use]
    pub const fn snapshot_republish_interval(mut self, interval: Duration) -> Self {
        self.candidate.snapshot_republish_interval = interval;
        self
    }

    /// Sets [`PolicyGateConfig::initial_reconnect_delay`]. Defaults to
    /// [`DEFAULT_INITIAL_RECONNECT_DELAY`].
    #[must_use]
    pub const fn initial_reconnect_delay(mut self, delay: Duration) -> Self {
        self.candidate.initial_reconnect_delay = delay;
        self
    }

    /// Sets [`PolicyGateConfig::max_reconnect_delay`]. Defaults to
    /// [`DEFAULT_MAX_RECONNECT_DELAY`].
    #[must_use]
    pub const fn max_reconnect_delay(mut self, delay: Duration) -> Self {
        self.candidate.max_reconnect_delay = delay;
        self
    }

    /// Sets [`PolicyGateConfig::watch_events_per_yield`]. Defaults to
    /// [`DEFAULT_WATCH_EVENTS_PER_YIELD`].
    #[must_use]
    pub const fn watch_events_per_yield(mut self, events: usize) -> Self {
        self.candidate.watch_events_per_yield = events;
        self
    }

    /// Sets [`PolicyGateConfig::max_subjects`]. Defaults to [`DEFAULT_MAX_SUBJECTS`].
    #[must_use]
    pub const fn max_subjects(mut self, max_subjects: usize) -> Self {
        self.candidate.max_subjects = max_subjects;
        self
    }

    /// Sets [`PolicyGateConfig::subject_ttl`]. Defaults to [`DEFAULT_SUBJECT_TTL`].
    #[must_use]
    pub const fn subject_ttl(mut self, subject_ttl: Duration) -> Self {
        self.candidate.subject_ttl = subject_ttl;
        self
    }

    /// Sets [`PolicyGateConfig::decision_freshness_ttl`]. Defaults to
    /// [`DEFAULT_DECISION_FRESHNESS_TTL`].
    #[must_use]
    pub const fn decision_freshness_ttl(mut self, ttl: Duration) -> Self {
        self.candidate.decision_freshness_ttl = ttl;
        self
    }

    /// Sets the window before expiry in which a cached decision read triggers a refresh.
    /// Zero disables background refresh.
    #[must_use]
    pub const fn refresh_before_expiry(mut self, refresh_before: Duration) -> Self {
        self.candidate.refresh_before_expiry = refresh_before;
        self
    }

    /// Sets the refresh queue handoff timeout. Defaults to
    /// [`DEFAULT_REFRESH_ENQUEUE_TIMEOUT`].
    #[must_use]
    pub const fn refresh_enqueue_timeout(mut self, timeout: Duration) -> Self {
        self.candidate.refresh_enqueue_timeout = timeout;
        self
    }

    /// Sets the decision refresh queue capacity. Defaults to
    /// [`DEFAULT_REFRESH_QUEUE_CAPACITY`].
    #[must_use]
    pub const fn refresh_queue_capacity(mut self, capacity: usize) -> Self {
        self.candidate.refresh_queue_capacity = capacity;
        self
    }

    /// Normalizes fields and checks cross-field rules.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] when the candidate settings cannot provide the runtime's timing
    /// and capacity guarantees.
    pub fn build(self) -> Result<PolicyGateConfig, ConfigError> {
        let candidate = self.candidate;
        if candidate.unary_timeout > candidate.admission_timeout {
            return Err(ConfigError::UnaryExceedsAdmission);
        }
        if candidate.initial_admission_retry_delay.is_zero() {
            return Err(ConfigError::InitialAdmissionRetryDelayZero);
        }
        if candidate.initial_admission_retry_delay > candidate.max_admission_retry_delay {
            return Err(ConfigError::InitialRetryExceedsMaximum);
        }
        if candidate.initial_reconnect_delay.is_zero() {
            return Err(ConfigError::InitialReconnectDelayZero);
        }
        if candidate.initial_reconnect_delay > candidate.max_reconnect_delay {
            return Err(ConfigError::InitialReconnectExceedsMaximum);
        }
        if candidate.watch_events_per_yield == 0 {
            return Err(ConfigError::WatchEventsPerYieldZero);
        }
        let now = Instant::now();
        if now.checked_add(candidate.admission_timeout).is_none() {
            return Err(ConfigError::AdmissionDeadlineOverflow);
        }
        for (name, duration) in [
            (
                "initial admission retry delay",
                candidate.initial_admission_retry_delay,
            ),
            (
                "maximum admission retry delay",
                candidate.max_admission_retry_delay,
            ),
            (
                "permanent failure cooldown",
                candidate.permanent_failure_cooldown,
            ),
            (
                "snapshot republish interval",
                candidate.snapshot_republish_interval,
            ),
            ("initial reconnect delay", candidate.initial_reconnect_delay),
            ("maximum reconnect delay", candidate.max_reconnect_delay),
            ("refresh enqueue timeout", candidate.refresh_enqueue_timeout),
        ] {
            if now.checked_add(duration).is_none() {
                return Err(ConfigError::DurationOverflow(name));
            }
        }
        if candidate.max_subjects == 0 {
            return Err(ConfigError::MaxSubjectsZero);
        }
        if candidate.refresh_queue_capacity == 0 {
            return Err(ConfigError::RefreshQueueCapacityZero);
        }
        if candidate.refresh_enqueue_timeout.is_zero() {
            return Err(ConfigError::RefreshEnqueueTimeoutZero);
        }
        if candidate.decision_freshness_ttl.is_zero() {
            return Err(ConfigError::DecisionFreshnessTtlZero);
        }
        if !candidate.refresh_before_expiry.is_zero()
            && candidate.decision_freshness_ttl == Duration::MAX
        {
            return Err(ConfigError::RefreshRequiresFiniteDecisionFreshnessTtl);
        }
        if candidate.refresh_before_expiry >= candidate.decision_freshness_ttl {
            return Err(ConfigError::RefreshWindowNotLessThanDecisionFreshnessTtl);
        }
        if candidate.decision_freshness_ttl != DEFAULT_DECISION_FRESHNESS_TTL
            && now.checked_add(candidate.decision_freshness_ttl).is_none()
        {
            return Err(ConfigError::DurationOverflow("decision freshness TTL"));
        }
        Ok(candidate)
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
    /// The refresh queue capacity is zero, so no background lookup could be scheduled.
    RefreshQueueCapacityZero,
    /// A zero queue handoff timeout would never attempt to enqueue a refresh.
    RefreshEnqueueTimeoutZero,
    /// A zero freshness TTL would make every authoritative decision immediately unusable.
    DecisionFreshnessTtlZero,
    /// Refresh needs a finite freshness deadline to define its trigger window.
    RefreshRequiresFiniteDecisionFreshnessTtl,
    /// Refresh must start strictly before the freshness deadline.
    RefreshWindowNotLessThanDecisionFreshnessTtl,
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
            Self::RefreshQueueCapacityZero => {
                f.write_str("refresh queue capacity must be greater than zero")
            }
            Self::RefreshEnqueueTimeoutZero => {
                f.write_str("refresh enqueue timeout must be greater than zero")
            }
            Self::DecisionFreshnessTtlZero => {
                f.write_str("decision freshness TTL must be greater than zero")
            }
            Self::RefreshRequiresFiniteDecisionFreshnessTtl => {
                f.write_str("decision refresh requires a finite decision freshness TTL")
            }
            Self::RefreshWindowNotLessThanDecisionFreshnessTtl => {
                f.write_str("decision refresh window must be less than decision freshness TTL")
            }
        }
    }
}

impl core::error::Error for ConfigError {}

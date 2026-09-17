// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::fmt::{self, Display};
use core::marker::PhantomData;
use core::pin::Pin;
use core::str::FromStr;
use core::task::{Context, Poll, ready};
use core::time::Duration;
use std::sync::Arc;

use crate::policy_proto::policy_authority_client::PolicyAuthorityClient;
use crate::policy_proto::{
    Decision as ProtoDecision, GetSubjectDecisionRequest, GetSubjectDecisionResponse,
    SubjectDecisionChange as ProtoSubjectDecisionChange, WatchSubjectDecisionsRequest,
};
use futures_core::Stream;
use tonic::transport::{Channel, Endpoint};

use crate::{
    Decision, DecisionChange, DecisionSource, DecisionSourceError, DecisionSourceErrorKind, Subject,
};

/// Endpoint and scope configuration for the lazy tonic policy decision source.
///
/// Consumed by [`TonicDecisionSource::connect_lazy`].
///
/// Requires the `tonic-client` feature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TonicDecisionSourceConfig {
    endpoint: String,
    scope: String,
    connect_timeout: Duration,
}

impl TonicDecisionSourceConfig {
    /// Creates strict scope-bound client configuration.
    ///
    /// `endpoint` is a tonic URI such as `http://authority.internal:50051`, and `scope` is the
    /// opaque scope name this source is bound to. The connect timeout defaults to two seconds and
    /// the scope echo is validated strictly.
    #[must_use]
    pub fn new(endpoint: impl Into<String>, scope: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            scope: scope.into(),
            connect_timeout: Duration::from_secs(2),
        }
    }

    /// Sets how long one TCP connection attempt to the authority may take.
    #[must_use]
    pub const fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Returns the configured authority endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Returns the scope this source is bound to.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// Returns the per-attempt connect timeout.
    #[must_use]
    pub const fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }
}

/// Invalid tonic policy decision source configuration.
///
/// Returned by [`TonicDecisionSource::connect_lazy`] when the endpoint cannot be parsed as a URI.
///
/// Requires the `tonic-client` feature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TonicDecisionSourceConfigError(String);

impl Display for TonicDecisionSourceConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid policy authority endpoint: {}", self.0)
    }
}

impl core::error::Error for TonicDecisionSourceConfigError {}

/// Scope-bound tonic adapter for the policy authority.
///
/// Implements [`DecisionSource`] over the bundled `aspect.policy.gate.v1.PolicyAuthority` service
/// for any subject type that is both [`Display`] and [`FromStr`]: subjects go out as their
/// `Display` form and come back parsed, and an unparseable identifier is reported as a
/// [`DecisionSourceErrorKind::Wire`] failure. gRPC statuses are classified for the gate — `NOT_FOUND`,
/// `INVALID_ARGUMENT`, `PERMISSION_DENIED`, `UNAUTHENTICATED`, `UNIMPLEMENTED`, and `DATA_LOSS`
/// are permanent, every other code is transient.
///
/// Each instance is bound to one scope, so a process that gates several scopes builds one source
/// and one [`PolicyGate`](crate::PolicyGate) per scope.
/// `DECISION_UNSPECIFIED` is reported as `None`; any other unknown value is a `Wire` failure.
///
/// Requires the `tonic-client` feature.
#[derive(Clone, Debug)]
pub struct TonicDecisionSource<T> {
    client: PolicyAuthorityClient<Channel>,
    scope: Arc<str>,
    subject: PhantomData<fn() -> T>,
}

/// Decoding stream returned by [`TonicDecisionSource`].
///
/// Validates each change's scope echo and parses its subject identifier, yielding normalized
/// [`DecisionChange`] values. The stream ends where the underlying gRPC stream ends; the watcher
/// reopens it.
///
/// Requires the `tonic-client` feature.
pub struct TonicDecisionStream<T> {
    inner: tonic::Streaming<ProtoSubjectDecisionChange>,
    scope: Arc<str>,
    subject: PhantomData<fn() -> T>,
}

impl<T> fmt::Debug for TonicDecisionStream<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TonicDecisionStream")
            .finish_non_exhaustive()
    }
}

impl<T: FromStr> Stream for TonicDecisionStream<T> {
    type Item = Result<DecisionChange<T>, DecisionSourceError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let result = ready!(Pin::new(&mut this.inner).poll_next(cx));
        Poll::Ready(result.map(|result| {
            result
                .map_err(|status| source_error(&status))
                .and_then(|change| decode_change(&change, &this.scope))
        }))
    }
}

impl<T> TonicDecisionSource<T> {
    /// Builds a strict scope-bound client around a host-prepared channel.
    ///
    /// Use it when the host already owns the channel, for example to apply TLS, load balancing, or
    /// interceptors of its own.
    #[must_use]
    pub fn from_channel(channel: Channel, scope: impl Into<Arc<str>>) -> Self {
        Self {
            client: PolicyAuthorityClient::new(channel),
            scope: scope.into(),
            subject: PhantomData,
        }
    }

    /// Builds a lazy channel using the supplied endpoint configuration.
    ///
    /// The channel connects on first use, so this never blocks and never fails on an authority
    /// that is still starting up. It enables HTTP/2 keep-alive while idle, which keeps the watch
    /// stream from silently dying behind an idle-timing proxy.
    ///
    /// # Errors
    ///
    /// Returns [`TonicDecisionSourceConfigError`] when the endpoint is not a valid tonic URI.
    pub fn connect_lazy(
        config: &TonicDecisionSourceConfig,
    ) -> Result<Self, TonicDecisionSourceConfigError> {
        let endpoint = Endpoint::from_shared(config.endpoint.clone())
            .map_err(|error| TonicDecisionSourceConfigError(error.to_string()))?
            .http2_keep_alive_interval(Duration::from_secs(10))
            .keep_alive_timeout(Duration::from_secs(5))
            .keep_alive_while_idle(true)
            .tcp_keepalive(Some(Duration::from_secs(30)))
            .connect_timeout(config.connect_timeout);
        Ok(Self::from_channel(
            endpoint.connect_lazy(),
            Arc::<str>::from(config.scope.as_str()),
        ))
    }
}

impl<T> DecisionSource<T> for TonicDecisionSource<T>
where
    T: Subject + Display + FromStr,
{
    type Changes = TonicDecisionStream<T>;

    async fn get_subject_decision(
        &self,
        subject: &T,
    ) -> Result<Option<Decision>, DecisionSourceError> {
        let mut client = self.client.clone();
        let response = client
            .get_subject_decision(GetSubjectDecisionRequest {
                subject_id: subject.to_string(),
                scope: self.scope.to_string(),
            })
            .await
            .map_err(|status| source_error(&status))?
            .into_inner();
        decode_response(&response, &self.scope)
    }

    async fn watch_subject_decisions(&self) -> Result<Self::Changes, DecisionSourceError> {
        let mut client = self.client.clone();
        let stream = client
            .watch_subject_decisions(WatchSubjectDecisionsRequest {
                scope: self.scope.to_string(),
            })
            .await
            .map_err(|status| source_error(&status))?
            .into_inner();
        Ok(TonicDecisionStream {
            inner: stream,
            scope: Arc::clone(&self.scope),
            subject: PhantomData,
        })
    }
}

fn decode_response(
    response: &GetSubjectDecisionResponse,
    scope: &str,
) -> Result<Option<Decision>, DecisionSourceError> {
    validate_scope_echo(scope, &response.scope)?;
    decode_decision(response.decision)
}

fn decode_change<T: FromStr>(
    change: &ProtoSubjectDecisionChange,
    scope: &str,
) -> Result<DecisionChange<T>, DecisionSourceError> {
    validate_scope_echo(scope, &change.scope)?;
    let subject = change.subject_id.parse().map_err(|_| {
        DecisionSourceError::new(
            DecisionSourceErrorKind::Wire,
            "decision source returned an invalid subject identifier",
        )
    })?;
    Ok(DecisionChange {
        subject,
        decision: decode_decision(change.decision)?,
    })
}

fn validate_scope_echo(expected: &str, actual: &str) -> Result<(), DecisionSourceError> {
    if actual == expected {
        return Ok(());
    }
    Err(DecisionSourceError::new(
        DecisionSourceErrorKind::Wire,
        "decision source returned a mismatched scope",
    ))
}

fn decode_decision(state: i32) -> Result<Option<Decision>, DecisionSourceError> {
    match ProtoDecision::try_from(state) {
        Ok(ProtoDecision::Unspecified) => Ok(None),
        Ok(ProtoDecision::Allowed) => Ok(Some(Decision::Allowed)),
        Ok(ProtoDecision::Denied) => Ok(Some(Decision::Denied)),
        Err(_) => Err(DecisionSourceError::new(
            DecisionSourceErrorKind::Wire,
            "decision source returned an unknown decision",
        )),
    }
}

fn source_error(status: &tonic::Status) -> DecisionSourceError {
    let kind = match status.code() {
        tonic::Code::NotFound
        | tonic::Code::InvalidArgument
        | tonic::Code::PermissionDenied
        | tonic::Code::Unauthenticated
        | tonic::Code::Unimplemented
        | tonic::Code::DataLoss => DecisionSourceErrorKind::Permanent,
        _ => DecisionSourceErrorKind::Transient,
    };
    DecisionSourceError::new(kind, status.to_string())
}

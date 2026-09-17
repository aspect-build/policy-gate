// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

/// Metric events emitted by the policy gate and transport layer.
///
/// Storage and export belong to the caller. Every method defaults to doing nothing, so an
/// implementation records only the events it cares about.
///
/// Methods are called from the admission path, from an active stream when it is cut off, and from
/// the watcher task — not on every successful frame. They must not block, await, or panic. The
/// events marked below as middleware events come from the Tower layer and are never emitted unless
/// the `tower-layer` feature is enabled.
pub trait PolicyGateMetrics: Send + Sync + 'static {
    /// Records a request rejected by an authoritative denial. Middleware event.
    fn denial(&self) {}
    /// Records a request rejected because no authoritative verdict was available. Middleware
    /// event.
    fn unavailable_rejection(&self) {}
    /// Records an admission that could not use the published snapshot. Middleware event.
    fn snapshot_miss(&self) {}
    /// Records an admission served from the subject-state map rather than the published snapshot.
    fn map_hit(&self) {}
    /// Records an active stream terminated by a denial or an expired decision. Middleware event.
    fn stream_cutoff(&self) {}
    /// Records publication of a subject-map snapshot.
    fn snapshot_republish(&self) {}
    /// Records a decision-source unary call.
    fn unary_call(&self) {}
    /// Records a decision-source unary call that failed, returned an invalid value, or returned no
    /// decision.
    fn unary_failure(&self) {}
    /// Records an admission retry after a retryable decision-source result.
    fn admission_retry(&self) {}
    /// Records an admission that exhausted its deadline.
    fn admission_timeout(&self) {}
    /// Updates decision-source watch connectivity.
    fn set_watch_connected(&self, _connected: bool) {}
    /// Records a decision-source watch disconnection.
    fn watch_disconnect(&self) {}
    /// Records a failed or timed-out decision-source watch open.
    fn watch_open_failure(&self) {}
    /// Records a decision-source watch event.
    fn watch_event(&self) {}
    /// Records an invalid decision-source state or subject identifier.
    ///
    /// Accompanies every [`DecisionSourceErrorKind::Wire`](crate::DecisionSourceErrorKind::Wire)
    /// failure, on both the lookup and the watch path.
    fn wire_failure(&self) {}
    /// Records a request rejected because it had no subject identifier. Middleware event.
    fn missing_subject_rejection(&self) {}
}

impl<M: PolicyGateMetrics + ?Sized> PolicyGateMetrics for std::sync::Arc<M> {
    fn denial(&self) {
        (**self).denial();
    }

    fn unavailable_rejection(&self) {
        (**self).unavailable_rejection();
    }

    fn snapshot_miss(&self) {
        (**self).snapshot_miss();
    }

    fn map_hit(&self) {
        (**self).map_hit();
    }

    fn stream_cutoff(&self) {
        (**self).stream_cutoff();
    }

    fn snapshot_republish(&self) {
        (**self).snapshot_republish();
    }

    fn unary_call(&self) {
        (**self).unary_call();
    }

    fn unary_failure(&self) {
        (**self).unary_failure();
    }

    fn admission_retry(&self) {
        (**self).admission_retry();
    }

    fn admission_timeout(&self) {
        (**self).admission_timeout();
    }

    fn set_watch_connected(&self, connected: bool) {
        (**self).set_watch_connected(connected);
    }

    fn watch_disconnect(&self) {
        (**self).watch_disconnect();
    }

    fn watch_open_failure(&self) {
        (**self).watch_open_failure();
    }

    fn watch_event(&self) {
        (**self).watch_event();
    }

    fn wire_failure(&self) {
        (**self).wire_failure();
    }

    fn missing_subject_rejection(&self) {
        (**self).missing_subject_rejection();
    }
}

/// Metrics sink used when the caller does not provide one.
///
/// Every event is discarded; the default methods make this a zero-cost handle.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NoopPolicyGateMetrics;

impl PolicyGateMetrics for NoopPolicyGateMetrics {}

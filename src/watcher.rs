// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use std::sync::Arc;
use std::time::Instant;

use futures_util::future::BoxFuture;
use futures_util::{FutureExt, StreamExt};
use parking_lot::Mutex;
use rand::RngCore;

use crate::DecisionSourceErrorKind;
use crate::gate::{DecisionSource, GateState, Subject};
use crate::metrics::{NoopPolicyGateMetrics, PolicyGateMetrics};
use crate::time::{TimeDriver, TokioTimeDriver};

/// Health indicator derived from decision-source watch connectivity.
///
/// Handed out by [`PolicyGate::new`](crate::PolicyGate::new) and shared with the watcher, so it
/// stays accurate for the life of the gate. Reading it takes only a brief lock and is safe from
/// any thread, which suits a readiness or liveness probe.
#[derive(Debug)]
pub struct DecisionSourceHealth<D = TokioTimeDriver> {
    disconnected_since: Arc<Mutex<Option<Instant>>>,
    admission_timeout: Duration,
    time: D,
}

/// Health derived from decision-source watch connectivity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionSourceHealthStatus {
    /// The watch has stayed open long enough to be considered reliable.
    Stable,
    /// The watch is down, or has reopened too recently to count as stable, but not for long
    /// enough to be treated as failed.
    ///
    /// Admissions may still succeed. Every process starts here.
    NotYetStable,
    /// The watch has gone without a stable connection for at least
    /// [`PolicyGateConfig::admission_timeout`](crate::PolicyGateConfig::admission_timeout).
    ///
    /// Admissions are timing out, or a flapping connection is keeping the watch from ever settling.
    Failed,
}

impl<D: TimeDriver> DecisionSourceHealth<D> {
    /// Returns the current decision-source watch health.
    ///
    /// A watch counts as stable only after it stays open for
    /// [`PolicyGateConfig::max_reconnect_delay`](crate::PolicyGateConfig::max_reconnect_delay),
    /// which keeps a flapping connection from reporting healthy between drops.
    #[must_use]
    pub fn status(&self) -> DecisionSourceHealthStatus {
        let disconnected_since = *self.disconnected_since.lock();
        match disconnected_since {
            None => DecisionSourceHealthStatus::Stable,
            Some(since)
                if self.time.now().saturating_duration_since(since) >= self.admission_timeout =>
            {
                DecisionSourceHealthStatus::Failed
            }
            Some(_) => DecisionSourceHealthStatus::NotYetStable,
        }
    }
}

/// One process-wide subject state watch loop.
///
/// The watcher is a future that never completes: it keeps the decision source's change stream
/// open, applies each change to the gate's cache, and reopens the stream with jittered backoff
/// after any failure. Poll it for the lifetime of the gate, normally with `tokio::spawn`.
///
/// It is the gate's only writer, so its progress is a hard requirement rather than an
/// optimization:
///
/// - while the watch is down, the cache is emptied, permits report
///   [`PermitState::Stale`](crate::PermitState), and admissions wait for reconnection before
///   failing closed;
/// - dropping it — or dropping the task that polls it — permanently stops new admissions and
///   leaves every permit stale.
pub struct DecisionWatcher<
    T: Subject,
    C: DecisionSource<T>,
    M: PolicyGateMetrics = NoopPolicyGateMetrics,
    D = TokioTimeDriver,
> {
    state: Arc<GateState<T, C, M, D>>,
    future: BoxFuture<'static, ()>,
}

impl<T: Subject, C: DecisionSource<T>, M: PolicyGateMetrics, D: TimeDriver> core::fmt::Debug
    for DecisionWatcher<T, C, M, D>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DecisionWatcher")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl<T: Subject, C: DecisionSource<T>, M: PolicyGateMetrics, D: TimeDriver>
    DecisionWatcher<T, C, M, D>
{
    /// Constructs the watcher and its shared health indicator.
    pub(crate) fn new(
        state: Arc<GateState<T, C, M, D>>,
        client: Arc<C>,
        metrics: M,
    ) -> (Self, Arc<DecisionSourceHealth<D>>) {
        let health = Arc::new(DecisionSourceHealth {
            disconnected_since: state.disconnected_since(),
            admission_timeout: state.admission_timeout(),
            time: state.time_driver(),
        });
        let future = watch_source(Arc::clone(&state), client, metrics).boxed();
        (Self { state, future }, health)
    }
}

impl<T: Subject, C: DecisionSource<T>, M: PolicyGateMetrics, D: TimeDriver> Future
    for DecisionWatcher<T, C, M, D>
{
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

impl<T: Subject, C: DecisionSource<T>, M: PolicyGateMetrics, D> Drop
    for DecisionWatcher<T, C, M, D>
{
    fn drop(&mut self) {
        self.state.watch_stopping();
    }
}

async fn watch_source<T: Subject, C: DecisionSource<T>, M: PolicyGateMetrics, D: TimeDriver>(
    state: Arc<GateState<T, C, M, D>>,
    client: Arc<C>,
    metrics: M,
) {
    let time = state.time_driver();
    let initial_reconnect_delay = state.initial_reconnect_delay();
    let max_reconnect_delay = state.max_reconnect_delay();
    let watch_events_per_yield = state.watch_events_per_yield();
    let mut reconnect_delay = initial_reconnect_delay;
    loop {
        let opened = time
            .timeout(state.admission_timeout(), client.watch_subject_decisions())
            .await;
        match opened {
            Ok(Ok(stream)) => {
                state.watch_connected();
                let stream = stream.fuse();
                let stable_timer = time.sleep(max_reconnect_delay).fuse();
                futures_util::pin_mut!(stream, stable_timer);
                let mut events_since_yield = 0;
                loop {
                    let item = futures_util::select! {
                        () = stable_timer => {
                            // Health recovery and backoff reset share the same stability threshold.
                            reconnect_delay = initial_reconnect_delay;
                            state.watch_stable();
                            continue;
                        },
                        item = stream.next() => item,
                    };
                    let Some(item) = item else {
                        break;
                    };
                    let change = match item {
                        Ok(change) => change,
                        Err(error) => {
                            if error.kind() == DecisionSourceErrorKind::Wire {
                                metrics.wire_failure();
                            }
                            tracing::warn!(?error, "policy authority watch failed");
                            break;
                        }
                    };
                    state.apply_change(&change);
                    metrics.watch_event();
                    events_since_yield += 1;
                    if events_since_yield == watch_events_per_yield {
                        events_since_yield = 0;
                        time.yield_now().await;
                    }
                }
                metrics.watch_disconnect();
            }
            Ok(Err(error)) => {
                tracing::warn!(?error, "failed to open policy authority watch");
                metrics.watch_open_failure();
            }
            Err(error) => {
                tracing::warn!(?error, "policy authority watch open timed out");
                metrics.watch_open_failure();
            }
        }

        state.watch_disconnected();
        time.sleep(jitter(reconnect_delay)).await;
        reconnect_delay = reconnect_delay.saturating_mul(2).min(max_reconnect_delay);
    }
}

fn jitter(delay: Duration) -> Duration {
    let millis = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
    let spread = millis / 2;
    if spread == 0 {
        return delay;
    }
    Duration::from_millis(millis - spread / 2 + rand::rng().next_u64() % spread)
}

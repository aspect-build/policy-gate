// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use std::sync::Arc;
use std::time::Instant;

use futures_util::future::BoxFuture;
use futures_util::stream::FuturesUnordered;
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
/// after any failure. When decision freshness is enabled, it also drives refresh-ahead lookups and
/// freshness expiry using the same time driver. Poll it for the lifetime of the gate, normally
/// with `tokio::spawn`.
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
    stop: fn(&GateState<T, C, M, D>),
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
        (
            Self {
                state,
                future,
                stop: stop_watcher::<T, C, M, D>,
            },
            health,
        )
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
        (self.stop)(&self.state);
    }
}

fn stop_watcher<T: Subject, C: DecisionSource<T>, M: PolicyGateMetrics, D: TimeDriver>(
    state: &GateState<T, C, M, D>,
) {
    state.watch_stopping();
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
                let stable = if state.refresh_enabled() {
                    watch_connected_with_refresh(
                        Arc::clone(&state),
                        stream,
                        metrics,
                        time.clone(),
                        max_reconnect_delay,
                        watch_events_per_yield,
                    )
                    .await
                } else if state.freshness_enabled() {
                    watch_connected_with_freshness(
                        Arc::clone(&state),
                        stream,
                        metrics,
                        time.clone(),
                        max_reconnect_delay,
                        watch_events_per_yield,
                    )
                    .await
                } else {
                    watch_connected_without_freshness(
                        Arc::clone(&state),
                        stream,
                        metrics,
                        time.clone(),
                        max_reconnect_delay,
                        watch_events_per_yield,
                    )
                    .await
                };
                if stable {
                    reconnect_delay = initial_reconnect_delay;
                }
                metrics.watch_disconnect();
            }
            Ok(Err(error)) => {
                if error.kind() == DecisionSourceErrorKind::Wire {
                    metrics.wire_failure();
                }
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

async fn watch_connected_without_freshness<
    T: Subject,
    C: DecisionSource<T>,
    M: PolicyGateMetrics,
    D: TimeDriver,
>(
    state: Arc<GateState<T, C, M, D>>,
    stream: C::Changes,
    metrics: M,
    time: D,
    stability_delay: Duration,
    events_per_yield: usize,
) -> bool {
    let stream = stream.fuse();
    let stable_timer = time.sleep(stability_delay).fuse();
    futures_util::pin_mut!(stream, stable_timer);
    let mut stable = false;
    let mut events_since_yield = 0;
    loop {
        let item = futures_util::select! {
            () = stable_timer => {
                stable = true;
                state.watch_stable();
                continue;
            },
            item = stream.next() => item,
        };
        let Some(change) = decode_watch_item(item, metrics) else {
            return stable;
        };
        state.apply_change(&change);
        metrics.watch_event();
        events_since_yield += 1;
        if events_since_yield == events_per_yield {
            events_since_yield = 0;
            time.yield_now().await;
        }
    }
}

async fn watch_connected_with_freshness<
    T: Subject,
    C: DecisionSource<T>,
    M: PolicyGateMetrics,
    D: TimeDriver,
>(
    state: Arc<GateState<T, C, M, D>>,
    stream: C::Changes,
    metrics: M,
    time: D,
    stability_delay: Duration,
    events_per_yield: usize,
) -> bool {
    let stream = stream.fuse();
    let stable_timer = time.sleep(stability_delay).fuse();
    let mut freshness_changes = state.freshness_changes();
    let mut freshness_deadline = state.take_scheduled_freshness_deadline();
    futures_util::pin_mut!(stream, stable_timer);
    let mut stable = false;
    let mut events_since_yield = 0;
    loop {
        let freshness_timer: BoxFuture<'_, ()> = if let Some(deadline) = freshness_deadline {
            time.sleep_until(deadline).boxed()
        } else {
            core::future::pending().boxed()
        };
        let freshness_timer = freshness_timer.fuse();
        let freshness_change = freshness_changes.changed().fuse();
        futures_util::pin_mut!(freshness_timer, freshness_change);
        let item = futures_util::select! {
            () = stable_timer => {
                stable = true;
                state.watch_stable();
                continue;
            },
            () = freshness_timer => {
                freshness_deadline = state.freshness_expiry_work();
                continue;
            },
            _ = freshness_change => {
                freshness_deadline = earlier(
                    freshness_deadline,
                    state.take_scheduled_freshness_deadline(),
                );
                continue;
            },
            item = stream.next() => item,
        };
        let Some(change) = decode_watch_item(item, metrics) else {
            return stable;
        };
        freshness_deadline = earlier(freshness_deadline, state.apply_change(&change));
        metrics.watch_event();
        events_since_yield += 1;
        if events_since_yield == events_per_yield {
            events_since_yield = 0;
            time.yield_now().await;
        }
    }
}

async fn watch_connected_with_refresh<
    T: Subject,
    C: DecisionSource<T>,
    M: PolicyGateMetrics,
    D: TimeDriver,
>(
    state: Arc<GateState<T, C, M, D>>,
    stream: C::Changes,
    metrics: M,
    time: D,
    stability_delay: Duration,
    work_per_yield: usize,
) -> bool {
    let stream = stream.fuse();
    let stable_timer = time.sleep(stability_delay).fuse();
    let mut freshness_changes = state.freshness_changes();
    let mut freshness_deadline = state.take_scheduled_freshness_deadline();
    let mut refreshes = FuturesUnordered::new();
    futures_util::pin_mut!(stream, stable_timer);
    let mut stable = false;
    let mut work_since_yield = 0;
    loop {
        let freshness_timer: BoxFuture<'_, ()> = if let Some(deadline) = freshness_deadline {
            time.sleep_until(deadline).boxed()
        } else {
            core::future::pending().boxed()
        };
        let freshness_timer = freshness_timer.fuse();
        let freshness_change = freshness_changes.changed().fuse();
        let refresh = refreshes.select_next_some();
        futures_util::pin_mut!(freshness_timer, freshness_change, refresh);
        let item = futures_util::select! {
            () = stable_timer => {
                stable = true;
                state.watch_stable();
                continue;
            },
            () = freshness_timer => {
                let (due, next) = state.freshness_work();
                refreshes.extend(due);
                freshness_deadline = next;
                continue;
            },
            _ = freshness_change => {
                freshness_deadline = earlier(
                    freshness_deadline,
                    state.take_scheduled_freshness_deadline(),
                );
                continue;
            },
            refresh = refresh => {
                freshness_deadline = earlier(
                    freshness_deadline,
                    state.apply_decision_refresh(refresh),
                );
                work_since_yield += 1;
                if work_since_yield == work_per_yield {
                    work_since_yield = 0;
                    time.yield_now().await;
                }
                continue;
            },
            item = stream.next() => item,
        };
        let Some(change) = decode_watch_item(item, metrics) else {
            return stable;
        };
        freshness_deadline = earlier(freshness_deadline, state.apply_change(&change));
        metrics.watch_event();
        work_since_yield += 1;
        if work_since_yield == work_per_yield {
            work_since_yield = 0;
            time.yield_now().await;
        }
    }
}

fn decode_watch_item<T: Subject, M: PolicyGateMetrics>(
    item: Option<Result<crate::DecisionChange<T>, crate::DecisionSourceError>>,
    metrics: M,
) -> Option<crate::DecisionChange<T>> {
    match item? {
        Ok(change) => Some(change),
        Err(error) => {
            if error.kind() == DecisionSourceErrorKind::Wire {
                metrics.wire_failure();
            }
            tracing::warn!(?error, "policy authority watch failed");
            None
        }
    }
}

fn earlier(current: Option<Instant>, candidate: Option<Instant>) -> Option<Instant> {
    match (current, candidate) {
        (Some(current), Some(candidate)) => Some(current.min(candidate)),
        (Some(current), None) => Some(current),
        (None, candidate) => candidate,
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

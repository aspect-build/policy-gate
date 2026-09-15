// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll};
use core::time::Duration;
use std::sync::Arc;

use futures_core::Stream;
use futures_util::task::noop_waker;
use policy_gate::{
    Decision, DecisionChange, DecisionSource, DecisionSourceError, DecisionSourceErrorKind,
    DecisionSourceHealthStatus, PolicyGate, PolicyGateRuntime,
};
use tokio::sync::broadcast;
use tonic::Code;
use uuid::Uuid;

use crate::support::{
    ConfigOptions, GetAction, SUBJECT_A, ScriptedDecisionSource, assert_allowed, assert_rejected,
    call_subject, response, runtime, start_runtime, validated, wait_for_health, wait_for_metric,
    wait_for_watch_connected,
};

struct AlwaysReadysource {
    events: Arc<AtomicUsize>,
}

struct AlwaysReadyChanges {
    events: Arc<AtomicUsize>,
    subject: Uuid,
}

impl Stream for AlwaysReadyChanges {
    type Item = Result<DecisionChange<Uuid>, DecisionSourceError>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.events.fetch_add(1, Ordering::Relaxed);
        Poll::Ready(Some(Ok(DecisionChange {
            subject: self.subject,
            decision: Decision::Denied,
        })))
    }
}

impl DecisionSource<Uuid> for AlwaysReadysource {
    type Changes = AlwaysReadyChanges;

    fn get_subject_decision(
        &self,
        _subject: &Uuid,
    ) -> impl Future<Output = Result<Decision, DecisionSourceError>> + Send {
        core::future::ready(Ok(Decision::Denied))
    }

    fn watch_subject_decisions(
        &self,
    ) -> impl Future<Output = Result<Self::Changes, DecisionSourceError>> + Send {
        core::future::ready(Ok(AlwaysReadyChanges {
            events: Arc::clone(&self.events),
            subject: SUBJECT_A.parse().expect("test subject must be a UUID"),
        }))
    }
}

#[tokio::test]
async fn always_ready_watch_stream_yields_to_its_caller() {
    let events = Arc::new(AtomicUsize::new(0));
    let source = Arc::new(AlwaysReadysource {
        events: Arc::clone(&events),
    });
    let options = ConfigOptions {
        watch_events_per_yield: 3,
        ..ConfigOptions::default()
    };
    let (_gate, watcher, _health) = PolicyGate::new(&validated(&options), Arc::clone(&source));
    let mut watcher = Box::pin(watcher);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    assert!(watcher.as_mut().poll(&mut cx).is_pending());
    assert_eq!(events.load(Ordering::Relaxed), 3);
}

#[tokio::test(start_paused = true)]
async fn disconnect_and_reconnect_both_clear_the_map() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let first_watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(
            SUBJECT_A,
            GetAction::Return(Ok(response(Decision::Allowed))),
        )
        .await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(response(Decision::Denied))))
        .await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;
    assert_allowed(&call_subject(&runtime.layer, SUBJECT_A).await);
    assert_eq!(source.get_calls(), 1);

    let _second_watch = source.push_live_watch(Vec::new()).await;
    drop(first_watch);
    wait_for_watch_connected(&runtime.metrics, false).await;
    let misses = runtime.metrics.snapshot_misses.load(Ordering::Relaxed);
    let call = tokio::spawn({
        let layer = runtime.layer.clone();
        async move { call_subject(&layer, SUBJECT_A).await }
    });
    wait_for_metric(&runtime.metrics.snapshot_misses, misses + 1).await;
    assert_eq!(source.get_calls(), 1);

    tokio::time::advance(Duration::from_millis(50)).await;
    assert_eq!(source.watch_calls(), 1);
    tokio::time::advance(Duration::from_millis(75)).await;
    source.wait_for_watches(2).await;
    wait_for_watch_connected(&runtime.metrics, true).await;
    assert_rejected(&call.await.expect("call joins"), Code::FailedPrecondition);
    assert_eq!(source.get_calls(), 2);
    runtime.stop().await;
}

#[tokio::test(start_paused = true)]
async fn watch_open_is_abandoned_at_the_admission_deadline() {
    let source = Arc::new(ScriptedDecisionSource::default());
    source.push_pending_watch().await;
    let PolicyGateRuntime {
        watcher,
        health,
        metrics,
        ..
    } = runtime(
        Arc::clone(&source),
        &ConfigOptions {
            admission_timeout: Duration::from_secs(1),
            ..ConfigOptions::default()
        },
    );
    let (shutdown, _) = broadcast::channel(1);
    let task = tokio::spawn({
        let mut shutdown_rx = shutdown.subscribe();
        async move {
            tokio::select! {
                () = watcher => {}
                _ = shutdown_rx.recv() => {}
            }
        }
    });
    source.wait_for_watches(1).await;

    tokio::time::advance(Duration::from_secs(1)).await;
    wait_for_metric(&metrics.watch_open_failures, 1).await;
    wait_for_health(&health, false).await;
    assert_eq!(metrics.watch_disconnects.load(Ordering::Relaxed), 0);

    drop(shutdown.send(()));
    task.await.expect("watch task joins");
}

#[tokio::test(start_paused = true)]
async fn wire_failure_reconnects_and_clears_state() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let watch = source.push_live_watch(Vec::new()).await;
    let _second_watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(
            SUBJECT_A,
            GetAction::Return(Ok(response(Decision::Allowed))),
        )
        .await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(response(Decision::Denied))))
        .await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;
    assert_allowed(&call_subject(&runtime.layer, SUBJECT_A).await);
    assert_eq!(source.get_calls(), 1);

    watch
        .send(Err(DecisionSourceError::new(
            DecisionSourceErrorKind::Wire,
            "invalid typed watch change",
        )))
        .expect("watch remains live");
    wait_for_metric(&runtime.metrics.wire_failures, 1).await;
    wait_for_watch_connected(&runtime.metrics, false).await;
    assert_eq!(runtime.metrics.watch_disconnects.load(Ordering::Relaxed), 1);
    tokio::time::advance(Duration::from_millis(125)).await;
    source.wait_for_watches(2).await;
    wait_for_watch_connected(&runtime.metrics, true).await;
    assert_rejected(
        &call_subject(&runtime.layer, SUBJECT_A).await,
        Code::FailedPrecondition,
    );
    assert_eq!(source.get_calls(), 2);
    runtime.stop().await;
}

#[tokio::test(start_paused = true)]
async fn sustained_disconnect_promotes_health_from_warning_to_failed() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let PolicyGateRuntime {
        watcher,
        health,
        metrics,
        ..
    } = runtime(
        Arc::clone(&source),
        &ConfigOptions {
            unary_timeout: Duration::from_millis(1),
            admission_timeout: Duration::from_millis(20),
            ..ConfigOptions::default()
        },
    );

    assert!(matches!(
        health.status(),
        DecisionSourceHealthStatus::NotYetStable
    ));
    tokio::time::advance(Duration::from_millis(30)).await;
    assert!(matches!(
        health.status(),
        DecisionSourceHealthStatus::Failed
    ));

    let _watch = source.push_live_watch(Vec::new()).await;
    let (shutdown, _) = broadcast::channel(1);
    let task = tokio::spawn({
        let mut shutdown_rx = shutdown.subscribe();
        async move {
            tokio::select! {
                () = watcher => {}
                _ = shutdown_rx.recv() => {}
            }
        }
    });
    source.wait_for_watches(1).await;
    wait_for_watch_connected(&metrics, true).await;
    assert!(matches!(
        health.status(),
        DecisionSourceHealthStatus::Failed
    ));
    tokio::time::advance(Duration::from_millis(4_999)).await;
    assert!(!matches!(
        health.status(),
        DecisionSourceHealthStatus::Stable
    ));
    tokio::time::advance(Duration::from_millis(1)).await;
    wait_for_health(&health, true).await;
    assert!(matches!(
        health.status(),
        DecisionSourceHealthStatus::Stable
    ));
    drop(shutdown.send(()));
    task.await.expect("watch task joins");
}

#[tokio::test(start_paused = true)]
async fn flapping_watch_streams_still_promote_health_to_failed() {
    let source = Arc::new(ScriptedDecisionSource::default());
    drop(source.push_live_watch(Vec::new()).await);
    drop(source.push_live_watch(Vec::new()).await);
    let _stable_watch = source.push_live_watch(Vec::new()).await;
    let PolicyGateRuntime {
        watcher,
        health,
        metrics,
        ..
    } = runtime(
        Arc::clone(&source),
        &ConfigOptions {
            unary_timeout: Duration::from_millis(1),
            admission_timeout: Duration::from_millis(20),
            ..ConfigOptions::default()
        },
    );
    let (shutdown, _) = broadcast::channel(1);
    let task = tokio::spawn({
        let mut shutdown_rx = shutdown.subscribe();
        async move {
            tokio::select! {
                () = watcher => {}
                _ = shutdown_rx.recv() => {}
            }
        }
    });

    source.wait_for_watches(1).await;
    for _ in 0..1_000 {
        if source.watch_calls() >= 3 {
            break;
        }
        tokio::time::advance(Duration::from_millis(1)).await;
    }
    assert_eq!(source.watch_calls(), 3);
    wait_for_watch_connected(&metrics, true).await;
    tokio::time::advance(Duration::from_millis(30)).await;
    assert!(matches!(
        health.status(),
        DecisionSourceHealthStatus::Failed
    ));

    tokio::time::advance(Duration::from_secs(5)).await;
    wait_for_health(&health, true).await;
    drop(shutdown.send(()));
    task.await.expect("watch task joins");
}

#[tokio::test(start_paused = true)]
async fn reconnect_backoff_resets_only_after_a_stable_stream() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let first = source.push_live_watch(Vec::new()).await;
    let second = source.push_live_watch(Vec::new()).await;
    let third = source.push_live_watch(Vec::new()).await;
    let _fourth = source.push_live_watch(Vec::new()).await;
    let options = ConfigOptions {
        initial_reconnect_delay: Duration::from_millis(200),
        max_reconnect_delay: Duration::from_secs(2),
        ..ConfigOptions::default()
    };
    let runtime = start_runtime(Arc::clone(&source), &options).await;
    tokio::time::advance(Duration::from_secs(2)).await;
    wait_for_health(&runtime.health, true).await;

    drop(first);
    wait_for_watch_connected(&runtime.metrics, false).await;
    tokio::time::advance(Duration::from_millis(249)).await;
    source.wait_for_watches(2).await;
    wait_for_watch_connected(&runtime.metrics, true).await;
    drop(second);
    wait_for_watch_connected(&runtime.metrics, false).await;
    tokio::time::advance(Duration::from_millis(299)).await;
    assert_eq!(source.watch_calls(), 2);
    tokio::time::advance(Duration::from_millis(200)).await;
    source.wait_for_watches(3).await;
    wait_for_watch_connected(&runtime.metrics, true).await;

    tokio::time::advance(Duration::from_millis(1_999)).await;
    assert!(!matches!(
        runtime.health.status(),
        DecisionSourceHealthStatus::Stable
    ));
    tokio::time::advance(Duration::from_millis(1)).await;
    wait_for_health(&runtime.health, true).await;
    drop(third);
    wait_for_watch_connected(&runtime.metrics, false).await;
    tokio::time::advance(Duration::from_millis(149)).await;
    assert_eq!(source.watch_calls(), 3);
    tokio::time::advance(Duration::from_millis(100)).await;
    source.wait_for_watches(4).await;
    runtime.stop().await;
}

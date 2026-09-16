// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::future::Future as _;
use core::sync::atomic::Ordering;
use core::task::{Context, Poll};
use core::time::Duration;
use std::sync::Arc;

use policy_gate::{AdmissionState, Decision, DecisionSourceError, DecisionSourceErrorKind};
use tokio::sync::{Semaphore, oneshot};
use tonic::Code;

use crate::support::{
    ConfigOptions, GetAction, PAYMENT_URL, RecordingWaker, SUBJECT_A, SUBJECT_B, SUBJECT_C,
    ScriptedDecisionSource, assert_allowed, assert_rejected, call_layer, call_subject, change,
    runtime, start_runtime, start_runtime_after, wait_for_metric, withdrawal,
};

const UNAVAILABLE_MESSAGE: &str = "Policy decision source is unavailable; retry the request.";
const MISSING_SUBJECT_MESSAGE: &str =
    "request is missing the subject identifier required for policy enforcement";

fn assert_unavailable(call: &crate::support::ObservedCall) {
    assert_rejected(call, Code::Unavailable);
    let status = call.status.as_ref().expect("gRPC status");
    assert_eq!(status.message(), UNAVAILABLE_MESSAGE);
}

#[tokio::test]
async fn missing_subject_is_rejected() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;

    let missing = call_layer(&runtime.layer, None).await;
    assert_rejected(&missing, Code::FailedPrecondition);
    assert_eq!(
        missing.status.as_ref().expect("gRPC status").message(),
        MISSING_SUBJECT_MESSAGE
    );
    assert_eq!(source.get_calls(), 0);
    runtime.stop().await;
}

#[tokio::test]
async fn disconnected_request_waits_for_watch_then_is_admitted() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    let runtime = start_runtime_after(
        Arc::clone(&source),
        &ConfigOptions::default(),
        Duration::from_secs(1),
    );
    let call = tokio::spawn({
        let layer = runtime.layer.clone();
        async move { call_subject(&layer, SUBJECT_A).await }
    });
    tokio::task::yield_now().await;
    runtime.time.advance(Duration::from_secs(1)).await;
    assert_allowed(&call.await.expect("call joins"));
    assert_eq!(source.get_calls(), 1);
    runtime.stop().await;
}

#[tokio::test]
async fn disconnected_request_times_out_at_the_admission_deadline() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let runtime = runtime(
        Arc::clone(&source),
        &ConfigOptions {
            admission_timeout: Duration::from_secs(1),
            ..ConfigOptions::default()
        },
    );
    let call = tokio::spawn({
        let layer = runtime.layer.clone();
        async move { call_subject(&layer, SUBJECT_A).await }
    });
    tokio::task::yield_now().await;
    runtime.time.advance(Duration::from_millis(999)).await;
    assert!(!call.is_finished());
    runtime.time.advance(Duration::from_millis(1)).await;
    let result = call.await.expect("call joins");

    assert_unavailable(&result);
    assert_eq!(source.get_calls(), 0);
    assert_eq!(
        runtime.metrics.admission_timeouts.load(Ordering::Relaxed),
        1
    );
}

#[tokio::test]
async fn unavailable_admission_uses_the_configured_response_callback() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let runtime = runtime(
        Arc::clone(&source),
        &ConfigOptions {
            admission_timeout: Duration::from_secs(1),
            ..ConfigOptions::default()
        },
    );
    let callback_calls = Box::leak(Box::new(core::sync::atomic::AtomicUsize::new(0)));
    let observed_callback_calls: &'static core::sync::atomic::AtomicUsize = callback_calls;
    let layer = runtime.layer.with_unavailable_response(move |_error| {
        observed_callback_calls.fetch_add(1, Ordering::Relaxed);
        tonic::Status::resource_exhausted("custom unavailable response").into_http()
    });

    let ((), result) = tokio::join!(
        async {
            tokio::task::yield_now().await;
            runtime.time.advance(Duration::from_secs(1)).await;
        },
        call_subject(&layer, SUBJECT_A),
    );

    assert_rejected(&result, Code::ResourceExhausted);
    assert_eq!(
        result.status.as_ref().expect("gRPC status").message(),
        "custom unavailable response"
    );
    assert_eq!(callback_calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn shutdown_rejects_new_admissions_without_waiting_for_the_deadline() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    let release = Arc::new(Semaphore::new(0));
    source
        .push_get(
            SUBJECT_A,
            GetAction::Gate {
                release,
                result: Ok(Decision::Allowed),
            },
        )
        .await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;
    let layer = runtime.layer.clone();
    let task_layer = layer.clone();
    let call = tokio::spawn(async move { call_subject(&task_layer, SUBJECT_A).await });
    source.wait_for_gets(1).await;
    runtime.stop().await;

    assert_unavailable(&call.await.expect("admission task joins"));
    assert_eq!(source.get_calls(), 1);

    assert_unavailable(&call_subject(&layer, SUBJECT_B).await);
    assert_eq!(source.get_calls(), 1);
}

#[tokio::test]
async fn dropping_an_unpolled_watcher_stops_admission() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let runtime = runtime(Arc::clone(&source), &ConfigOptions::default());
    let layer = runtime.layer.clone();
    drop(runtime.watcher);

    assert_unavailable(&call_subject(&layer, SUBJECT_A).await);
    assert_eq!(source.watch_calls(), 0);
    assert_eq!(source.get_calls(), 0);
}

#[tokio::test]
async fn dropping_the_watcher_wakes_an_admission_waiting_for_connection() {
    let source = Arc::new(ScriptedDecisionSource::default());
    source.push_pending_watch().await;
    let runtime = runtime(Arc::clone(&source), &ConfigOptions::default());
    let layer = runtime.layer.clone();
    let metrics = runtime.metrics;
    let (stop, stopped) = oneshot::channel();
    let watcher_task = tokio::spawn(async move {
        tokio::select! {
            () = runtime.watcher => {}
            _ = stopped => {}
        }
    });
    source.wait_for_watches(1).await;
    let admission = tokio::spawn(async move { call_subject(&layer, SUBJECT_A).await });
    tokio::task::yield_now().await;

    stop.send(()).expect("watcher remains live");
    watcher_task.await.expect("watcher task joins");

    assert_unavailable(&admission.await.expect("admission task joins"));
    assert_eq!(source.get_calls(), 0);
    assert_eq!(metrics.admission_timeouts.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn denied_is_cached_until_an_allowed_event() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Denied)))
        .await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;

    let denied = call_subject(&runtime.layer, SUBJECT_A).await;
    assert_rejected(&denied, Code::FailedPrecondition);
    assert_eq!(
        denied.status.expect("denial status").message(),
        format!(
            "Your organization has reached its cache usage limit. Visit {PAYMENT_URL} to review usage and restore access."
        )
    );
    assert_rejected(
        &call_subject(&runtime.layer, SUBJECT_A).await,
        Code::FailedPrecondition,
    );
    assert_eq!(source.get_calls(), 1);

    watch
        .send(Ok(change(SUBJECT_A, Decision::Allowed)))
        .expect("watch remains live");
    wait_for_metric(&runtime.metrics.watch_events, 1).await;
    assert_allowed(&call_subject(&runtime.layer, SUBJECT_A).await);
    assert_eq!(source.get_calls(), 1);
    runtime.stop().await;
}

#[tokio::test]
async fn dropped_first_requester_does_not_cancel_the_shared_fetch() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    let release = Arc::new(Semaphore::new(0));
    source
        .push_get(
            SUBJECT_A,
            GetAction::Gate {
                release: Arc::clone(&release),
                result: Ok(Decision::Allowed),
            },
        )
        .await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;
    let cancelled = tokio::spawn({
        let layer = runtime.layer.clone();
        async move { call_subject(&layer, SUBJECT_A).await }
    });
    source.wait_for_gets(1).await;

    cancelled.abort();
    match cancelled.await {
        Err(error) => assert!(error.is_cancelled()),
        Ok(_) => panic!("request must be cancelled"),
    }
    let second = tokio::spawn({
        let layer = runtime.layer.clone();
        async move { call_subject(&layer, SUBJECT_A).await }
    });
    wait_for_metric(&runtime.metrics.snapshot_misses, 2).await;
    assert_eq!(source.get_calls(), 1);
    release.add_permits(1);

    assert_allowed(&second.await.expect("second call joins"));
    assert_eq!(source.get_calls(), 1);
    runtime.stop().await;
}

#[tokio::test]
async fn concurrent_pending_requests_share_one_unary() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    let release = Arc::new(Semaphore::new(0));
    source
        .push_get(
            SUBJECT_A,
            GetAction::Gate {
                release: Arc::clone(&release),
                result: Ok(Decision::Allowed),
            },
        )
        .await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;
    let first = tokio::spawn({
        let layer = runtime.layer.clone();
        async move { call_subject(&layer, SUBJECT_A).await }
    });
    source.wait_for_gets(1).await;
    let second = tokio::spawn({
        let layer = runtime.layer.clone();
        async move { call_subject(&layer, SUBJECT_A).await }
    });
    wait_for_metric(&runtime.metrics.snapshot_misses, 2).await;
    assert_eq!(source.get_calls(), 1);
    release.add_permits(1);

    assert_allowed(&first.await.expect("first call joins"));
    assert_allowed(&second.await.expect("second call joins"));
    assert_eq!(source.get_calls(), 1);
    assert_allowed(&call_subject(&runtime.layer, SUBJECT_A).await);
    assert_eq!(source.get_calls(), 1);
    runtime.stop().await;
}

#[tokio::test]
async fn transient_unary_failure_is_retried_then_admitted() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(
            SUBJECT_A,
            GetAction::Return(Err(DecisionSourceError::new(
                DecisionSourceErrorKind::Transient,
                "database unavailable",
            ))),
        )
        .await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;
    let call = tokio::spawn({
        let layer = runtime.layer.clone();
        async move { call_subject(&layer, SUBJECT_A).await }
    });
    source.wait_for_gets(1).await;
    runtime.time.advance(Duration::from_millis(100)).await;

    assert_allowed(&call.await.expect("call joins"));
    assert_eq!(source.get_calls(), 2);
    runtime.stop().await;
}

#[tokio::test]
async fn permanent_unary_status_fails_fast() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(
            SUBJECT_A,
            GetAction::Return(Err(DecisionSourceError::new(
                DecisionSourceErrorKind::Permanent,
                "subject not enrolled",
            ))),
        )
        .await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;
    let result = call_subject(&runtime.layer, SUBJECT_A).await;

    assert_unavailable(&result);
    assert_eq!(source.get_calls(), 1);
    assert_eq!(runtime.metrics.admission_retries.load(Ordering::Relaxed), 0);
    assert_eq!(
        runtime.metrics.admission_timeouts.load(Ordering::Relaxed),
        0
    );
    runtime.stop().await;
}

#[tokio::test]
async fn permanent_failure_cooldown_coalesces_later_requests() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(
            SUBJECT_A,
            GetAction::Return(Err(DecisionSourceError::new(
                DecisionSourceErrorKind::Permanent,
                "subject not enrolled",
            ))),
        )
        .await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    let runtime = start_runtime(
        Arc::clone(&source),
        &ConfigOptions {
            permanent_failure_cooldown: Duration::from_millis(250),
            ..ConfigOptions::default()
        },
    )
    .await;

    assert_unavailable(&call_subject(&runtime.layer, SUBJECT_A).await);
    assert_eq!(source.get_calls(), 1);
    assert_eq!(runtime.metrics.unary_calls.load(Ordering::Relaxed), 1);
    assert_eq!(runtime.metrics.unary_failures.load(Ordering::Relaxed), 1);
    let snapshot_misses = runtime.metrics.snapshot_misses.load(Ordering::Relaxed);
    let first = tokio::spawn({
        let layer = runtime.layer.clone();
        async move { call_subject(&layer, SUBJECT_A).await }
    });
    let second = tokio::spawn({
        let layer = runtime.layer.clone();
        async move { call_subject(&layer, SUBJECT_A).await }
    });
    wait_for_metric(&runtime.metrics.snapshot_misses, snapshot_misses + 2).await;

    runtime.time.advance(Duration::from_millis(249)).await;
    assert_eq!(source.get_calls(), 1);
    assert!(!first.is_finished());
    assert!(!second.is_finished());
    runtime.time.advance(Duration::from_millis(1)).await;
    source.wait_for_gets(2).await;

    assert_allowed(&first.await.expect("first waiting call joins"));
    assert_allowed(&second.await.expect("second waiting call joins"));
    assert_eq!(source.get_calls(), 2);
    runtime.stop().await;
}

#[tokio::test]
async fn missing_unary_decision_is_retried() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    source.push_get(SUBJECT_B, GetAction::Missing).await;
    source
        .push_get(SUBJECT_B, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    let runtime = start_runtime(
        Arc::clone(&source),
        &ConfigOptions {
            initial_admission_retry_delay: Duration::from_millis(250),
            ..ConfigOptions::default()
        },
    )
    .await;
    let first = tokio::spawn({
        let layer = runtime.layer.clone();
        async move { call_subject(&layer, SUBJECT_B).await }
    });
    source.wait_for_gets(1).await;
    wait_for_metric(&runtime.metrics.admission_retries, 1).await;

    runtime.time.advance(Duration::from_millis(249)).await;
    assert_eq!(source.get_calls(), 1);
    runtime.time.advance(Duration::from_millis(1)).await;
    source.wait_for_gets(2).await;

    assert_allowed(&first.await.expect("first call joins"));
    assert_eq!(runtime.metrics.unary_failures.load(Ordering::Relaxed), 1);
    assert_eq!(runtime.metrics.admission_retries.load(Ordering::Relaxed), 1);
    runtime.stop().await;
}

#[tokio::test]
async fn unknown_unary_state_fails_fast_as_a_wire_error() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(
            SUBJECT_C,
            GetAction::Return(Err(DecisionSourceError::new(
                DecisionSourceErrorKind::Wire,
                "unknown state",
            ))),
        )
        .await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;
    assert_unavailable(&call_subject(&runtime.layer, SUBJECT_C).await);
    assert_eq!(source.get_calls(), 1);
    assert_eq!(runtime.metrics.wire_failures.load(Ordering::Relaxed), 1);
    assert_eq!(runtime.metrics.admission_retries.load(Ordering::Relaxed), 0);
    runtime.stop().await;
}

#[tokio::test]
async fn watch_verdict_wakes_pending_admission_before_unary_completion() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let watch = source.push_live_watch(Vec::new()).await;
    let release = Arc::new(Semaphore::new(0));
    source
        .push_get(
            SUBJECT_A,
            GetAction::Gate {
                release: Arc::clone(&release),
                result: Ok(Decision::Allowed),
            },
        )
        .await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;
    let layer = runtime.layer.clone();
    let mut call = Box::pin(call_subject(&layer, SUBJECT_A));
    let wake_counter = Arc::new(RecordingWaker::default());
    let waker = wake_counter.waker();
    let mut context = Context::from_waker(&waker);
    assert!(matches!(call.as_mut().poll(&mut context), Poll::Pending));
    source.wait_for_gets(1).await;

    let wakes_before_denial = wake_counter.count();
    watch
        .send(Ok(change(SUBJECT_A, Decision::Denied)))
        .expect("watch remains live");
    wait_for_metric(&runtime.metrics.watch_events, 1).await;
    assert!(wake_counter.count() > wakes_before_denial);
    let Poll::Ready(result) = call.as_mut().poll(&mut context) else {
        panic!("watch verdict must complete the pending admission after waking it");
    };
    assert_rejected(&result, Code::FailedPrecondition);
    assert_eq!(source.get_calls(), 1);
    release.add_permits(1);
    runtime.stop().await;
}

#[tokio::test]
async fn disconnect_mid_fetch_reconnects_and_refetches_before_admitting() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let first_watch = source.push_live_watch(Vec::new()).await;
    let release = Arc::new(Semaphore::new(0));
    source
        .push_get(
            SUBJECT_A,
            GetAction::Gate {
                release: Arc::clone(&release),
                result: Ok(Decision::Allowed),
            },
        )
        .await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;
    let call = tokio::spawn({
        let layer = runtime.layer.clone();
        async move { call_subject(&layer, SUBJECT_A).await }
    });
    source.wait_for_gets(1).await;

    let _second_watch = source.push_live_watch(Vec::new()).await;
    drop(first_watch);
    crate::support::wait_for_watch_connected(&runtime.metrics, false).await;
    runtime.time.advance(Duration::from_millis(125)).await;
    source.wait_for_watches(2).await;
    crate::support::wait_for_watch_connected(&runtime.metrics, true).await;
    release.add_permits(1);
    source.wait_for_get_completions(1).await;
    source.wait_for_gets(2).await;

    assert_allowed(&call.await.expect("call joins"));
    assert_eq!(source.get_calls(), 2);
    assert_eq!(runtime.metrics.admission_retries.load(Ordering::Relaxed), 0);
    runtime.stop().await;
}

#[tokio::test]
async fn withdrawn_decision_forgets_a_known_subject() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Denied)))
        .await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;

    assert_allowed(&call_subject(&runtime.layer, SUBJECT_A).await);
    watch
        .send(Ok(withdrawal(SUBJECT_A)))
        .expect("watch remains live");
    wait_for_metric(&runtime.metrics.watch_events, 1).await;
    assert_rejected(
        &call_subject(&runtime.layer, SUBJECT_A).await,
        Code::FailedPrecondition,
    );
    assert_eq!(source.get_calls(), 2);
    runtime.stop().await;
}

#[tokio::test]
async fn admission_reads_current_state_after_authority_changes() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Denied)))
        .await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;
    let subject = SUBJECT_A.parse().expect("subject");
    let admission = runtime
        .gate
        .admit(&subject)
        .await
        .expect("authoritative denial");
    assert_eq!(admission.state(), AdmissionState::Denied);
    assert!(!admission.is_allowed());
    let cached = runtime
        .gate
        .try_cached(&subject)
        .await
        .expect("cached denial handle");
    assert!(!cached.is_allowed());

    watch
        .send(Ok(change(SUBJECT_A, Decision::Allowed)))
        .expect("live watch");
    wait_for_metric(&runtime.metrics.watch_events, 1).await;
    assert_eq!(admission.state(), AdmissionState::Allowed);
    assert_eq!(cached.state(), AdmissionState::Allowed);
    assert!(cached.is_allowed());

    watch.send(Ok(withdrawal(SUBJECT_A))).expect("live watch");
    wait_for_metric(&runtime.metrics.watch_events, 2).await;
    assert_eq!(admission.state(), AdmissionState::Stale);
    assert!(!admission.is_allowed());
    assert!(!cached.is_allowed());
    runtime.stop().await;
}

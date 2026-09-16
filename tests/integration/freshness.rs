// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::pin::Pin;
use core::sync::atomic::Ordering;
use core::task::{Context, Poll};
use core::time::Duration;
use std::sync::Arc;

use bytes::Bytes;
use http_body::{Body as _, Frame};
use policy_gate::{Admission, AdmissionState, Decision};
use tokio::sync::Semaphore;
use tonic::{Code, Status};

use crate::support::{
    ConfigOptions, GetAction, RecordingWaker, SUBJECT_A, SUBJECT_B, ScriptedDecisionSource, change,
    start_runtime, start_streaming_call, wait_for_metric,
};

fn freshness_config() -> ConfigOptions {
    ConfigOptions {
        decision_freshness_ttl: Duration::from_millis(100),
        ..ConfigOptions::default()
    }
}

async fn admit_allowed(
    runtime: &crate::support::RunningRuntime,
    subject: &str,
) -> Admission<crate::support::TestTimeDriver> {
    let subject = subject.parse().expect("test subject UUID");
    let admission = runtime
        .gate
        .admit(&subject)
        .await
        .expect("admission succeeds");
    assert!(admission.is_allowed(), "subject must be allowed");
    admission
}

#[tokio::test]
async fn freshness_is_disabled_by_default() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;
    let admission = admit_allowed(&runtime, SUBJECT_A).await;

    runtime.time.advance(Duration::from_secs(60)).await;

    assert_eq!(source.get_calls(), 1);
    assert_eq!(admission.state(), AdmissionState::Allowed);
    runtime.stop().await;
}

#[tokio::test]
async fn ordinary_access_does_not_extend_the_absolute_deadline() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    for _ in 0..2 {
        source
            .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
            .await;
    }
    let runtime = start_runtime(Arc::clone(&source), &freshness_config()).await;
    let admission = admit_allowed(&runtime, SUBJECT_A).await;

    runtime.time.advance(Duration::from_millis(70)).await;
    let subject = SUBJECT_A.parse().expect("test subject UUID");
    drop(
        runtime
            .gate
            .try_cached(&subject)
            .expect("decision remains fresh"),
    );
    runtime.time.advance(Duration::from_millis(29)).await;
    assert!(runtime.gate.try_cached(&subject).is_some());
    runtime.time.advance(Duration::from_millis(1)).await;

    assert!(!admission.is_allowed());
    assert_eq!(admission.state(), AdmissionState::Stale);
    assert!(
        runtime.gate.try_cached(&subject).is_none(),
        "ordinary access does not extend absolute freshness"
    );
    drop(admit_allowed(&runtime, SUBJECT_A).await);
    assert_eq!(source.get_calls(), 2);
    runtime.stop().await;
}

#[tokio::test]
async fn denied_decision_expires_and_is_refetched() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Denied)))
        .await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    let runtime = start_runtime(Arc::clone(&source), &freshness_config()).await;
    let subject = SUBJECT_A.parse().expect("test subject UUID");
    assert_eq!(
        runtime.gate.admit(&subject).await.expect("denial").state(),
        AdmissionState::Denied
    );

    runtime.time.advance(Duration::from_millis(100)).await;

    assert!(runtime.gate.try_cached(&subject).is_none());
    drop(admit_allowed(&runtime, SUBJECT_A).await);
    assert_eq!(source.get_calls(), 2);
    runtime.stop().await;
}

#[tokio::test]
async fn watch_change_starts_a_new_absolute_window() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    let runtime = start_runtime(Arc::clone(&source), &freshness_config()).await;
    let admission = admit_allowed(&runtime, SUBJECT_A).await;

    runtime.time.advance(Duration::from_millis(70)).await;
    watch
        .send(Ok(change(SUBJECT_A, Decision::Allowed)))
        .expect("watch remains live");
    wait_for_metric(&runtime.metrics.watch_events, 1).await;

    runtime.time.advance(Duration::from_millis(99)).await;
    assert_eq!(admission.state(), AdmissionState::Allowed);
    runtime.time.advance(Duration::from_millis(1)).await;

    assert_eq!(admission.state(), AdmissionState::Stale);
    assert_eq!(source.get_calls(), 1);
    runtime.stop().await;
}

#[tokio::test]
async fn subject_ttl_remains_sliding_and_can_expire_first() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    for subject in [SUBJECT_A, SUBJECT_B] {
        source
            .push_get(subject, GetAction::Return(Ok(Decision::Allowed)))
            .await;
    }
    let mut config = freshness_config();
    config.subject_ttl = Duration::from_millis(50);
    let runtime = start_runtime(Arc::clone(&source), &config).await;
    let first_admission = admit_allowed(&runtime, SUBJECT_A).await;

    runtime.time.advance(Duration::from_millis(40)).await;
    let first = SUBJECT_A.parse().expect("test subject UUID");
    drop(
        runtime
            .gate
            .try_cached(&first)
            .expect("access renews idle age"),
    );
    runtime.time.advance(Duration::from_millis(40)).await;
    drop(admit_allowed(&runtime, SUBJECT_B).await);
    assert_eq!(first_admission.state(), AdmissionState::Allowed);

    runtime.time.advance(Duration::from_millis(11)).await;
    let second = SUBJECT_B.parse().expect("test subject UUID");
    drop(
        runtime
            .gate
            .try_cached(&second)
            .expect("second subject is cached"),
    );

    assert_eq!(
        first_admission.state(),
        AdmissionState::Stale,
        "sliding idle TTL expires the first subject before absolute freshness"
    );
    assert_eq!(source.get_calls(), 2);
    runtime.stop().await;
}

#[tokio::test]
async fn watch_can_renew_an_expired_entry() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let watch = source.push_live_watch(Vec::new()).await;
    let runtime = start_runtime(Arc::clone(&source), &freshness_config()).await;
    let admission = admit_allowed(&runtime, SUBJECT_A).await;
    runtime.time.advance(Duration::from_millis(100)).await;
    assert_eq!(admission.state(), AdmissionState::Stale);
    assert!(!admission.is_allowed());

    watch
        .send(Ok(change(SUBJECT_A, Decision::Allowed)))
        .expect("live watch");
    wait_for_metric(&runtime.metrics.watch_events, 1).await;
    assert_eq!(admission.state(), AdmissionState::Allowed);
    assert!(admission.is_allowed());

    watch
        .send(Ok(change(SUBJECT_A, Decision::Denied)))
        .expect("live watch");
    wait_for_metric(&runtime.metrics.watch_events, 2).await;
    assert_eq!(admission.state(), AdmissionState::Denied);
    assert!(!admission.is_allowed());
    assert_eq!(source.get_calls(), 1);
    runtime.stop().await;
}

#[tokio::test]
async fn idle_bodies_cut_off_expiry_on_the_next_poll_even_after_cached_readmission() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    let runtime = start_runtime(Arc::clone(&source), &freshness_config()).await;
    let mut call = start_streaming_call(&runtime.layer, SUBJECT_A).await;
    let wake_counter = Arc::new(RecordingWaker::default());
    let waker = wake_counter.waker();
    let mut cx = Context::from_waker(&waker);
    assert!(
        Pin::new(&mut call.request_body)
            .poll_frame(&mut cx)
            .is_pending()
    );
    assert!(
        Pin::new(&mut call.response_body)
            .poll_frame(&mut cx)
            .is_pending()
    );
    let before = wake_counter.count();
    let request_polls = call.request_probe.polls.load(Ordering::Relaxed);
    let response_polls = call.response_probe.polls.load(Ordering::Relaxed);

    runtime.time.advance(Duration::from_millis(100)).await;
    assert_eq!(
        wake_counter.count(),
        before,
        "idle streams must not wake for expiry"
    );
    assert_eq!(source.get_calls(), 1);
    assert!(admit_allowed(&runtime, SUBJECT_A).await.is_allowed());
    assert_eq!(source.get_calls(), 2);
    call.request_sender
        .send(Ok(Frame::data(Bytes::from_static(b"blocked"))))
        .expect("live request");
    call.response_sender
        .send(Ok(Frame::data(Bytes::from_static(b"blocked"))))
        .expect("live response");
    assert!(matches!(
        Pin::new(&mut call.request_body).poll_frame(&mut cx),
        Poll::Ready(Some(Err(_)))
    ));
    let Poll::Ready(Some(Ok(frame))) = Pin::new(&mut call.response_body).poll_frame(&mut cx) else {
        panic!("expired response emits rejection trailers");
    };
    let status = Status::from_header_map(frame.trailers_ref().expect("trailers")).expect("status");
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(
        call.request_probe.polls.load(Ordering::Relaxed),
        request_polls
    );
    assert_eq!(
        call.response_probe.polls.load(Ordering::Relaxed),
        response_polls
    );
    assert_eq!(runtime.metrics.stream_cutoffs.load(Ordering::Relaxed), 2);
    assert_eq!(source.get_calls(), 2, "cutoff must not start readmission");
    runtime.stop().await;
}

#[tokio::test]
async fn expired_admission_cuts_off_without_attempting_readmission() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    let runtime = start_runtime(Arc::clone(&source), &freshness_config()).await;
    let mut call = start_streaming_call(&runtime.layer, SUBJECT_A).await;
    let wake_counter = Arc::new(RecordingWaker::default());
    let waker = wake_counter.waker();
    let mut cx = Context::from_waker(&waker);
    assert!(
        Pin::new(&mut call.request_body)
            .poll_frame(&mut cx)
            .is_pending()
    );

    runtime.time.advance(Duration::from_millis(100)).await;

    assert!(matches!(
        Pin::new(&mut call.request_body).poll_frame(&mut cx),
        Poll::Ready(Some(Err(_)))
    ));
    assert_eq!(
        source.get_calls(),
        1,
        "an expired admission must cut off without attempting readmission"
    );
    runtime.stop().await;
}

#[tokio::test]
async fn unrepresentable_deadline_fails_closed() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    source
        .push_get(
            SUBJECT_A,
            GetAction::Gate {
                release: Arc::new(Semaphore::new(0)),
                result: Ok(Decision::Allowed),
            },
        )
        .await;
    let config = ConfigOptions {
        decision_freshness_ttl: Duration::from_nanos((1_u64 << 62) - 1),
        ..ConfigOptions::default()
    };
    let runtime = start_runtime(Arc::clone(&source), &config).await;
    let gate = runtime.gate.clone();
    let admission = tokio::spawn(async move {
        let subject = SUBJECT_A.parse().expect("test subject UUID");
        gate.admit(&subject).await
    });
    source.wait_for_gets(2).await;

    runtime.time.advance(config.admission_timeout).await;

    assert!(admission.await.expect("admission task joins").is_err());
    runtime.stop().await;
}

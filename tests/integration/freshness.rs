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
            .await
            .expect("decision remains fresh"),
    );
    runtime.time.advance(Duration::from_millis(29)).await;
    assert!(runtime.gate.try_cached(&subject).await.is_some());
    runtime.time.advance(Duration::from_millis(1)).await;

    assert!(!admission.is_allowed());
    assert_eq!(admission.state(), AdmissionState::Stale);
    assert!(
        runtime.gate.try_cached(&subject).await.is_none(),
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

    assert!(runtime.gate.try_cached(&subject).await.is_none());
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
            .await
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
            .await
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
    // An unusable effective snapshot takes admission backoff before the next lookup.
    wait_for_metric(&runtime.metrics.admission_retries, 1).await;
    runtime
        .time
        .advance(config.initial_admission_retry_delay)
        .await;
    source.wait_for_gets(2).await;

    runtime.time.advance(config.admission_timeout).await;

    assert!(admission.await.expect("admission task joins").is_err());
    runtime.stop().await;
}

fn refresh_config() -> ConfigOptions {
    ConfigOptions {
        refresh_before_expiry: Duration::from_millis(40),
        permanent_failure_cooldown: Duration::from_millis(20),
        ..freshness_config()
    }
}

#[tokio::test]
async fn check_reports_refresh_due_only_inside_the_window() {
    for (config, decision) in [
        (refresh_config(), Decision::Allowed),
        (refresh_config(), Decision::Denied),
        (freshness_config(), Decision::Allowed),
        (ConfigOptions::default(), Decision::Allowed),
    ] {
        let source = Arc::new(ScriptedDecisionSource::default());
        let _watch = source.push_live_watch(Vec::new()).await;
        source
            .push_get(SUBJECT_A, GetAction::Return(Ok(decision)))
            .await;
        let runtime = start_runtime(Arc::clone(&source), &config).await;
        let subject = SUBJECT_A.parse().expect("subject UUID");
        let admission = runtime.gate.admit(&subject).await.expect("admission");
        let state = match decision {
            Decision::Allowed => AdmissionState::Allowed,
            Decision::Denied => AdmissionState::Denied,
        };
        assert_eq!(admission.check(), (state, false));
        for (advance, in_window) in [(59, false), (1, true), (39, true)] {
            runtime.time.advance(Duration::from_millis(advance)).await;
            assert_eq!(
                admission.check(),
                (state, in_window && !config.refresh_before_expiry.is_zero())
            );
        }
        runtime.time.advance(Duration::from_millis(1)).await;
        let expired = config.decision_freshness_ttl != Duration::MAX;
        assert_eq!(
            admission.check(),
            (
                if expired {
                    AdmissionState::Stale
                } else {
                    state
                },
                false
            )
        );
        assert_eq!(source.get_calls(), 1, "checking never starts a lookup");
        runtime.stop().await;
    }
}

#[tokio::test]
async fn refresh_renews_the_retained_handle_in_place() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    let runtime = start_runtime(Arc::clone(&source), &refresh_config()).await;
    let admission = admit_allowed(&runtime, SUBJECT_A).await;
    let subject = SUBJECT_A.parse().expect("subject UUID");
    runtime.time.advance(Duration::from_millis(60)).await;
    runtime.gate.refresh(subject, admission.clone()).await;
    source.wait_for_get_completions(2).await;
    assert_eq!(admission.check(), (AdmissionState::Allowed, false));
    runtime.time.advance(Duration::from_millis(99)).await;
    assert!(admission.is_allowed());
    runtime.time.advance(Duration::from_millis(1)).await;
    assert_eq!(admission.check(), (AdmissionState::Stale, false));
    assert_eq!(source.get_calls(), 2);
    runtime.stop().await;
}

#[tokio::test]
async fn refresh_is_single_flight_across_handles_and_tasks() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    let runtime = start_runtime(Arc::clone(&source), &refresh_config()).await;
    let admission = admit_allowed(&runtime, SUBJECT_A).await;
    let second = admission.clone();
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
    runtime.time.advance(Duration::from_millis(60)).await;
    let subject = SUBJECT_A.parse().expect("subject UUID");
    let first_task = tokio::spawn(runtime.gate.refresh(subject, admission.clone()));
    let second_task = tokio::spawn(runtime.gate.refresh(subject, second.clone()));
    first_task.await.expect("first enqueue");
    second_task.await.expect("second enqueue");
    source.wait_for_gets(2).await;
    assert_eq!(admission.check(), (AdmissionState::Allowed, false));
    assert_eq!(second.check(), (AdmissionState::Allowed, false));
    assert!(runtime.gate.try_cached(&subject).await.is_some());
    assert!(runtime.gate.admit(&subject).await.is_ok());
    assert_eq!(source.get_calls(), 2);
    release.add_permits(1);
    source.wait_for_get_completions(2).await;
    runtime.time.advance(Duration::from_millis(99)).await;
    assert!(second.is_allowed());
    runtime.time.advance(Duration::from_millis(1)).await;
    assert_eq!(admission.state(), AdmissionState::Stale);
    assert_eq!(source.get_calls(), 2);
    runtime.stop().await;
}

#[tokio::test]
async fn failed_refresh_waits_for_the_cooldown() {
    use policy_gate::{DecisionSourceError, DecisionSourceErrorKind};
    for kind in [
        DecisionSourceErrorKind::Transient,
        DecisionSourceErrorKind::Permanent,
        DecisionSourceErrorKind::Wire,
    ] {
        let source = Arc::new(ScriptedDecisionSource::default());
        let _watch = source.push_live_watch(Vec::new()).await;
        let runtime = start_runtime(Arc::clone(&source), &refresh_config()).await;
        let admission = admit_allowed(&runtime, SUBJECT_A).await;
        source
            .push_get(
                SUBJECT_A,
                GetAction::Return(Err(DecisionSourceError::new(kind, "refresh failed"))),
            )
            .await;
        runtime.time.advance(Duration::from_millis(60)).await;
        let subject = SUBJECT_A.parse().expect("subject UUID");
        runtime.gate.refresh(subject, admission.clone()).await;
        source.wait_for_get_completions(2).await;
        for advance in [0, 19] {
            runtime.time.advance(Duration::from_millis(advance)).await;
            assert_eq!(admission.check(), (AdmissionState::Allowed, false));
            assert!(runtime.gate.try_cached(&subject).await.is_some());
            assert!(runtime.gate.admit(&subject).await.is_ok());
            runtime.gate.refresh(subject, admission.clone()).await;
            assert_eq!(source.get_calls(), 2);
        }
        runtime.time.advance(Duration::from_millis(1)).await;
        assert_eq!(admission.check(), (AdmissionState::Allowed, true));
        runtime.gate.refresh(subject, admission.clone()).await;
        source.wait_for_get_completions(3).await;
        assert_eq!(admission.check(), (AdmissionState::Allowed, false));
        runtime.time.advance(Duration::from_millis(99)).await;
        assert!(admission.is_allowed());
        runtime.time.advance(Duration::from_millis(1)).await;
        assert_eq!(admission.state(), AdmissionState::Stale);
        assert_eq!(source.get_calls(), 3);
        runtime.stop().await;
    }
}

#[tokio::test]
async fn zero_cooldown_retries_on_the_next_read() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    let config = ConfigOptions {
        permanent_failure_cooldown: Duration::ZERO,
        ..refresh_config()
    };
    let runtime = start_runtime(Arc::clone(&source), &config).await;
    let admission = admit_allowed(&runtime, SUBJECT_A).await;
    source.push_get(SUBJECT_A, GetAction::Missing).await;
    runtime.time.advance(Duration::from_millis(60)).await;
    let subject = SUBJECT_A.parse().expect("subject UUID");
    runtime.gate.refresh(subject, admission.clone()).await;
    source.wait_for_get_completions(2).await;
    assert_eq!(admission.check(), (AdmissionState::Allowed, true));
    assert!(runtime.gate.try_cached(&subject).await.is_some());
    source.wait_for_get_completions(3).await;
    assert_eq!(admission.check(), (AdmissionState::Allowed, false));
    assert_eq!(source.get_calls(), 3);
    runtime.stop().await;
}

#[tokio::test]
async fn refresh_with_a_mismatched_subject_is_a_no_op() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    let runtime = start_runtime(Arc::clone(&source), &refresh_config()).await;
    let admission = admit_allowed(&runtime, SUBJECT_A).await;
    runtime.time.advance(Duration::from_millis(60)).await;
    let wrong = SUBJECT_B.parse().expect("subject UUID");
    runtime.gate.refresh(wrong, admission.clone()).await;
    assert!(runtime.gate.try_cached(&wrong).await.is_none());
    assert_eq!(source.get_calls(), 1);
    assert_eq!(admission.check(), (AdmissionState::Allowed, true));
    // A wrong subject that is itself cached must also fail the identity check.
    drop(admit_allowed(&runtime, SUBJECT_B).await);
    runtime.gate.refresh(wrong, admission.clone()).await;
    assert_eq!(source.get_calls(), 2);
    assert_eq!(admission.check(), (AdmissionState::Allowed, true));
    runtime.stop().await;
}

#[tokio::test]
async fn refresh_of_a_replaced_entry_is_a_no_op() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    let runtime = start_runtime(Arc::clone(&source), &refresh_config()).await;
    let old = admit_allowed(&runtime, SUBJECT_A).await;
    runtime.time.advance(Duration::from_millis(100)).await;
    let new = admit_allowed(&runtime, SUBJECT_A).await;
    let subject = SUBJECT_A.parse().expect("subject UUID");
    runtime.time.advance(Duration::from_millis(60)).await;
    runtime.gate.refresh(subject, old.clone()).await;
    assert_eq!(source.get_calls(), 2);
    assert_eq!(old.check(), (AdmissionState::Stale, false));
    assert_eq!(new.check(), (AdmissionState::Allowed, true));
    runtime.stop().await;
}

#[tokio::test]
async fn refresh_renews_the_idle_ttl() {
    for touch in [false, true] {
        let source = Arc::new(ScriptedDecisionSource::default());
        let _watch = source.push_live_watch(Vec::new()).await;
        let config = ConfigOptions {
            subject_ttl: Duration::from_millis(50),
            ..refresh_config()
        };
        let runtime = start_runtime(Arc::clone(&source), &config).await;
        let admission = admit_allowed(&runtime, SUBJECT_A).await;
        runtime.time.advance(Duration::from_millis(40)).await;
        if touch {
            runtime
                .gate
                .refresh(SUBJECT_A.parse().expect("subject UUID"), admission.clone())
                .await;
        }
        assert_eq!(source.get_calls(), 1, "outside the refresh window");
        runtime.time.advance(Duration::from_millis(40)).await;
        drop(admit_allowed(&runtime, SUBJECT_B).await);
        assert_eq!(
            admission.state(),
            if touch {
                AdmissionState::Allowed
            } else {
                AdmissionState::Stale
            }
        );
        assert_eq!(source.get_calls(), 2);
        runtime.stop().await;
    }
}

#[tokio::test]
async fn no_events_no_refresh() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    let runtime = start_runtime(Arc::clone(&source), &refresh_config()).await;
    let admission = admit_allowed(&runtime, SUBJECT_A).await;
    runtime.time.advance(Duration::from_millis(100)).await;
    assert_eq!(admission.check(), (AdmissionState::Stale, false));
    runtime
        .gate
        .refresh(SUBJECT_A.parse().expect("subject UUID"), admission.clone())
        .await;
    assert_eq!(admission.state(), AdmissionState::Stale);
    assert_eq!(source.get_calls(), 1);
    runtime.stop().await;
}

#[tokio::test]
async fn refresh_uses_the_retained_entry_when_the_snapshot_lags() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    let config = ConfigOptions {
        snapshot_republish_interval: Duration::from_secs(1),
        ..refresh_config()
    };
    let runtime = start_runtime(Arc::clone(&source), &config).await;
    drop(admit_allowed(&runtime, SUBJECT_A).await);
    let admission = admit_allowed(&runtime, SUBJECT_B).await;
    let subject = SUBJECT_B.parse().expect("subject UUID");
    runtime.time.advance(Duration::from_millis(60)).await;
    assert!(runtime.gate.try_cached(&subject).await.is_none());
    runtime.gate.refresh(subject, admission.clone()).await;
    source.wait_for_get_completions(3).await;
    assert_eq!(admission.check(), (AdmissionState::Allowed, false));
    assert_eq!(source.get_calls(), 3);
    runtime.stop().await;
}

#[tokio::test]
async fn refresh_cannot_revive_an_expired_decision_or_overwrite_a_watch_change() {
    for watch_change in [false, true] {
        let source = Arc::new(ScriptedDecisionSource::default());
        let watch = source.push_live_watch(Vec::new()).await;
        let runtime = start_runtime(Arc::clone(&source), &refresh_config()).await;
        let admission = admit_allowed(&runtime, SUBJECT_A).await;
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
        runtime.time.advance(Duration::from_millis(60)).await;
        runtime
            .gate
            .refresh(SUBJECT_A.parse().expect("subject UUID"), admission.clone())
            .await;
        source.wait_for_gets(2).await;
        let expected = if watch_change {
            watch
                .send(Ok(change(SUBJECT_A, Decision::Denied)))
                .expect("watch live");
            wait_for_metric(&runtime.metrics.watch_events, 1).await;
            AdmissionState::Denied
        } else {
            runtime.time.advance(Duration::from_millis(40)).await;
            AdmissionState::Stale
        };
        assert_eq!(admission.check(), (expected, false));
        release.add_permits(1);
        if watch_change {
            tokio::task::yield_now().await;
        } else {
            source.wait_for_get_completions(2).await;
        }
        assert_eq!(admission.check(), (expected, false));
        assert_eq!(source.get_calls(), 2);
        runtime.stop().await;
    }
}

#[tokio::test]
async fn cancelled_or_timed_out_enqueue_releases_the_claim_without_cooldown() {
    use crate::support::TestTimeDriver;
    use policy_gate::{PolicyGate, PolicyGateConfig};
    for timeout in [false, true] {
        let source = Arc::new(ScriptedDecisionSource::default());
        let _watch = source.push_live_watch(Vec::new()).await;
        let time = TestTimeDriver::new();
        let config = PolicyGateConfig::builder()
            .decision_freshness_ttl(Duration::from_millis(100))
            .refresh_before_expiry(Duration::from_millis(40))
            .refresh_queue_capacity(1)
            .refresh_enqueue_timeout(Duration::from_millis(10))
            .build()
            .expect("valid config");
        let (gate, mut watcher, _) =
            PolicyGate::new_with_time_driver(&config, Arc::clone(&source), time);
        assert!(futures_util::poll!(&mut watcher).is_pending());
        let first = SUBJECT_A.parse().expect("subject UUID");
        let second = SUBJECT_B.parse().expect("subject UUID");
        let first_admission = gate.admit(&first).await.expect("first admission");
        let second_admission = gate.admit(&second).await.expect("second admission");
        time.advance(Duration::from_millis(60)).await;
        // Keep the watcher unpolled so the first subject fills the sole queue slot.
        gate.refresh(first, first_admission).await;
        let mut enqueue = Box::pin(gate.refresh(second, second_admission.clone()));
        assert!(futures_util::poll!(&mut enqueue).is_pending());
        assert_eq!(second_admission.check(), (AdmissionState::Allowed, false));
        if timeout {
            time.advance(Duration::from_millis(10)).await;
            assert!(futures_util::poll!(&mut enqueue).is_ready());
        }
        drop(enqueue);
        assert_eq!(second_admission.check(), (AdmissionState::Allowed, true));
        assert_eq!(source.get_calls(), 2, "enqueue never calls the authority");
        assert!(futures_util::poll!(&mut watcher).is_pending());
        gate.refresh(second, second_admission.clone()).await;
        assert!(futures_util::poll!(&mut watcher).is_pending());
        assert_eq!(source.get_calls(), 4);
        assert_eq!(second_admission.check(), (AdmissionState::Allowed, false));
    }
}

#[tokio::test]
async fn delayed_refresh_claimant_observes_a_completed_generations_cooldown() {
    use core::cell::Cell;
    use core::sync::atomic::AtomicUsize;
    use std::sync::{Barrier, OnceLock};
    use std::time::Instant;

    use futures_util::FutureExt as _;
    use policy_gate::{
        DecisionSource, DecisionSourceError, DecisionSourceErrorKind, PolicyGate, PolicyGateConfig,
        TimeDriver,
    };

    std::thread_local! { static PAUSE_CLONE: Cell<bool> = const { Cell::new(false) }; }
    static ENTER: Barrier = Barrier::new(2);
    static RELEASE: Barrier = Barrier::new(2);
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    static MILLIS: AtomicUsize = AtomicUsize::new(0);

    #[derive(Eq, PartialEq, Hash)]
    struct Key;
    impl Clone for Key {
        fn clone(&self) -> Self {
            if PAUSE_CLONE.with(|pause| pause.replace(false)) {
                ENTER.wait();
                RELEASE.wait();
            }
            Self
        }
    }
    #[derive(Clone)]
    struct Clock;
    impl TimeDriver for Clock {
        fn now() -> Instant {
            *EPOCH.get_or_init(Instant::now)
                + Duration::from_millis(MILLIS.load(Ordering::SeqCst) as u64)
        }
        fn sleep_until(_: Instant) -> impl Future<Output = ()> + Send {
            core::future::pending()
        }
        fn yield_now() -> impl Future<Output = ()> + Send {
            core::future::ready(())
        }
    }
    struct Source(AtomicUsize);
    impl DecisionSource<Key> for Source {
        type Changes = futures_util::stream::Pending<
            Result<policy_gate::DecisionChange<Key>, DecisionSourceError>,
        >;
        fn watch_subject_decisions(
            &self,
        ) -> impl Future<Output = Result<Self::Changes, DecisionSourceError>> + Send {
            core::future::ready(Ok(futures_util::stream::pending()))
        }
        fn get_subject_decision(
            &self,
            _: &Key,
        ) -> impl Future<Output = Result<Option<Decision>, DecisionSourceError>> + Send {
            core::future::ready(if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(Some(Decision::Allowed))
            } else {
                Err(DecisionSourceError::new(
                    DecisionSourceErrorKind::Transient,
                    "refresh failed",
                ))
            })
        }
    }

    let config = PolicyGateConfig::builder()
        .decision_freshness_ttl(Duration::from_millis(100))
        .refresh_before_expiry(Duration::from_millis(40))
        .permanent_failure_cooldown(Duration::from_millis(20))
        .build()
        .expect("valid config");
    let source = Arc::new(Source(AtomicUsize::new(0)));
    let (gate, mut watcher, _) =
        PolicyGate::new_with_time_driver(&config, Arc::clone(&source), Clock);
    assert!(futures_util::poll!(&mut watcher).is_pending());
    let admission = gate.admit(&Key).await.expect("admission");
    MILLIS.store(60, Ordering::SeqCst);
    assert_eq!(admission.check(), (AdmissionState::Allowed, true));
    let contender_gate = gate.clone();
    let contender_admission = admission.clone();
    let contender = std::thread::spawn(move || {
        PAUSE_CLONE.with(|pause| pause.set(true));
        contender_gate
            .refresh(Key, contender_admission)
            .now_or_never()
            .expect("queue has room");
    });
    // Pause after the due pre-check but before the pending CAS, then complete another generation.
    ENTER.wait();
    gate.refresh(Key, admission.clone()).await;
    assert!(futures_util::poll!(&mut watcher).is_pending());
    RELEASE.wait();
    contender.join().expect("contender finishes");
    assert!(futures_util::poll!(&mut watcher).is_pending());
    assert_eq!(
        source.0.load(Ordering::SeqCst),
        2,
        "delayed claim must respect cooldown"
    );
    assert_eq!(admission.check(), (AdmissionState::Allowed, false));
    MILLIS.store(80, Ordering::SeqCst);
    assert_eq!(admission.check(), (AdmissionState::Allowed, true));
}

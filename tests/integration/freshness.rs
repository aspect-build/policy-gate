// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::future::Future as _;
use core::sync::atomic::Ordering;
use core::task::{Context, Poll};
use core::time::Duration;
use std::sync::Arc;

use policy_gate::{Admission, Decision, DecisionSourceError, DecisionSourceErrorKind, Permit};
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::support::{
    ConfigOptions, GetAction, RecordingWaker, SUBJECT_A, ScriptedDecisionSource, TestRuntime,
    change, runtime, start_runtime, wait_for_metric,
};

fn freshness_config() -> ConfigOptions {
    ConfigOptions {
        decision_freshness_ttl: Some(Duration::from_millis(100)),
        decision_refresh_ahead: Some(Duration::from_millis(20)),
        ..ConfigOptions::default()
    }
}

fn ttl_only_config() -> ConfigOptions {
    ConfigOptions {
        decision_freshness_ttl: Some(Duration::from_millis(100)),
        ..ConfigOptions::default()
    }
}

async fn admit_permit(runtime: &crate::support::RunningRuntime) -> Permit {
    let subject = SUBJECT_A.parse().expect("test subject UUID");
    match runtime
        .gate
        .admit(subject)
        .await
        .expect("admission succeeds")
    {
        Admission::Allowed(permit) => permit,
        Admission::Denied => panic!("subject must be allowed"),
    }
}

#[tokio::test]
async fn freshness_is_disabled_by_default() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;
    let permit = admit_permit(&runtime).await;

    runtime.time.advance(Duration::from_secs(60)).await;

    assert_eq!(source.get_calls(), 1);
    assert_eq!(permit.state(), policy_gate::PermitState::Allowed);
    runtime.stop().await;
}

#[tokio::test]
async fn disabled_freshness_does_not_wake_the_watcher_for_permit_lifecycle() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    let TestRuntime { gate, watcher, .. } = runtime(source, &ConfigOptions::default());
    let mut watcher = Box::pin(watcher);
    let wake_counter = Arc::new(RecordingWaker::default());
    let waker = wake_counter.waker();
    let mut context = Context::from_waker(&waker);
    assert!(matches!(watcher.as_mut().poll(&mut context), Poll::Pending));
    let wakes_before_admission = wake_counter.count();

    let subject = SUBJECT_A.parse().expect("test subject UUID");
    let permit = match gate.admit(subject).await.expect("admission succeeds") {
        Admission::Allowed(permit) => permit,
        Admission::Denied => panic!("subject must be allowed"),
    };
    drop(permit);

    assert_eq!(wake_counter.count(), wakes_before_admission);
}

#[tokio::test]
async fn ttl_only_permits_use_expiry_path_without_refresh_work() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    let TestRuntime {
        gate,
        watcher,
        time,
        ..
    } = runtime(Arc::clone(&source), &ttl_only_config());
    let mut watcher = Box::pin(watcher);
    let wake_counter = Arc::new(RecordingWaker::default());
    let waker = wake_counter.waker();
    let mut context = Context::from_waker(&waker);
    assert!(matches!(watcher.as_mut().poll(&mut context), Poll::Pending));

    let subject = SUBJECT_A.parse().expect("test subject UUID");
    let mut permit = match gate.admit(subject).await.expect("admission succeeds") {
        Admission::Allowed(permit) => permit,
        Admission::Denied => panic!("subject must be allowed"),
    };
    assert!(matches!(watcher.as_mut().poll(&mut context), Poll::Pending));
    let wakes_before_permit_lifecycle = wake_counter.count();

    let clone = permit.clone();
    drop(clone);
    assert_eq!(wake_counter.count(), wakes_before_permit_lifecycle);
    time.advance(Duration::from_millis(80)).await;
    assert_eq!(source.get_calls(), 1, "TTL-only mode does not refresh");
    assert_eq!(permit.state(), policy_gate::PermitState::Allowed);

    time.advance(Duration::from_millis(20)).await;
    assert!(matches!(watcher.as_mut().poll(&mut context), Poll::Pending));
    assert_eq!(permit.changed().await, policy_gate::PermitState::Stale);
    assert_eq!(source.get_calls(), 1);
}

#[tokio::test]
async fn ttl_only_watch_change_starts_a_new_absolute_window() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    let runtime = start_runtime(Arc::clone(&source), &ttl_only_config()).await;
    let mut permit = admit_permit(&runtime).await;

    runtime.time.advance(Duration::from_millis(70)).await;
    watch
        .send(Ok(change(SUBJECT_A, Decision::Allowed)))
        .expect("watch remains live");
    wait_for_metric(&runtime.metrics.watch_events, 1).await;

    runtime.time.advance(Duration::from_millis(99)).await;
    assert_eq!(permit.state(), policy_gate::PermitState::Allowed);
    runtime.time.advance(Duration::from_millis(1)).await;

    assert_eq!(permit.changed().await, policy_gate::PermitState::Stale);
    assert_eq!(source.get_calls(), 1);
    runtime.stop().await;
}

#[tokio::test]
async fn ordinary_access_does_not_extend_freshness_or_refresh_without_a_live_permit() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    for _ in 0..2 {
        source
            .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
            .await;
    }
    let runtime = start_runtime(Arc::clone(&source), &freshness_config()).await;
    drop(admit_permit(&runtime).await);

    runtime.time.advance(Duration::from_millis(70)).await;
    let subject = SUBJECT_A.parse().expect("test subject UUID");
    let cached = runtime
        .gate
        .try_cached(&subject)
        .expect("decision remains fresh");
    drop(cached);
    runtime.time.advance(Duration::from_millis(10)).await;
    assert_eq!(source.get_calls(), 1, "ordinary access does not refresh");

    runtime.time.advance(Duration::from_millis(20)).await;
    assert!(
        runtime.gate.try_cached(&subject).is_none(),
        "the absolute deadline is not extended by access"
    );
    drop(admit_permit(&runtime).await);
    assert_eq!(source.get_calls(), 2);
    runtime.stop().await;
}

#[tokio::test]
async fn live_permit_is_refreshed_ahead_of_expiry() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Denied)))
        .await;
    let runtime = start_runtime(Arc::clone(&source), &freshness_config()).await;
    let mut permit = admit_permit(&runtime).await;

    runtime.time.advance(Duration::from_millis(79)).await;
    assert_eq!(source.get_calls(), 1);
    runtime.time.advance(Duration::from_millis(1)).await;

    assert_eq!(permit.changed().await, policy_gate::PermitState::Denied);
    assert_eq!(source.get_calls(), 2);
    runtime.stop().await;
}

#[tokio::test]
async fn successful_refresh_starts_a_new_absolute_window() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    for _ in 0..3 {
        source
            .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
            .await;
    }
    let runtime = start_runtime(Arc::clone(&source), &freshness_config()).await;
    let permit = admit_permit(&runtime).await;

    runtime.time.advance(Duration::from_millis(80)).await;
    source.wait_for_get_completions(2).await;
    runtime.time.advance(Duration::from_millis(79)).await;
    assert_eq!(source.get_calls(), 2);
    runtime.time.advance(Duration::from_millis(1)).await;

    source.wait_for_gets(3).await;
    assert_eq!(permit.state(), policy_gate::PermitState::Allowed);
    runtime.stop().await;
}

#[tokio::test]
async fn permit_clone_keeps_refresh_live_until_the_last_handle_is_dropped() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    for _ in 0..2 {
        source
            .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
            .await;
    }
    let runtime = start_runtime(Arc::clone(&source), &freshness_config()).await;
    let original = admit_permit(&runtime).await;
    let clone = original.clone();
    drop(original);

    runtime.time.advance(Duration::from_millis(80)).await;
    source.wait_for_get_completions(2).await;
    drop(clone);
    runtime.time.advance(Duration::from_millis(80)).await;

    assert_eq!(
        source.get_calls(),
        2,
        "the last drop suppresses the next refresh"
    );
    runtime.stop().await;
}

#[tokio::test]
async fn idle_subject_ttl_still_evicts_before_freshness_refresh() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    let mut config = freshness_config();
    config.subject_ttl = Duration::from_millis(50);
    let runtime = start_runtime(Arc::clone(&source), &config).await;
    let mut permit = admit_permit(&runtime).await;

    runtime.time.advance(Duration::from_millis(80)).await;

    assert_eq!(permit.changed().await, policy_gate::PermitState::Stale);
    assert_eq!(source.get_calls(), 1, "an idle subject is not refreshed");
    runtime.stop().await;
}

#[tokio::test]
async fn failed_refresh_becomes_stale_at_the_absolute_deadline() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    source
        .push_get(
            SUBJECT_A,
            GetAction::Return(Err(DecisionSourceError::new(
                DecisionSourceErrorKind::Transient,
                "refresh failed",
            ))),
        )
        .await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    let runtime = start_runtime(Arc::clone(&source), &freshness_config()).await;
    let mut permit = admit_permit(&runtime).await;

    runtime.time.advance(Duration::from_millis(80)).await;
    wait_for_metric(&runtime.metrics.unary_failures, 1).await;
    assert_eq!(permit.state(), policy_gate::PermitState::Allowed);
    runtime.time.advance(Duration::from_millis(20)).await;

    assert_eq!(permit.changed().await, policy_gate::PermitState::Stale);
    drop(admit_permit(&runtime).await);
    assert_eq!(source.get_calls(), 3);
    runtime.stop().await;
}

#[tokio::test]
async fn refresh_still_in_flight_at_expiry_cannot_revive_a_stale_permit() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
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
    let runtime = start_runtime(Arc::clone(&source), &freshness_config()).await;
    let mut permit = admit_permit(&runtime).await;

    runtime.time.advance(Duration::from_millis(80)).await;
    source.wait_for_gets(2).await;
    runtime.time.advance(Duration::from_millis(20)).await;
    assert_eq!(permit.changed().await, policy_gate::PermitState::Stale);

    release.add_permits(1);
    source.wait_for_get_completions(2).await;
    tokio::task::yield_now().await;
    assert_eq!(permit.state(), policy_gate::PermitState::Stale);
    runtime.stop().await;
}

#[tokio::test]
async fn watch_change_supersedes_an_in_flight_refresh() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
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
    let runtime = start_runtime(Arc::clone(&source), &freshness_config()).await;
    let mut permit = admit_permit(&runtime).await;
    runtime.time.advance(Duration::from_millis(80)).await;
    source.wait_for_gets(2).await;

    watch
        .send(Ok(change(SUBJECT_A, Decision::Denied)))
        .expect("watch remains live");
    assert_eq!(permit.changed().await, policy_gate::PermitState::Denied);
    release.add_permits(1);
    source.wait_for_get_completions(2).await;
    tokio::task::yield_now().await;

    assert_eq!(permit.state(), policy_gate::PermitState::Denied);
    runtime.stop().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn ready_refresh_batch_yields_to_watch_and_applies_non_superseded_results() {
    const SUBJECTS: usize = 12;
    const WORK_PER_YIELD: usize = 3;
    const MAX_POLLS_TO_WATCH: usize = SUBJECTS / WORK_PER_YIELD + 1;
    let source = Arc::new(ScriptedDecisionSource::default());
    let watch = source.push_live_watch(Vec::new()).await;
    let release = Arc::new(Semaphore::new(0));
    let subjects: Vec<_> = (1..=SUBJECTS)
        .map(|value| Uuid::from_u128(value as u128))
        .collect();
    for subject in &subjects {
        let subject = subject.to_string();
        source
            .push_get(&subject, GetAction::Return(Ok(Decision::Allowed)))
            .await;
        source
            .push_get(
                &subject,
                GetAction::Gate {
                    release: Arc::clone(&release),
                    result: Ok(Decision::Denied),
                },
            )
            .await;
    }
    let mut config = freshness_config();
    config.watch_events_per_yield = WORK_PER_YIELD;
    let TestRuntime {
        gate,
        watcher,
        metrics,
        time,
        ..
    } = runtime(Arc::clone(&source), &config);
    let mut watcher = Box::pin(watcher);
    let wake_counter = Arc::new(RecordingWaker::default());
    let waker = wake_counter.waker();
    let mut context = Context::from_waker(&waker);
    assert!(matches!(watcher.as_mut().poll(&mut context), Poll::Pending));

    let mut permits = Vec::new();
    for subject in &subjects {
        match gate.admit(*subject).await.expect("admission succeeds") {
            Admission::Allowed(permit) => permits.push(permit),
            Admission::Denied => panic!("subject must be allowed"),
        }
    }

    time.advance(Duration::from_millis(80)).await;
    assert!(matches!(watcher.as_mut().poll(&mut context), Poll::Pending));
    assert_eq!(source.get_calls(), SUBJECTS * 2);
    assert_eq!(source.get_completions(), SUBJECTS);

    // No await or watcher poll separates these operations, so every refresh and the watch item
    // are ready together when the manual harness next polls the watcher.
    release.add_permits(SUBJECTS);
    watch
        .send(Ok(policy_gate::DecisionChange {
            subject: subjects[0],
            decision: Decision::Denied,
        }))
        .expect("watch remains live");

    let mut processed = 0;
    let mut polls_to_watch = None;
    for poll in 1..=MAX_POLLS_TO_WATCH {
        assert!(matches!(watcher.as_mut().poll(&mut context), Poll::Pending));
        let watch_event_seen = metrics.watch_events.load(Ordering::Acquire) == 1;
        let now_processed = source.get_completions() - SUBJECTS + usize::from(watch_event_seen);
        assert!(
            now_processed - processed <= WORK_PER_YIELD,
            "each manual poll stops at the configured watcher yield boundary"
        );
        processed = now_processed;
        if watch_event_seen {
            polls_to_watch = Some(poll);
            break;
        }
    }
    assert!(
        polls_to_watch.is_some(),
        "the ready watch item is serviced within the bounded yield budget"
    );
    assert_eq!(permits[0].state(), policy_gate::PermitState::Denied);

    for _ in 0..=MAX_POLLS_TO_WATCH {
        if permits[1..]
            .iter()
            .all(|permit| permit.state() == policy_gate::PermitState::Denied)
        {
            break;
        }
        assert!(matches!(watcher.as_mut().poll(&mut context), Poll::Pending));
        let watch_event_seen = metrics.watch_events.load(Ordering::Acquire) == 1;
        let now_processed = source.get_completions() - SUBJECTS + usize::from(watch_event_seen);
        assert!(
            now_processed - processed <= WORK_PER_YIELD,
            "refresh application remains bounded after the watch item"
        );
        processed = now_processed;
    }
    for permit in &permits[1..] {
        assert_eq!(
            permit.state(),
            policy_gate::PermitState::Denied,
            "every non-superseded refresh result is applied"
        );
    }
    assert_eq!(permits[0].state(), policy_gate::PermitState::Denied);
}

#[tokio::test]
async fn watch_change_resets_the_freshness_deadline() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Denied)))
        .await;
    let runtime = start_runtime(Arc::clone(&source), &freshness_config()).await;
    let mut permit = admit_permit(&runtime).await;

    runtime.time.advance(Duration::from_millis(70)).await;
    watch
        .send(Ok(change(SUBJECT_A, Decision::Allowed)))
        .expect("watch remains live");
    wait_for_metric(&runtime.metrics.watch_events, 1).await;

    runtime.time.advance(Duration::from_millis(79)).await;
    assert_eq!(source.get_calls(), 1, "the old refresh deadline was reset");
    runtime.time.advance(Duration::from_millis(1)).await;
    assert_eq!(permit.changed().await, policy_gate::PermitState::Denied);
    assert_eq!(source.get_calls(), 2);
    assert_eq!(runtime.metrics.unary_calls.load(Ordering::Relaxed), 2);
    runtime.stop().await;
}

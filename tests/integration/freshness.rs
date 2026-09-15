// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::time::Duration;
use std::sync::Arc;

use policy_gate::{Admission, Decision, Permit};

use crate::support::{
    ConfigOptions, GetAction, SUBJECT_A, SUBJECT_B, ScriptedDecisionSource, change, start_runtime,
    wait_for_metric,
};

fn freshness_config() -> ConfigOptions {
    ConfigOptions {
        decision_freshness_ttl: Some(Duration::from_millis(100)),
        ..ConfigOptions::default()
    }
}

async fn admit_permit(runtime: &crate::support::RunningRuntime, subject: &str) -> Permit {
    let subject = subject.parse().expect("test subject UUID");
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
    let permit = admit_permit(&runtime, SUBJECT_A).await;

    runtime.time.advance(Duration::from_secs(60)).await;

    assert_eq!(source.get_calls(), 1);
    assert_eq!(permit.state(), policy_gate::PermitState::Allowed);
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
    drop(admit_permit(&runtime, SUBJECT_A).await);

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

    assert!(
        runtime.gate.try_cached(&subject).is_none(),
        "ordinary access does not extend absolute freshness"
    );
    drop(admit_permit(&runtime, SUBJECT_A).await);
    assert_eq!(source.get_calls(), 2);
    runtime.stop().await;
}

#[tokio::test]
async fn live_permit_becomes_stale_at_the_absolute_deadline() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    let runtime = start_runtime(Arc::clone(&source), &freshness_config()).await;
    let mut permit = admit_permit(&runtime, SUBJECT_A).await;

    runtime.time.advance(Duration::from_millis(99)).await;
    assert_eq!(permit.state(), policy_gate::PermitState::Allowed);
    runtime.time.advance(Duration::from_millis(1)).await;

    assert_eq!(permit.changed().await, policy_gate::PermitState::Stale);
    assert_eq!(
        source.get_calls(),
        1,
        "expiry does not fetch a new decision"
    );
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
    assert!(matches!(
        runtime.gate.admit(subject).await,
        Ok(Admission::Denied)
    ));

    runtime.time.advance(Duration::from_millis(100)).await;

    assert!(runtime.gate.try_cached(&subject).is_none());
    drop(admit_permit(&runtime, SUBJECT_A).await);
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
    let mut permit = admit_permit(&runtime, SUBJECT_A).await;

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
    let mut first_permit = admit_permit(&runtime, SUBJECT_A).await;

    runtime.time.advance(Duration::from_millis(40)).await;
    let first = SUBJECT_A.parse().expect("test subject UUID");
    drop(
        runtime
            .gate
            .try_cached(&first)
            .expect("access renews idle age"),
    );
    runtime.time.advance(Duration::from_millis(40)).await;
    drop(admit_permit(&runtime, SUBJECT_B).await);
    assert_eq!(first_permit.state(), policy_gate::PermitState::Allowed);

    runtime.time.advance(Duration::from_millis(11)).await;
    let second = SUBJECT_B.parse().expect("test subject UUID");
    drop(
        runtime
            .gate
            .try_cached(&second)
            .expect("second subject is cached"),
    );

    assert_eq!(
        first_permit.changed().await,
        policy_gate::PermitState::Stale,
        "sliding idle TTL expires the first subject before absolute freshness"
    );
    assert_eq!(source.get_calls(), 2);
    runtime.stop().await;
}

// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::sync::atomic::Ordering;
use core::time::Duration;
use std::sync::Arc;

use policy_gate::Decision;

use crate::support::{
    ConfigOptions, GetAction, SUBJECT_A, SUBJECT_B, SUBJECT_C, ScriptedDecisionSource,
    assert_allowed, assert_rejected, call_subject, change, start_runtime, wait_for_metric,
};
use tonic::Code;

fn policy(max_count: usize, subject_ttl: Duration) -> ConfigOptions {
    ConfigOptions {
        max_subjects: if max_count == 0 { 65_536 } else { max_count },
        subject_ttl: if subject_ttl.is_zero() {
            Duration::from_secs(3_600)
        } else {
            subject_ttl
        },
        snapshot_republish_interval: Duration::from_millis(10),
        ..ConfigOptions::default()
    }
}

#[tokio::test]
async fn idle_subject_is_evicted_and_readmitted() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    for subject in [SUBJECT_A, SUBJECT_B, SUBJECT_A] {
        source
            .push_get(subject, GetAction::Return(Ok(Decision::Allowed)))
            .await;
    }
    let runtime = start_runtime(Arc::clone(&source), &policy(0, Duration::from_millis(10))).await;
    let initial_republishes = runtime.metrics.snapshot_republishes.load(Ordering::Relaxed);

    assert_allowed(&call_subject(&runtime.layer, SUBJECT_A).await);
    assert_eq!(
        runtime.metrics.snapshot_republishes.load(Ordering::Relaxed),
        initial_republishes + 1,
    );
    let misses_before = runtime.metrics.snapshot_misses.load(Ordering::Relaxed);

    runtime.time.advance(Duration::from_millis(20)).await;
    assert_allowed(&call_subject(&runtime.layer, SUBJECT_B).await);
    assert_eq!(
        runtime.metrics.snapshot_republishes.load(Ordering::Relaxed),
        initial_republishes + 2,
    );
    assert_allowed(&call_subject(&runtime.layer, SUBJECT_A).await);

    assert_eq!(source.get_calls(), 3);
    assert_eq!(
        runtime.metrics.snapshot_misses.load(Ordering::Relaxed),
        misses_before + 2
    );
    runtime.stop().await;
}

#[tokio::test]
async fn cached_activity_keeps_watch_denials_authoritative_past_ttl() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    let runtime = start_runtime(Arc::clone(&source), &policy(0, Duration::from_millis(50))).await;

    assert_allowed(&call_subject(&runtime.layer, SUBJECT_A).await);
    for _ in 0..2 {
        runtime.time.advance(Duration::from_millis(40)).await;
        assert_allowed(&call_subject(&runtime.layer, SUBJECT_A).await);
    }
    assert_eq!(source.get_calls(), 1);

    watch
        .send(Ok(change(SUBJECT_A, Decision::Denied)))
        .expect("watch remains live");
    wait_for_metric(&runtime.metrics.watch_events, 1).await;
    assert_rejected(
        &call_subject(&runtime.layer, SUBJECT_A).await,
        Code::FailedPrecondition,
    );
    assert_eq!(source.get_calls(), 1);
    runtime.stop().await;
}

#[tokio::test]
async fn max_count_evicts_the_least_recently_used_subject() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    for subject in [SUBJECT_C, SUBJECT_A, SUBJECT_B, SUBJECT_C, SUBJECT_B] {
        source
            .push_get(subject, GetAction::Return(Ok(Decision::Allowed)))
            .await;
    }
    let runtime = start_runtime(Arc::clone(&source), &policy(2, Duration::ZERO)).await;

    // Prime the immediate snapshot publish so the following subjects exercise the truth-map LRU.
    assert_allowed(&call_subject(&runtime.layer, SUBJECT_C).await);
    assert_allowed(&call_subject(&runtime.layer, SUBJECT_A).await);
    assert_allowed(&call_subject(&runtime.layer, SUBJECT_B).await);
    assert_allowed(&call_subject(&runtime.layer, SUBJECT_A).await);
    runtime.time.advance(Duration::from_millis(10)).await;
    assert_allowed(&call_subject(&runtime.layer, SUBJECT_C).await);
    assert_eq!(source.get_calls(), 4);

    assert_allowed(&call_subject(&runtime.layer, SUBJECT_A).await);
    assert_eq!(
        source.get_calls(),
        4,
        "the recently used subject stays live"
    );
    assert_allowed(&call_subject(&runtime.layer, SUBJECT_B).await);
    assert_eq!(source.get_calls(), 5, "the LRU subject is fetched again");
    runtime.stop().await;
}

#[tokio::test]
async fn snapshot_hits_update_capacity_recency() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    let runtime = start_runtime(
        Arc::clone(&source),
        &ConfigOptions {
            max_subjects: 2,
            snapshot_republish_interval: Duration::ZERO,
            ..ConfigOptions::default()
        },
    )
    .await;

    assert_allowed(&call_subject(&runtime.layer, SUBJECT_A).await);
    assert_allowed(&call_subject(&runtime.layer, SUBJECT_B).await);
    assert_allowed(&call_subject(&runtime.layer, SUBJECT_A).await);
    assert_allowed(&call_subject(&runtime.layer, SUBJECT_C).await);
    assert_allowed(&call_subject(&runtime.layer, SUBJECT_A).await);
    assert_eq!(
        source.get_calls(),
        3,
        "the recently used subject stays cached"
    );
    assert_allowed(&call_subject(&runtime.layer, SUBJECT_B).await);
    assert_eq!(source.get_calls(), 4, "the idle subject is fetched again");
    runtime.stop().await;
}

#[tokio::test]
async fn snapshot_hits_keep_ttl_order_consistent() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    let runtime = start_runtime(
        Arc::clone(&source),
        &ConfigOptions {
            subject_ttl: Duration::from_millis(50),
            snapshot_republish_interval: Duration::ZERO,
            ..ConfigOptions::default()
        },
    )
    .await;

    assert_allowed(&call_subject(&runtime.layer, SUBJECT_A).await);
    assert_allowed(&call_subject(&runtime.layer, SUBJECT_B).await);
    for duration in [Duration::from_millis(40), Duration::from_millis(20)] {
        runtime.time.advance(duration).await;
        assert_allowed(&call_subject(&runtime.layer, SUBJECT_A).await);
    }
    assert_allowed(&call_subject(&runtime.layer, SUBJECT_C).await);
    assert_allowed(&call_subject(&runtime.layer, SUBJECT_B).await);
    assert_eq!(
        source.get_calls(),
        4,
        "the expired subject is fetched again"
    );
    runtime.stop().await;
}

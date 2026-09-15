// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::sync::atomic::Ordering;
use core::time::Duration;
use std::sync::Arc;

use tonic::Code;

use crate::support::{
    ConfigOptions, SUBJECT_A, SUBJECT_B, ScriptedDecisionSource, assert_allowed, assert_rejected,
    call_subject, start_runtime, wait_for_metric, wait_for_watch_connected,
};

#[tokio::test(start_paused = true)]
async fn new_subject_is_served_correctly_before_the_republish_interval() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    let runtime = start_runtime(
        Arc::clone(&source),
        &ConfigOptions {
            snapshot_republish_interval: Duration::from_millis(100),
            ..ConfigOptions::default()
        },
    )
    .await;
    let initial_republishes = runtime.metrics.snapshot_republishes.load(Ordering::Relaxed);

    assert_allowed(&call_subject(&runtime.layer, SUBJECT_A).await);
    assert_allowed(&call_subject(&runtime.layer, SUBJECT_B).await);
    assert_eq!(runtime.metrics.snapshot_misses.load(Ordering::Relaxed), 2);
    assert_eq!(source.get_calls(), 2);
    assert_eq!(
        runtime.metrics.snapshot_republishes.load(Ordering::Relaxed),
        initial_republishes + 1
    );

    tokio::time::advance(Duration::from_millis(110)).await;
    assert_allowed(&call_subject(&runtime.layer, SUBJECT_B).await);
    assert_eq!(
        runtime.metrics.snapshot_republishes.load(Ordering::Relaxed),
        initial_republishes + 2
    );
    assert_allowed(&call_subject(&runtime.layer, SUBJECT_B).await);
    assert_eq!(source.get_calls(), 2);
    runtime.stop().await;
}

#[tokio::test(start_paused = true)]
async fn disconnect_empties_the_snapshot() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let watch = source.push_live_watch(Vec::new()).await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;

    assert_allowed(&call_subject(&runtime.layer, SUBJECT_A).await);
    let republishes = runtime.metrics.snapshot_republishes.load(Ordering::Relaxed);
    drop(watch);
    wait_for_watch_connected(&runtime.metrics, false).await;

    let misses = runtime.metrics.snapshot_misses.load(Ordering::Relaxed);
    let call = tokio::spawn({
        let layer = runtime.layer.clone();
        async move { call_subject(&layer, SUBJECT_A).await }
    });
    wait_for_metric(&runtime.metrics.snapshot_misses, misses + 1).await;

    tokio::time::advance(Duration::from_millis(10)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        runtime.metrics.snapshot_republishes.load(Ordering::Relaxed),
        republishes
    );
    runtime.stop().await;
    assert_rejected(&call.await.expect("call joins"), Code::Unavailable);
}

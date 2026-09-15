// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::sync::atomic::Ordering;
use core::time::Duration;
use std::sync::Arc;

use crate::support::{
    ConfigOptions, SUBJECT_A, SUBJECT_B, ScriptedDecisionSource, assert_allowed, call_subject,
    start_runtime,
};

#[tokio::test]
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

    runtime.time.advance(Duration::from_millis(110)).await;
    assert_allowed(&call_subject(&runtime.layer, SUBJECT_B).await);
    assert_eq!(
        runtime.metrics.snapshot_republishes.load(Ordering::Relaxed),
        initial_republishes + 2
    );
    assert_allowed(&call_subject(&runtime.layer, SUBJECT_B).await);
    assert_eq!(source.get_calls(), 2);
    runtime.stop().await;
}

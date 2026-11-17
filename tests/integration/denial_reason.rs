// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::convert::Infallible;
use core::sync::atomic::Ordering;
use std::sync::Arc;

use bytes::Bytes;
use http_body::Frame;
use http_body_util::BodyExt;
use policy_gate::{Decision, DecisionChange};
use tonic::{Code, Status};
use uuid::Uuid;

use crate::support::{
    ConfigOptions, DENIAL_REASON, DENIAL_REASON_MESSAGE, GetAction, ObservedCall, SUBJECT_A,
    SUBJECT_B, ScriptedDecisionSource, call_subject, change, denied_for, layer_config,
    start_runtime, start_streaming_call, wait_for_metric,
};

fn rejection_message(call: &ObservedCall) -> String {
    assert_eq!(call.inner_calls, 0);
    let status = call.status.as_ref().expect("gRPC status");
    assert_eq!(status.code(), Code::FailedPrecondition);
    status.message().to_owned()
}

fn default_message() -> String {
    layer_config().denied_message().to_owned()
}

#[tokio::test]
async fn admission_denial_renders_the_message_mapped_to_its_reason() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::DeniedFor(DENIAL_REASON))
        .await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;

    let looked_up = call_subject(&runtime.layer, SUBJECT_A).await;
    let cached = call_subject(&runtime.layer, SUBJECT_A).await;

    assert_eq!(rejection_message(&looked_up), DENIAL_REASON_MESSAGE);
    assert_eq!(rejection_message(&cached), DENIAL_REASON_MESSAGE);
    assert_eq!(source.get_calls(), 1);
    runtime.stop().await;
}

#[tokio::test]
async fn unmapped_or_missing_reason_falls_back_to_the_default_message() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::DeniedFor("unmapped-reason"))
        .await;
    source
        .push_get(SUBJECT_B, GetAction::Return(Ok(Decision::Denied)))
        .await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;

    let unmapped = call_subject(&runtime.layer, SUBJECT_A).await;
    let missing = call_subject(&runtime.layer, SUBJECT_B).await;

    assert_eq!(rejection_message(&unmapped), default_message());
    assert_eq!(rejection_message(&missing), default_message());
    runtime.stop().await;
}

#[tokio::test]
async fn watch_change_replaces_the_cached_reason_while_the_subject_stays_denied() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Denied)))
        .await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;
    let before = call_subject(&runtime.layer, SUBJECT_A).await;

    watch
        .send(Ok(denied_for(SUBJECT_A, DENIAL_REASON)))
        .expect("watch remains live");
    wait_for_metric(&runtime.metrics.watch_events, 1).await;
    let with_reason = call_subject(&runtime.layer, SUBJECT_A).await;

    watch
        .send(Ok(change(SUBJECT_A, Decision::Denied)))
        .expect("watch remains live");
    wait_for_metric(&runtime.metrics.watch_events, 2).await;
    let without_reason = call_subject(&runtime.layer, SUBJECT_A).await;

    assert_eq!(rejection_message(&before), default_message());
    assert_eq!(rejection_message(&with_reason), DENIAL_REASON_MESSAGE);
    assert_eq!(rejection_message(&without_reason), default_message());
    assert_eq!(source.get_calls(), 1);
    runtime.stop().await;
}

#[tokio::test]
async fn reason_is_ignored_on_an_allowed_decision() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let watch = source.push_live_watch(Vec::new()).await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;
    let subject: Uuid = SUBJECT_A.parse().expect("test subject must be a UUID");
    let admission = runtime.gate.admit(&subject).await.expect("admitted");

    watch
        .send(Ok(DecisionChange {
            denial_reason: Some(Arc::from(DENIAL_REASON)),
            ..change(SUBJECT_A, Decision::Allowed)
        }))
        .expect("watch remains live");
    wait_for_metric(&runtime.metrics.watch_events, 1).await;
    assert!(admission.is_allowed());
    assert!(admission.denial_reason().is_none());

    watch
        .send(Ok(change(SUBJECT_A, Decision::Denied)))
        .expect("watch remains live");
    wait_for_metric(&runtime.metrics.watch_events, 2).await;
    assert!(admission.denial_reason().is_none());
    runtime.stop().await;
}

#[tokio::test]
async fn stream_cutoff_renders_the_message_mapped_to_its_reason() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let watch = source.push_live_watch(Vec::new()).await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;
    let mut call = start_streaming_call(&runtime.layer, SUBJECT_A).await;

    send_data(&call.response_sender, b"one");
    assert_eq!(next_data(&mut call.response_body).await, "one");
    watch
        .send(Ok(denied_for(SUBJECT_A, DENIAL_REASON)))
        .expect("watch remains live");
    wait_for_metric(&runtime.metrics.watch_events, 1).await;
    send_data(&call.response_sender, b"not-delivered");

    let frame = call
        .response_body
        .frame()
        .await
        .expect("body emits trailers")
        .expect("trailer frame succeeds");
    let status = Status::from_header_map(frame.trailers_ref().expect("trailers frame"))
        .expect("gRPC status trailers");
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(status.message(), DENIAL_REASON_MESSAGE);
    assert_eq!(runtime.metrics.stream_cutoffs.load(Ordering::Relaxed), 1);
    runtime.stop().await;
}

fn send_data(
    sender: &tokio::sync::mpsc::UnboundedSender<Result<Frame<Bytes>, Infallible>>,
    data: &'static [u8],
) {
    sender
        .send(Ok(Frame::data(Bytes::from_static(data))))
        .expect("stream remains open");
}

async fn next_data(body: &mut axum_core::body::Body) -> Bytes {
    body.frame()
        .await
        .expect("body remains open")
        .expect("body frame succeeds")
        .into_data()
        .expect("data frame")
}

// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::convert::Infallible;
use core::pin::Pin;
use core::sync::atomic::Ordering;
use core::task::{Context, Poll};
use core::time::Duration;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::stream;
use http::header::{CONTENT_LENGTH, HeaderValue};
use http::{HeaderMap, Request, Response};
use http_body::{Body as _, Frame};
use http_body_util::{BodyExt, Full, StreamBody};
use policy_gate::{Decision, DecisionSourceError, DecisionSourceErrorKind};
use tonic::{Code, Status};
use tower::{Layer, ServiceExt, service_fn};

use crate::support::{
    ConfigOptions, GetAction, PAYMENT_URL, RecordingWaker, RunningRuntime, SUBJECT_A,
    ScriptedDecisionSource, TestSubject, change, start_runtime, start_streaming_call,
    start_streaming_call_at_path, wait_for_metric, wait_for_watch_connected,
};

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

async fn next_status(body: &mut axum_core::body::Body) -> Status {
    let frame = body
        .frame()
        .await
        .expect("body emits trailers")
        .expect("trailer frame succeeds");
    Status::from_header_map(frame.trailers_ref().expect("trailers frame"))
        .expect("gRPC status trailers")
}

async fn full_response(runtime: &RunningRuntime) -> Response<axum_core::body::Body> {
    let inner = service_fn(|_request| async {
        let mut response = Response::new(Full::new(Bytes::from_static(b"ok")));
        response
            .headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from_static("2"));
        Ok::<_, Infallible>(response)
    });
    let mut request = Request::new(axum_core::body::Body::empty());
    request.extensions_mut().insert(TestSubject(
        SUBJECT_A.parse().expect("test subject must be a UUID"),
    ));
    runtime
        .layer
        .layer(inner)
        .oneshot(request)
        .await
        .expect("infallible service")
}

#[tokio::test]
async fn wrapped_response_removes_exact_length_metadata() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    let runtime = start_runtime(source, &ConfigOptions::default()).await;
    let response = full_response(&runtime).await;

    assert!(!response.headers().contains_key(CONTENT_LENGTH));
    let body = response.into_body();
    assert!(!body.is_end_stream());
    assert_eq!(body.size_hint().lower(), 0);
    assert_eq!(body.size_hint().exact(), None);
    runtime.stop().await;
}

#[tokio::test]
async fn wrapped_response_latches_eof() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let watch = source.push_live_watch(Vec::new()).await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;
    let mut body = full_response(&runtime).await.into_body();

    assert_eq!(next_data(&mut body).await, "ok");
    assert!(body.frame().await.is_none());
    assert!(body.is_end_stream());

    watch
        .send(Ok(change(SUBJECT_A, Decision::Denied)))
        .expect("watch remains live");
    wait_for_metric(&runtime.metrics.watch_events, 1).await;
    assert!(body.frame().await.is_none(), "EOF remains terminal");
    assert_eq!(runtime.metrics.stream_cutoffs.load(Ordering::Relaxed), 0);
    runtime.stop().await;
}

#[tokio::test]
async fn wrapped_response_latches_terminal_trailers() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let _watch = source.push_live_watch(Vec::new()).await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;
    let inner = service_fn(|_request| async {
        let frames = vec![
            Ok::<_, Infallible>(Frame::trailers(HeaderMap::new())),
            Ok(Frame::data(Bytes::from_static(b"after-trailers"))),
        ];
        Ok::<_, Infallible>(Response::new(StreamBody::new(stream::iter(frames))))
    });
    let mut request = Request::new(axum_core::body::Body::empty());
    request.extensions_mut().insert(TestSubject(
        SUBJECT_A.parse().expect("test subject must be a UUID"),
    ));
    let mut body = runtime
        .layer
        .layer(inner)
        .oneshot(request)
        .await
        .expect("infallible service")
        .into_body();
    let trailers = body
        .frame()
        .await
        .expect("terminal trailers")
        .expect("trailers succeed");
    assert!(trailers.is_trailers());
    assert!(body.is_end_stream());
    assert!(body.frame().await.is_none(), "nothing follows trailers");
    runtime.stop().await;
}

#[tokio::test]
async fn read_is_cut_after_denial_with_trailers_and_metering_stops_at_the_cut() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;
    let mut call = start_streaming_call(&runtime.layer, SUBJECT_A).await;

    send_data(&call.response_sender, b"one");
    assert_eq!(next_data(&mut call.response_body).await, "one");
    send_data(&call.response_sender, b"two");
    assert_eq!(next_data(&mut call.response_body).await, "two");
    watch
        .send(Ok(change(SUBJECT_A, Decision::Denied)))
        .expect("watch remains live");
    wait_for_metric(&runtime.metrics.watch_events, 1).await;
    send_data(&call.response_sender, b"not-delivered");

    let status = next_status(&mut call.response_body).await;
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(
        status.message(),
        format!(
            "Your organization has reached its cache usage limit. Visit {PAYMENT_URL} to review usage and restore access."
        )
    );
    assert!(call.response_body.frame().await.is_none());
    assert_eq!(call.response_probe.bytes.load(Ordering::Relaxed), 6);
    assert_eq!(runtime.metrics.stream_cutoffs.load(Ordering::Relaxed), 1);
    drop(call.response_body);
    assert!(call.response_probe.dropped.load(Ordering::Acquire));
    runtime.stop().await;
}

#[tokio::test]
async fn authority_changes_leave_idle_bodies_asleep_and_enforce_on_next_poll() {
    for event in [
        change(SUBJECT_A, Decision::Denied),
        crate::support::withdrawal(SUBJECT_A),
    ] {
        let source = Arc::new(ScriptedDecisionSource::default());
        let watch = source.push_live_watch(Vec::new()).await;
        source
            .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
            .await;
        source
            .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Denied)))
            .await;
        let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;
        let mut call = start_streaming_call(&runtime.layer, SUBJECT_A).await;
        let wake_counter = Arc::new(RecordingWaker::default());
        let waker = wake_counter.waker();
        let mut context = Context::from_waker(&waker);
        assert!(
            Pin::new(&mut call.request_body)
                .poll_frame(&mut context)
                .is_pending()
        );
        assert!(
            Pin::new(&mut call.response_body)
                .poll_frame(&mut context)
                .is_pending()
        );
        let wakes_before_change = wake_counter.count();
        watch.send(Ok(event)).expect("live watch");
        wait_for_metric(&runtime.metrics.watch_events, 1).await;
        assert_eq!(
            wake_counter.count(),
            wakes_before_change,
            "authority must not wake idle bodies"
        );
        assert_eq!(
            source.get_calls(),
            1,
            "stale recovery starts on the next poll"
        );

        send_data(&call.request_sender, b"blocked");
        send_data(&call.response_sender, b"blocked");
        assert!(
            wake_counter.count() > wakes_before_change,
            "traffic wakes the bodies"
        );
        assert!(matches!(
            Pin::new(&mut call.request_body).poll_frame(&mut context),
            Poll::Ready(Some(Err(_)))
        ));
        let Poll::Ready(Some(Ok(frame))) =
            Pin::new(&mut call.response_body).poll_frame(&mut context)
        else {
            panic!("body must emit denial trailers on its next poll");
        };
        let status =
            Status::from_header_map(frame.trailers_ref().expect("trailers")).expect("status");
        assert_eq!(status.code(), Code::FailedPrecondition);
        assert_eq!(call.request_probe.bytes.load(Ordering::Relaxed), 0);
        assert_eq!(call.response_probe.bytes.load(Ordering::Relaxed), 0);
        runtime.stop().await;
    }
}

#[tokio::test]
async fn client_streaming_request_is_reset_after_denial() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let watch = source.push_live_watch(Vec::new()).await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;
    let mut call = start_streaming_call(&runtime.layer, SUBJECT_A).await;

    send_data(&call.request_sender, b"one");
    assert_eq!(next_data(&mut call.request_body).await, "one");
    watch
        .send(Ok(change(SUBJECT_A, Decision::Denied)))
        .expect("watch remains live");
    wait_for_metric(&runtime.metrics.watch_events, 1).await;
    send_data(&call.request_sender, b"not-delivered");

    let error = call
        .request_body
        .frame()
        .await
        .expect("body emits reset")
        .expect_err("request stream is reset");
    let status = core::error::Error::source(&error)
        .and_then(|source| source.downcast_ref::<Status>())
        .expect("tonic status error");
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(
        status.message(),
        format!(
            "Your organization has reached its cache usage limit. Visit {PAYMENT_URL} to review usage and restore access."
        )
    );
    assert!(call.request_body.frame().await.is_none());
    assert_eq!(call.request_probe.bytes.load(Ordering::Relaxed), 3);
    assert_eq!(runtime.metrics.stream_cutoffs.load(Ordering::Relaxed), 1);
    runtime.stop().await;
}

#[tokio::test]
async fn unary_request_body_is_not_wrapped_for_mid_stream_cutoff() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let watch = source.push_live_watch(Vec::new()).await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;
    let mut call = start_streaming_call_at_path(
        &runtime.layer,
        SUBJECT_A,
        "/google.bytestream.ByteStream/QueryWriteStatus",
    )
    .await;

    watch
        .send(Ok(change(SUBJECT_A, Decision::Denied)))
        .expect("watch remains live");
    wait_for_metric(&runtime.metrics.watch_events, 1).await;
    send_data(&call.request_sender, b"still-forwarded");
    assert_eq!(next_data(&mut call.request_body).await, "still-forwarded");
    assert_eq!(runtime.metrics.stream_cutoffs.load(Ordering::Relaxed), 0);
    runtime.stop().await;
}

#[tokio::test]
async fn reconnect_keeps_stream_open_and_later_denial_of_refetched_entry_cuts_it() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let first_watch = source.push_live_watch(Vec::new()).await;
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
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
    let mut call = start_streaming_call(&runtime.layer, SUBJECT_A).await;
    send_data(&call.response_sender, b"before");
    assert_eq!(next_data(&mut call.response_body).await, "before");

    let second_watch = source.push_live_watch(Vec::new()).await;
    drop(first_watch);
    wait_for_watch_connected(&runtime.metrics, false).await;
    runtime.time.advance(Duration::from_millis(125)).await;
    source.wait_for_watches(2).await;
    wait_for_watch_connected(&runtime.metrics, true).await;

    send_data(&call.response_sender, b"after");
    assert_eq!(next_data(&mut call.response_body).await, "after");
    source.wait_for_gets(2).await;
    release.add_permits(1);
    send_data(&call.response_sender, b"adopted");
    assert_eq!(next_data(&mut call.response_body).await, "adopted");
    second_watch
        .send(Ok(change(SUBJECT_A, Decision::Denied)))
        .expect("watch remains live");
    wait_for_metric(&runtime.metrics.watch_events, 1).await;
    let status = next_status(&mut call.response_body).await;
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(runtime.metrics.stream_cutoffs.load(Ordering::Relaxed), 1);
    assert_eq!(source.get_calls(), 2);
    runtime.stop().await;
}

#[tokio::test]
async fn permanent_readmission_failure_flows_during_the_cooldown() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let first_watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    for _ in 0..2 {
        source
            .push_get(
                SUBJECT_A,
                GetAction::Return(Err(DecisionSourceError::new(
                    DecisionSourceErrorKind::Permanent,
                    "subject is not enrolled",
                ))),
            )
            .await;
    }
    let runtime = start_runtime(
        Arc::clone(&source),
        &ConfigOptions {
            unary_timeout: Duration::from_millis(1),
            admission_timeout: Duration::from_millis(50),
            permanent_failure_cooldown: Duration::ZERO,
            ..ConfigOptions::default()
        },
    )
    .await;
    let mut call = start_streaming_call(&runtime.layer, SUBJECT_A).await;

    let _second_watch = source.push_live_watch(Vec::new()).await;
    drop(first_watch);
    wait_for_watch_connected(&runtime.metrics, false).await;
    runtime.time.advance(Duration::from_millis(125)).await;
    source.wait_for_watches(2).await;
    wait_for_watch_connected(&runtime.metrics, true).await;

    for data in [b"one".as_slice(), b"two", b"three"] {
        send_data(&call.response_sender, data);
        assert_eq!(next_data(&mut call.response_body).await, data);
    }
    assert_eq!(source.get_calls(), 2);

    runtime.time.advance(Duration::from_millis(10)).await;
    send_data(&call.response_sender, b"still-cooling");
    assert_eq!(next_data(&mut call.response_body).await, "still-cooling");
    assert_eq!(source.get_calls(), 2);

    runtime.time.advance(Duration::from_millis(50)).await;
    send_data(&call.response_sender, b"join-cooldown");
    assert_eq!(next_data(&mut call.response_body).await, "join-cooldown");
    assert_eq!(source.get_calls(), 3);
    runtime.stop().await;
}

#[tokio::test]
async fn idle_stale_stream_retries_readmission_after_a_failure() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let first_watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    source
        .push_get(
            SUBJECT_A,
            GetAction::Return(Err(DecisionSourceError::new(
                DecisionSourceErrorKind::Permanent,
                "subject is not enrolled",
            ))),
        )
        .await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Denied)))
        .await;
    let runtime = start_runtime(
        Arc::clone(&source),
        &ConfigOptions {
            unary_timeout: Duration::from_millis(1),
            admission_timeout: Duration::from_millis(50),
            permanent_failure_cooldown: Duration::ZERO,
            ..ConfigOptions::default()
        },
    )
    .await;
    let mut call = start_streaming_call(&runtime.layer, SUBJECT_A).await;

    let _second_watch = source.push_live_watch(Vec::new()).await;
    drop(first_watch);
    wait_for_watch_connected(&runtime.metrics, false).await;
    runtime.time.advance(Duration::from_millis(125)).await;
    source.wait_for_watches(2).await;
    wait_for_watch_connected(&runtime.metrics, true).await;

    send_data(&call.response_sender, b"starts-readmission");
    assert_eq!(
        next_data(&mut call.response_body).await,
        "starts-readmission"
    );
    source.wait_for_gets(2).await;

    let status = tokio::spawn(async move { next_status(&mut call.response_body).await });
    tokio::task::yield_now().await;
    runtime.time.advance(Duration::from_millis(50)).await;
    source.wait_for_gets(3).await;
    assert_eq!(
        status.await.expect("status task joins").code(),
        Code::FailedPrecondition
    );
    runtime.stop().await;
}

#[tokio::test]
async fn stale_stream_is_cut_when_readmission_is_denied() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let first_watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Denied)))
        .await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;
    let mut call = start_streaming_call(&runtime.layer, SUBJECT_A).await;

    let _second_watch = source.push_live_watch(Vec::new()).await;
    drop(first_watch);
    wait_for_watch_connected(&runtime.metrics, false).await;
    runtime.time.advance(Duration::from_millis(125)).await;
    source.wait_for_watches(2).await;
    wait_for_watch_connected(&runtime.metrics, true).await;
    send_data(&call.response_sender, b"not-delivered");

    let status = next_status(&mut call.response_body).await;
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert_eq!(source.get_calls(), 2);
    assert_eq!(runtime.metrics.stream_cutoffs.load(Ordering::Relaxed), 1);
    runtime.stop().await;
}

#[tokio::test]
async fn event_does_not_revive_an_entry_removed_after_a_failed_readmission() {
    let source = Arc::new(ScriptedDecisionSource::default());
    let first_watch = source.push_live_watch(Vec::new()).await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    source
        .push_get(
            SUBJECT_A,
            GetAction::Gate {
                release: Arc::clone(&release),
                result: Err(DecisionSourceError::new(
                    DecisionSourceErrorKind::Transient,
                    "temporary failure",
                )),
            },
        )
        .await;
    source
        .push_get(SUBJECT_A, GetAction::Return(Ok(Decision::Allowed)))
        .await;
    let runtime = start_runtime(Arc::clone(&source), &ConfigOptions::default()).await;
    let mut call = start_streaming_call(&runtime.layer, SUBJECT_A).await;

    let second_watch = source.push_live_watch(Vec::new()).await;
    drop(first_watch);
    wait_for_watch_connected(&runtime.metrics, false).await;
    runtime.time.advance(Duration::from_millis(125)).await;
    source.wait_for_watches(2).await;
    wait_for_watch_connected(&runtime.metrics, true).await;
    send_data(&call.response_sender, b"starts-readmission");
    assert_eq!(
        next_data(&mut call.response_body).await,
        "starts-readmission"
    );
    source.wait_for_gets(2).await;
    release.add_permits(1);
    send_data(&call.response_sender, b"failed");
    assert_eq!(next_data(&mut call.response_body).await, "failed");
    wait_for_metric(&runtime.metrics.admission_retries, 1).await;

    // An event cannot revive the detached Stale entry held by the stream.
    second_watch
        .send(Ok(change(SUBJECT_A, Decision::Allowed)))
        .expect("watch remains live");
    wait_for_metric(&runtime.metrics.watch_events, 1).await;
    runtime.time.advance(Duration::from_millis(100)).await;
    send_data(&call.response_sender, b"refetched");
    assert_eq!(next_data(&mut call.response_body).await, "refetched");
    assert_eq!(source.get_calls(), 3, "the stale entry is not revived");
    runtime.stop().await;
}

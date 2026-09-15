// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::convert::Infallible;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::task::{Context as TaskContext, Poll};
use core::time::Duration;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use bytes::{Buf, Bytes};
use futures_util::stream::{self, StreamExt};
use futures_util::task::{ArcWake, waker};
use http::header::CONTENT_TYPE;
use http::{Request, Response};
use http_body::{Body, Frame, SizeHint};
use http_body_util::Full;
use policy_gate::{
    AxumBodyAdapter, Decision, DecisionChange, DecisionSource, DecisionSourceError,
    DecisionSourceHealth, DecisionSourceHealthStatus, PolicyGate, PolicyGateConfig,
    PolicyGateLayer, PolicyGateLayerConfig, PolicyGateMetrics, PolicyGateRuntime, RequestPolicy,
    TimeDriver, TonicRejectionResponse,
};
use tokio::sync::{Mutex, Semaphore, broadcast, mpsc, oneshot};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::Status;
use tower::{Layer, ServiceExt, service_fn};
use uuid::Uuid;

#[path = "../support/time.rs"]
mod time;
pub(crate) use time::TestTimeDriver;

pub(crate) const PAYMENT_URL: &str = "https://pay.example.test/billing";
pub(crate) const SUBJECT_A: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
pub(crate) const SUBJECT_B: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
pub(crate) const SUBJECT_C: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

const WAIT_ITERATIONS: usize = 10_000;
const CLIENT_STREAMING_PATHS: [&str; 2] = [
    "/google.bytestream.ByteStream/Write",
    "/google.devtools.build.v1.PublishBuildEvent/PublishBuildToolEventStream",
];

#[derive(Default)]
pub(crate) struct RecordingWaker(AtomicUsize);

impl RecordingWaker {
    pub(crate) fn waker(self: &Arc<Self>) -> core::task::Waker {
        waker(Arc::clone(self))
    }

    pub(crate) fn count(&self) -> usize {
        self.0.load(Ordering::Acquire)
    }
}

impl ArcWake for RecordingWaker {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.0.fetch_add(1, Ordering::AcqRel);
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TestSubject(pub(crate) Uuid);

#[derive(Clone, Copy, Debug)]
pub(crate) struct TestPolicy;

impl RequestPolicy<Uuid> for TestPolicy {
    fn subject<B>(&self, request: &Request<B>) -> Option<Uuid> {
        request
            .extensions()
            .get::<TestSubject>()
            .map(|subject| subject.0)
    }

    fn enforce_request_body<B>(&self, request: &Request<B>) -> bool {
        CLIENT_STREAMING_PATHS.contains(&request.uri().path())
    }
}

pub(crate) type TestPolicyGateLayer = PolicyGateLayer<
    TestPolicy,
    Uuid,
    ScriptedDecisionSource,
    AxumBodyAdapter,
    TestMetrics,
    TonicRejectionResponse,
    TestTimeDriver,
>;

#[derive(Debug, Default)]
pub(crate) struct TestMetricStorage {
    pub(crate) denials: AtomicU64,
    pub(crate) unavailable_rejections: AtomicU64,
    pub(crate) snapshot_misses: AtomicU64,
    pub(crate) map_hits: AtomicU64,
    pub(crate) stream_cutoffs: AtomicU64,
    pub(crate) snapshot_republishes: AtomicU64,
    pub(crate) unary_calls: AtomicU64,
    pub(crate) unary_failures: AtomicU64,
    pub(crate) admission_retries: AtomicU64,
    pub(crate) admission_timeouts: AtomicU64,
    pub(crate) watch_connected: AtomicU64,
    pub(crate) watch_disconnects: AtomicU64,
    pub(crate) watch_open_failures: AtomicU64,
    pub(crate) watch_events: AtomicU64,
    pub(crate) wire_failures: AtomicU64,
    pub(crate) missing_subject_rejections: AtomicU64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TestMetrics(&'static TestMetricStorage);

impl core::ops::Deref for TestMetrics {
    type Target = TestMetricStorage;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl PolicyGateMetrics for TestMetrics {
    fn denial(self) {
        self.denials.fetch_add(1, Ordering::Relaxed);
    }

    fn unavailable_rejection(self) {
        self.unavailable_rejections.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot_miss(self) {
        self.snapshot_misses.fetch_add(1, Ordering::Relaxed);
    }

    fn map_hit(self) {
        self.map_hits.fetch_add(1, Ordering::Relaxed);
    }

    fn stream_cutoff(self) {
        self.stream_cutoffs.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot_republish(self) {
        self.snapshot_republishes.fetch_add(1, Ordering::Relaxed);
    }

    fn unary_call(self) {
        self.unary_calls.fetch_add(1, Ordering::Relaxed);
    }

    fn unary_failure(self) {
        self.unary_failures.fetch_add(1, Ordering::Relaxed);
    }

    fn admission_retry(self) {
        self.admission_retries.fetch_add(1, Ordering::Relaxed);
    }

    fn admission_timeout(self) {
        self.admission_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    fn set_watch_connected(self, connected: bool) {
        self.watch_connected
            .store(u64::from(connected), Ordering::Release);
    }

    fn watch_disconnect(self) {
        self.watch_disconnects.fetch_add(1, Ordering::Relaxed);
    }

    fn watch_open_failure(self) {
        self.watch_open_failures.fetch_add(1, Ordering::Relaxed);
    }

    fn watch_event(self) {
        self.watch_events.fetch_add(1, Ordering::Relaxed);
    }

    fn wire_failure(self) {
        self.wire_failures.fetch_add(1, Ordering::Relaxed);
    }

    fn missing_subject_rejection(self) {
        self.missing_subject_rejections
            .fetch_add(1, Ordering::Relaxed);
    }
}

fn test_metrics() -> TestMetrics {
    TestMetrics(Box::leak(Box::new(TestMetricStorage::default())))
}

type ScriptedChange = Result<DecisionChange<Uuid>, DecisionSourceError>;
type ScriptedChangeStream = stream::Chain<
    stream::Iter<std::vec::IntoIter<ScriptedChange>>,
    UnboundedReceiverStream<ScriptedChange>,
>;

pub(crate) enum GetAction {
    Return(Result<Decision, DecisionSourceError>),
    Gate {
        release: Arc<Semaphore>,
        result: Result<Decision, DecisionSourceError>,
    },
}

enum WatchAction {
    Live(
        Vec<Result<DecisionChange<Uuid>, DecisionSourceError>>,
        mpsc::UnboundedReceiver<Result<DecisionChange<Uuid>, DecisionSourceError>>,
    ),
    PendingOpen,
    Error(DecisionSourceError),
}

#[derive(Default)]
pub(crate) struct ScriptedDecisionSource {
    gets: Mutex<HashMap<String, VecDeque<GetAction>>>,
    watches: Mutex<VecDeque<WatchAction>>,
    get_calls: AtomicUsize,
    get_completions: AtomicUsize,
    watch_calls: AtomicUsize,
}

impl ScriptedDecisionSource {
    pub(crate) async fn push_get(&self, subject: &str, action: GetAction) {
        self.gets
            .lock()
            .await
            .entry(subject.to_owned())
            .or_default()
            .push_back(action);
    }

    pub(crate) async fn push_live_watch(
        &self,
        initial: Vec<Result<DecisionChange<Uuid>, DecisionSourceError>>,
    ) -> mpsc::UnboundedSender<Result<DecisionChange<Uuid>, DecisionSourceError>> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.watches
            .lock()
            .await
            .push_back(WatchAction::Live(initial, rx));
        tx
    }

    pub(crate) async fn push_pending_watch(&self) {
        self.watches
            .lock()
            .await
            .push_back(WatchAction::PendingOpen);
    }

    pub(crate) async fn push_watch_error(&self, error: DecisionSourceError) {
        self.watches
            .lock()
            .await
            .push_back(WatchAction::Error(error));
    }

    pub(crate) fn get_calls(&self) -> usize {
        self.get_calls.load(Ordering::Acquire)
    }

    pub(crate) fn get_completions(&self) -> usize {
        self.get_completions.load(Ordering::Acquire)
    }

    pub(crate) fn watch_calls(&self) -> usize {
        self.watch_calls.load(Ordering::Acquire)
    }

    pub(crate) async fn wait_for_gets(&self, expected: usize) {
        for _ in 0..WAIT_ITERATIONS {
            if self.get_calls() >= expected {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("source get count did not advance");
    }

    pub(crate) async fn wait_for_get_completions(&self, expected: usize) {
        for _ in 0..WAIT_ITERATIONS {
            if self.get_completions() >= expected {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("source get completion count did not advance");
    }

    pub(crate) async fn wait_for_watches(&self, expected: usize) {
        for _ in 0..WAIT_ITERATIONS {
            if self.watch_calls() >= expected {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("source watch count did not advance");
    }
}

impl DecisionSource<Uuid> for ScriptedDecisionSource {
    type Changes = ScriptedChangeStream;

    async fn get_subject_decision(&self, subject: &Uuid) -> Result<Decision, DecisionSourceError> {
        let subject = subject.to_string();
        self.get_calls.fetch_add(1, Ordering::AcqRel);
        let action = self
            .gets
            .lock()
            .await
            .get_mut(&subject)
            .and_then(VecDeque::pop_front)
            .unwrap_or(GetAction::Return(Ok(Decision::Allowed)));
        let result = match action {
            GetAction::Return(result) => result,
            GetAction::Gate { release, result } => {
                let permit = release.acquire().await.expect("gate must remain open");
                permit.forget();
                result
            }
        };
        self.get_completions.fetch_add(1, Ordering::Release);
        result
    }

    async fn watch_subject_decisions(&self) -> Result<Self::Changes, DecisionSourceError> {
        self.watch_calls.fetch_add(1, Ordering::AcqRel);
        let action = self
            .watches
            .lock()
            .await
            .pop_front()
            .unwrap_or(WatchAction::PendingOpen);
        match action {
            WatchAction::Live(initial, receiver) => {
                Ok(stream::iter(initial).chain(UnboundedReceiverStream::new(receiver)))
            }
            WatchAction::PendingOpen => core::future::pending().await,
            WatchAction::Error(error) => Err(error),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ConfigOptions {
    pub(crate) unary_timeout: Duration,
    pub(crate) admission_timeout: Duration,
    pub(crate) initial_admission_retry_delay: Duration,
    pub(crate) max_admission_retry_delay: Duration,
    pub(crate) permanent_failure_cooldown: Duration,
    pub(crate) snapshot_republish_interval: Duration,
    pub(crate) initial_reconnect_delay: Duration,
    pub(crate) max_reconnect_delay: Duration,
    pub(crate) watch_events_per_yield: usize,
    pub(crate) max_subjects: usize,
    pub(crate) subject_ttl: Duration,
    pub(crate) decision_freshness_ttl: Option<Duration>,
    pub(crate) decision_refresh_ahead: Option<Duration>,
}

impl Default for ConfigOptions {
    fn default() -> Self {
        Self {
            unary_timeout: Duration::from_secs(1),
            admission_timeout: Duration::from_secs(3),
            initial_admission_retry_delay: Duration::from_millis(100),
            max_admission_retry_delay: Duration::from_secs(1),
            permanent_failure_cooldown: Duration::from_secs(1),
            snapshot_republish_interval: Duration::from_millis(10),
            initial_reconnect_delay: Duration::from_millis(100),
            max_reconnect_delay: Duration::from_secs(5),
            watch_events_per_yield: 64,
            max_subjects: 65_536,
            subject_ttl: Duration::from_secs(3_600),
            decision_freshness_ttl: None,
            decision_refresh_ahead: None,
        }
    }
}

pub(crate) fn validated(options: &ConfigOptions) -> PolicyGateConfig {
    let mut builder = PolicyGateConfig::builder()
        .unary_timeout(options.unary_timeout)
        .admission_timeout(options.admission_timeout)
        .initial_admission_retry_delay(options.initial_admission_retry_delay)
        .max_admission_retry_delay(options.max_admission_retry_delay)
        .permanent_failure_cooldown(options.permanent_failure_cooldown)
        .snapshot_republish_interval(options.snapshot_republish_interval)
        .initial_reconnect_delay(options.initial_reconnect_delay)
        .max_reconnect_delay(options.max_reconnect_delay)
        .watch_events_per_yield(options.watch_events_per_yield)
        .max_subjects(options.max_subjects)
        .subject_ttl(options.subject_ttl);
    if let Some(ttl) = options.decision_freshness_ttl {
        builder = builder.decision_freshness_ttl(ttl);
    }
    if let Some(refresh_ahead) = options.decision_refresh_ahead {
        builder = builder.decision_refresh_ahead(refresh_ahead);
    }
    builder.build().expect("test config must validate")
}

pub(crate) fn layer_config() -> PolicyGateLayerConfig {
    PolicyGateLayerConfig::new(
        format!(
            "Your organization has reached its cache usage limit. Visit {PAYMENT_URL} to review usage and restore access."
        ),
        "request is missing the subject identifier required for policy enforcement",
    )
}

pub(crate) struct TestRuntime {
    pub(crate) gate: PolicyGate<Uuid, ScriptedDecisionSource, TestMetrics, TestTimeDriver>,
    pub(crate) layer: TestPolicyGateLayer,
    pub(crate) watcher:
        policy_gate::DecisionWatcher<Uuid, ScriptedDecisionSource, TestMetrics, TestTimeDriver>,
    pub(crate) health: Arc<DecisionSourceHealth<TestTimeDriver>>,
    pub(crate) metrics: TestMetrics,
    pub(crate) time: TestTimeDriver,
}

pub(crate) fn runtime(source: Arc<ScriptedDecisionSource>, options: &ConfigOptions) -> TestRuntime {
    let time = TestTimeDriver::default();
    let PolicyGateRuntime {
        gate,
        layer,
        watcher,
        health,
        metrics,
        ..
    } = PolicyGateRuntime::new_with_client_metrics_response_and_time_driver(
        &validated(options),
        &layer_config(),
        source,
        TestPolicy,
        AxumBodyAdapter,
        test_metrics(),
        TonicRejectionResponse,
        time.clone(),
    );
    TestRuntime {
        gate,
        layer,
        watcher,
        health,
        metrics,
        time,
    }
}

pub(crate) struct RunningRuntime {
    pub(crate) gate: PolicyGate<Uuid, ScriptedDecisionSource, TestMetrics, TestTimeDriver>,
    pub(crate) layer: TestPolicyGateLayer,
    pub(crate) health: Arc<DecisionSourceHealth<TestTimeDriver>>,
    pub(crate) metrics: TestMetrics,
    pub(crate) time: TestTimeDriver,
    shutdown: broadcast::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl RunningRuntime {
    pub(crate) async fn stop(self) {
        drop(self.shutdown.send(()));
        self.task.await.expect("watch task must join");
    }
}

pub(crate) async fn start_runtime(
    source: Arc<ScriptedDecisionSource>,
    options: &ConfigOptions,
) -> RunningRuntime {
    let runtime = start_runtime_inner(Arc::clone(&source), options, None);
    source.wait_for_watches(1).await;
    wait_for_watch_connected(&runtime.metrics, true).await;
    runtime
}

pub(crate) fn start_runtime_after(
    source: Arc<ScriptedDecisionSource>,
    options: &ConfigOptions,
    delay: Duration,
) -> RunningRuntime {
    start_runtime_inner(source, options, Some(delay))
}

fn start_runtime_inner(
    source: Arc<ScriptedDecisionSource>,
    options: &ConfigOptions,
    delay: Option<Duration>,
) -> RunningRuntime {
    let TestRuntime {
        gate,
        layer,
        watcher,
        health,
        metrics,
        time,
    } = runtime(source, options);
    let (shutdown, _) = broadcast::channel(1);
    let task_time = time.clone();
    let task = tokio::spawn({
        let mut shutdown_rx = shutdown.subscribe();
        async move {
            if let Some(delay) = delay {
                task_time.sleep(delay).await;
            }
            tokio::select! {
                () = watcher => {}
                _ = shutdown_rx.recv() => {}
            }
        }
    });
    RunningRuntime {
        gate,
        layer,
        health,
        metrics,
        time,
        shutdown,
        task,
    }
}

pub(crate) fn change(subject: &str, state: Decision) -> DecisionChange<Uuid> {
    DecisionChange {
        subject: subject.parse().expect("test subject must be a UUID"),
        decision: state,
    }
}

pub(crate) struct ObservedCall {
    pub(crate) status: Option<Status>,
    pub(crate) inner_calls: usize,
    pub(crate) has_grpc_content_type: bool,
}

pub(crate) fn assert_allowed(call: &ObservedCall) {
    assert_eq!(call.inner_calls, 1);
    assert!(call.status.is_none());
}

pub(crate) fn assert_rejected(call: &ObservedCall, code: tonic::Code) {
    assert_eq!(call.inner_calls, 0);
    assert_eq!(call.status.as_ref().expect("gRPC status").code(), code);
    assert!(call.has_grpc_content_type);
}

#[derive(Debug, Default)]
pub(crate) struct StreamProbe {
    pub(crate) bytes: AtomicUsize,
    pub(crate) polls: AtomicUsize,
    pub(crate) dropped: AtomicBool,
}

pub(crate) struct ScriptedBody {
    receiver: mpsc::UnboundedReceiver<Result<Frame<Bytes>, Infallible>>,
    probe: Arc<StreamProbe>,
}

impl Body for ScriptedBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.probe.polls.fetch_add(1, Ordering::Relaxed);
        let result = self.receiver.poll_recv(cx);
        if let Poll::Ready(Some(Ok(frame))) = &result
            && let Some(data) = frame.data_ref()
        {
            self.probe
                .bytes
                .fetch_add(data.remaining(), Ordering::Relaxed);
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.receiver.is_closed() && self.receiver.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

impl Drop for ScriptedBody {
    fn drop(&mut self) {
        self.probe.dropped.store(true, Ordering::Release);
    }
}

pub(crate) struct StreamingCall {
    pub(crate) request_sender: mpsc::UnboundedSender<Result<Frame<Bytes>, Infallible>>,
    pub(crate) request_body: axum_core::body::Body,
    pub(crate) request_probe: Arc<StreamProbe>,
    pub(crate) response_sender: mpsc::UnboundedSender<Result<Frame<Bytes>, Infallible>>,
    pub(crate) response_body: axum_core::body::Body,
    pub(crate) response_probe: Arc<StreamProbe>,
}

pub(crate) async fn start_streaming_call(
    layer: &TestPolicyGateLayer,
    subject: &str,
) -> StreamingCall {
    start_streaming_call_at_path(layer, subject, "/google.bytestream.ByteStream/Write").await
}

pub(crate) async fn start_streaming_call_at_path(
    layer: &TestPolicyGateLayer,
    subject: &str,
    path: &str,
) -> StreamingCall {
    let (request_sender, request_receiver) = mpsc::unbounded_channel();
    let request_probe = Arc::new(StreamProbe::default());
    let request_body = ScriptedBody {
        receiver: request_receiver,
        probe: Arc::clone(&request_probe),
    };
    let (response_sender, response_receiver) = mpsc::unbounded_channel();
    let response_probe = Arc::new(StreamProbe::default());
    let inner_response_probe = Arc::clone(&response_probe);
    let response_receiver = Arc::new(std::sync::Mutex::new(Some(response_receiver)));
    let (captured_request_tx, captured_request_rx) = oneshot::channel();
    let captured_request_tx = Arc::new(std::sync::Mutex::new(Some(captured_request_tx)));

    let inner = service_fn(move |request: Request<axum_core::body::Body>| {
        let captured_request_tx = Arc::clone(&captured_request_tx);
        let response_receiver = Arc::clone(&response_receiver);
        let response_probe = Arc::clone(&inner_response_probe);
        async move {
            captured_request_tx
                .lock()
                .expect("capture lock")
                .take()
                .expect("service called once")
                .send(request.into_body())
                .expect("request receiver remains open");
            let receiver = response_receiver
                .lock()
                .expect("response lock")
                .take()
                .expect("service called once");
            Ok::<_, Infallible>(Response::new(ScriptedBody {
                receiver,
                probe: response_probe,
            }))
        }
    });
    let mut request = Request::new(axum_core::body::Body::new(request_body));
    *request.uri_mut() = path.parse().expect("method URI");
    request.extensions_mut().insert(TestSubject(
        subject.parse().expect("test subject must be a UUID"),
    ));
    let response = layer
        .layer(inner)
        .oneshot(request)
        .await
        .expect("infallible service");
    let request_body = captured_request_rx.await.expect("inner receives request");
    StreamingCall {
        request_sender,
        request_body,
        request_probe,
        response_sender,
        response_body: response.into_body(),
        response_probe,
    }
}

pub(crate) async fn call_layer<R>(
    layer: &PolicyGateLayer<
        TestPolicy,
        Uuid,
        ScriptedDecisionSource,
        AxumBodyAdapter,
        TestMetrics,
        R,
        TestTimeDriver,
    >,
    subject: Option<&str>,
) -> ObservedCall
where
    R: policy_gate::RejectionResponse<AxumBodyAdapter>,
{
    let inner_calls = Arc::new(AtomicUsize::new(0));
    let observed_inner_calls = Arc::clone(&inner_calls);
    let inner = service_fn(move |_request: Request<axum_core::body::Body>| {
        observed_inner_calls.fetch_add(1, Ordering::Relaxed);
        async { Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok")))) }
    });
    let mut request = Request::new(axum_core::body::Body::empty());
    if let Some(subject) = subject {
        request.extensions_mut().insert(TestSubject(
            subject.parse().expect("test subject must be a UUID"),
        ));
    }
    let response = layer
        .layer(inner)
        .oneshot(request)
        .await
        .expect("infallible service");
    ObservedCall {
        status: Status::from_header_map(response.headers()),
        inner_calls: inner_calls.load(Ordering::Relaxed),
        has_grpc_content_type: response
            .headers()
            .get(CONTENT_TYPE)
            .is_some_and(|value| value == "application/grpc"),
    }
}

pub(crate) async fn call_subject<R>(
    layer: &PolicyGateLayer<
        TestPolicy,
        Uuid,
        ScriptedDecisionSource,
        AxumBodyAdapter,
        TestMetrics,
        R,
        TestTimeDriver,
    >,
    subject: &str,
) -> ObservedCall
where
    R: policy_gate::RejectionResponse<AxumBodyAdapter>,
{
    call_layer(layer, Some(subject)).await
}

pub(crate) async fn wait_for_health(
    health: &DecisionSourceHealth<TestTimeDriver>,
    expected_ok: bool,
) {
    for _ in 0..WAIT_ITERATIONS {
        let is_ok = matches!(health.status(), DecisionSourceHealthStatus::Stable);
        if is_ok == expected_ok {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("health did not reach expected state");
}

pub(crate) async fn wait_for_watch_connected(metrics: &TestMetrics, expected_connected: bool) {
    let expected = u64::from(expected_connected);
    for _ in 0..WAIT_ITERATIONS {
        if metrics.watch_connected.load(Ordering::Acquire) == expected {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("watch connection gauge did not reach expected state");
}

pub(crate) async fn wait_for_metric(metric: &AtomicU64, expected: u64) {
    for _ in 0..WAIT_ITERATIONS {
        if metric.load(Ordering::Acquire) >= expected {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("metric did not advance");
}

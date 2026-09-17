// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use futures_util::poll;
use parking_lot::Mutex;
use policy_gate::{
    AdmissionState, Decision, DecisionChange, DecisionResult, DecisionSource, DecisionSourceError,
    NoopPolicyGateMetrics, PolicyGate, PolicyGateConfig,
};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::UnboundedReceiverStream;

#[allow(dead_code)]
#[path = "support/time.rs"]
mod time;
use time::TestTimeDriver;

struct Payload(&'static str);
type Reply = Result<Option<DecisionResult<Payload>>, DecisionSourceError>;
type Change = Result<DecisionChange<u8>, DecisionSourceError>;
type Gate = PolicyGate<u8, Source, NoopPolicyGateMetrics, TestTimeDriver, Payload>;

#[derive(Default)]
struct Source {
    replies: Mutex<VecDeque<oneshot::Receiver<Reply>>>,
    calls: AtomicUsize,
    watch: Mutex<Option<mpsc::UnboundedReceiver<Change>>>,
}

impl Source {
    fn enqueue(&self) -> oneshot::Sender<Reply> {
        let (tx, rx) = oneshot::channel();
        self.replies.lock().push_back(rx);
        tx
    }
}

impl DecisionSource<u8, Payload> for Source {
    type Changes = UnboundedReceiverStream<Change>;

    fn get_subject_decision(
        &self,
        _: &u8,
    ) -> impl Future<Output = Result<Option<Decision>, DecisionSourceError>> + Send {
        core::future::ready(Ok(Some(Decision::Denied)))
    }

    async fn get_subject_decision_result(&self, _: &u8) -> Reply {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let reply = self.replies.lock().pop_front().expect("scripted reply");
        reply.await.expect("reply sender")
    }

    fn watch_subject_decisions(
        &self,
    ) -> impl Future<Output = Result<Self::Changes, DecisionSourceError>> + Send {
        core::future::ready(Ok(UnboundedReceiverStream::new(
            self.watch.lock().take().expect("one watch"),
        )))
    }
}

fn allowed(value: &'static str) -> DecisionResult<Payload> {
    DecisionResult {
        decision: Decision::Allowed,
        payload: Some(Arc::new(Payload(value))),
        valid_until: None,
    }
}

// Regression: decision transitions must never expose the payload from an older snapshot.
#[tokio::test]
async fn watch_and_invalidation_clear_the_published_payload() {
    let (watch, rx) = mpsc::unbounded_channel();
    let source = Arc::new(Source {
        watch: Mutex::new(Some(rx)),
        ..Source::default()
    });
    let (gate, mut watcher, _) = Gate::new_with_time_driver(
        &PolicyGateConfig::builder().build().unwrap(),
        Arc::clone(&source),
        TestTimeDriver::new(),
    );
    assert!(poll!(&mut watcher).is_pending());
    assert!(source.enqueue().send(Ok(Some(allowed("cached")))).is_ok());
    let admission = gate.admit(&1).await.unwrap();
    assert_eq!(admission.payload().unwrap().0, "cached");

    watch
        .send(Ok(DecisionChange {
            subject: 1,
            decision: Some(Decision::Allowed),
        }))
        .unwrap();
    assert!(poll!(&mut watcher).is_pending());
    assert!(admission.is_allowed());
    assert!(admission.payload().is_none());

    admission.invalidate();
    assert_eq!(admission.state(), AdmissionState::Stale);
    assert!(admission.payload().is_none());
}

// Regression: a refresh that passed its expiry check cannot replace a concurrent expiry latch.
#[tokio::test]
async fn expiry_latch_fences_late_refresh_payload() {
    use core::cell::Cell;
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Barrier, OnceLock};

    use futures_util::FutureExt;
    use policy_gate::TimeDriver;

    std::thread_local! { static PAUSE_AFTER: Cell<usize> = const { Cell::new(0) }; }
    static ENTER: Barrier = Barrier::new(2);
    static RELEASE: Barrier = Barrier::new(2);
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    static MILLIS: AtomicU64 = AtomicU64::new(0);

    #[derive(Clone)]
    struct Clock;
    impl TimeDriver for Clock {
        fn now() -> Instant {
            let now = *EPOCH.get_or_init(Instant::now)
                + Duration::from_millis(MILLIS.load(Ordering::SeqCst));
            if PAUSE_AFTER.with(|pause| {
                let count = pause.get();
                pause.set(count.saturating_sub(1));
                count == 1
            }) {
                ENTER.wait();
                RELEASE.wait();
            }
            now
        }

        fn sleep_until(_: Instant) -> impl Future<Output = ()> + Send {
            core::future::pending()
        }

        fn yield_now() -> impl Future<Output = ()> + Send {
            core::future::ready(())
        }
    }

    struct RaceSource(AtomicUsize);
    impl DecisionSource<u8, Payload> for RaceSource {
        type Changes = futures_util::stream::Pending<Change>;

        fn get_subject_decision(
            &self,
            _: &u8,
        ) -> impl Future<Output = Result<Option<Decision>, DecisionSourceError>> + Send {
            core::future::ready(Ok(Some(Decision::Denied)))
        }

        fn get_subject_decision_result(&self, _: &u8) -> impl Future<Output = Reply> + Send {
            let value = if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                "old"
            } else {
                PAUSE_AFTER.with(|pause| pause.set(2));
                "late"
            };
            core::future::ready(Ok(Some(allowed(value))))
        }

        fn watch_subject_decisions(
            &self,
        ) -> impl Future<Output = Result<Self::Changes, DecisionSourceError>> + Send {
            core::future::ready(Ok(futures_util::stream::pending()))
        }
    }

    let (gate, mut watcher, _) = PolicyGate::new_with_time_driver(
        &PolicyGateConfig::builder()
            .decision_freshness_ttl(Duration::from_millis(100))
            .refresh_before_expiry(Duration::from_millis(40))
            .build()
            .unwrap(),
        Arc::new(RaceSource(AtomicUsize::new(0))),
        Clock,
    );
    assert!(poll!(&mut watcher).is_pending());
    let admission = gate.admit(&1).await.unwrap();
    assert_eq!(admission.payload().unwrap().0, "old");
    MILLIS.store(60, Ordering::SeqCst);
    gate.refresh(1, admission.clone()).await;
    let completion = std::thread::spawn(move || {
        assert!((&mut watcher).now_or_never().is_none());
        watcher
    });
    ENTER.wait();
    MILLIS.store(100, Ordering::SeqCst);
    assert!(admission.payload().is_none());
    RELEASE.wait();
    let _watcher = completion.join().unwrap();
    assert_eq!(admission.state(), AdmissionState::Stale);
    assert!(admission.payload().is_none());
}

fn capped(value: &'static str, deadline: Instant) -> DecisionResult<Payload> {
    DecisionResult {
        valid_until: Some(deadline),
        ..allowed(value)
    }
}

#[tokio::test]
async fn validity_caps_freshness_and_reusing_a_result_keeps_its_anchor() {
    let (_watch, rx) = mpsc::unbounded_channel();
    let source = Arc::new(Source {
        watch: Mutex::new(Some(rx)),
        ..Source::default()
    });
    let time = TestTimeDriver::new();
    let (gate, mut watcher, _) = Gate::new_with_time_driver(
        &PolicyGateConfig::builder()
            .decision_freshness_ttl(Duration::from_millis(100))
            .refresh_before_expiry(Duration::from_millis(40))
            .build()
            .unwrap(),
        Arc::clone(&source),
        time,
    );
    assert!(poll!(&mut watcher).is_pending());
    let anchor = time.now() + Duration::from_millis(30);
    assert!(
        source
            .enqueue()
            .send(Ok(Some(capped("short", anchor))))
            .is_ok()
    );
    let short = gate.admit(&1).await.unwrap();
    assert_eq!(short.check(), (AdmissionState::Allowed, false));
    // A later source deadline must never extend the configured 100 ms TTL.
    assert!(
        source
            .enqueue()
            .send(Ok(Some(capped(
                "long",
                time.now() + Duration::from_secs(1)
            ))))
            .is_ok()
    );
    let long = gate.admit(&2).await.unwrap();
    time.advance(Duration::from_millis(15)).await;
    assert_eq!(short.check(), (AdmissionState::Allowed, true));
    assert!(
        source
            .enqueue()
            .send(Ok(Some(capped("reused", anchor))))
            .is_ok()
    );
    gate.refresh(1, short.clone()).await;
    assert!(poll!(&mut watcher).is_pending());
    assert_eq!(short.payload().unwrap().0, "reused");
    assert_eq!(short.check(), (AdmissionState::Allowed, false));
    time.advance(Duration::from_millis(15)).await;
    assert_eq!(short.state(), AdmissionState::Stale);
    assert!(short.payload().is_none());
    time.advance(Duration::from_millis(70)).await;
    assert_eq!(long.state(), AdmissionState::Stale);
    assert!(long.payload().is_none());
}

#[tokio::test]
async fn expired_cold_results_back_off_before_retrying() {
    let (_watch, rx) = mpsc::unbounded_channel();
    let source = Arc::new(Source {
        watch: Mutex::new(Some(rx)),
        ..Source::default()
    });
    let time = TestTimeDriver::new();
    let (gate, mut watcher, _) = Gate::new_with_time_driver(
        &PolicyGateConfig::builder()
            .initial_admission_retry_delay(Duration::from_millis(10))
            .max_admission_retry_delay(Duration::from_millis(20))
            .build()
            .unwrap(),
        Arc::clone(&source),
        time,
    );
    assert!(poll!(&mut watcher).is_pending());
    for _ in 0..2 {
        assert!(
            source
                .enqueue()
                .send(Ok(Some(capped("expired", time.now()))))
                .is_ok()
        );
    }
    assert!(source.enqueue().send(Ok(Some(allowed("fresh")))).is_ok());
    let mut admit = Box::pin(gate.admit(&1));
    assert!(poll!(&mut admit).is_pending());
    assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    time.advance(Duration::from_millis(9)).await;
    assert!(poll!(&mut admit).is_pending());
    assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    time.advance(Duration::from_millis(1)).await;
    assert!(poll!(&mut admit).is_pending());
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
    time.advance(Duration::from_millis(19)).await;
    assert!(poll!(&mut admit).is_pending());
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
    time.advance(Duration::from_millis(1)).await;
    assert_eq!(admit.await.unwrap().payload().unwrap().0, "fresh");
    assert_eq!(source.calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn expired_refresh_retains_snapshot_and_short_success_waits_half_its_lifetime() {
    let (_watch, rx) = mpsc::unbounded_channel();
    let source = Arc::new(Source {
        watch: Mutex::new(Some(rx)),
        ..Source::default()
    });
    let time = TestTimeDriver::new();
    let (gate, mut watcher, _) = Gate::new_with_time_driver(
        &PolicyGateConfig::builder()
            .decision_freshness_ttl(Duration::from_millis(100))
            .refresh_before_expiry(Duration::from_millis(40))
            .permanent_failure_cooldown(Duration::from_millis(10))
            .build()
            .unwrap(),
        Arc::clone(&source),
        time,
    );
    assert!(poll!(&mut watcher).is_pending());
    assert!(source.enqueue().send(Ok(Some(allowed("old")))).is_ok());
    let admission = gate.admit(&1).await.unwrap();
    time.advance(Duration::from_millis(60)).await;
    // A denial that expires while the lookup is pending cannot replace the old allow/payload.
    let reply = source.enqueue();
    let deadline = time.now() + Duration::from_millis(5);
    gate.refresh(1, admission.clone()).await;
    assert!(poll!(&mut watcher).is_pending());
    time.advance(Duration::from_millis(5)).await;
    assert!(
        reply
            .send(Ok(Some(DecisionResult {
                decision: Decision::Denied,
                ..capped("expired", deadline)
            })))
            .is_ok()
    );
    assert!(poll!(&mut watcher).is_pending());
    assert_eq!(admission.payload().unwrap().0, "old");
    assert_eq!(admission.check(), (AdmissionState::Allowed, false));
    time.advance(Duration::from_millis(9)).await;
    gate.refresh(1, admission.clone()).await;
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
    time.advance(Duration::from_millis(1)).await;
    assert_eq!(admission.check(), (AdmissionState::Allowed, true));
    assert!(
        source
            .enqueue()
            .send(Ok(Some(capped(
                "short",
                time.now() + Duration::from_millis(20)
            ))))
            .is_ok()
    );
    gate.refresh(1, admission.clone()).await;
    assert!(poll!(&mut watcher).is_pending());
    assert_eq!(admission.payload().unwrap().0, "short");
    for _ in 0..4 {
        assert_eq!(admission.check(), (AdmissionState::Allowed, false));
        gate.refresh(1, admission.clone()).await;
        assert!(gate.try_cached(&1).await.is_some());
        assert!(poll!(&mut watcher).is_pending());
    }
    assert_eq!(source.calls.load(Ordering::SeqCst), 3);
    time.advance(Duration::from_millis(9)).await;
    assert_eq!(admission.check(), (AdmissionState::Allowed, false));
    time.advance(Duration::from_millis(1)).await;
    assert_eq!(admission.check(), (AdmissionState::Allowed, true));
    time.advance(Duration::from_millis(10)).await;
    assert_eq!(admission.check(), (AdmissionState::Stale, false));
    assert!(admission.payload().is_none());
}

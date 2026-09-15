// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::future::Future as _;
use core::hash::{Hash, Hasher};
use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use policy_gate::{
    Decision, DecisionChange, DecisionSource, DecisionSourceError, DecisionWatcher, PolicyGate,
    PolicyGateConfig, TimeDriver,
};

static NOW: OnceLock<Instant> = OnceLock::new();
static NOW_CALLS_UNTIL_CANCEL: AtomicUsize = AtomicUsize::new(0);
static WATCHER: Mutex<Option<DecisionWatcher>> = Mutex::new(None);

#[derive(Clone, Copy)]
struct CancellationTime;

impl TimeDriver for CancellationTime {
    fn now() -> Instant {
        if NOW_CALLS_UNTIL_CANCEL.fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
            remaining.checked_sub(1)
        }) == Ok(1)
        {
            drop(WATCHER.lock().expect("watcher lock").take());
        }
        *NOW.get_or_init(Instant::now)
    }

    fn sleep_until(_: Instant) -> impl Future<Output = ()> + Send {
        core::future::pending()
    }

    fn yield_now() -> impl Future<Output = ()> + Send {
        core::future::ready(())
    }
}

#[derive(Clone)]
struct TrackedSubject {
    id: u8,
    _lifetime: Arc<()>,
}

impl PartialEq for TrackedSubject {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for TrackedSubject {}

impl Hash for TrackedSubject {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

struct Source;

impl DecisionSource<TrackedSubject> for Source {
    type Changes =
        futures_util::stream::Pending<Result<DecisionChange<TrackedSubject>, DecisionSourceError>>;

    fn get_subject_decision(
        &self,
        _: &TrackedSubject,
    ) -> impl Future<Output = Result<Option<Decision>, DecisionSourceError>> + Send {
        core::future::ready(Ok(Some(Decision::Allowed)))
    }

    fn watch_subject_decisions(
        &self,
    ) -> impl Future<Output = Result<Self::Changes, DecisionSourceError>> + Send {
        core::future::ready(Ok(futures_util::stream::pending()))
    }
}

#[tokio::test]
async fn cancellation_between_clear_and_insert_does_not_retain_the_subject() {
    let config = PolicyGateConfig::builder().build().expect("valid config");
    let (gate, mut watcher, _) =
        PolicyGate::new_with_time_driver(&config, Arc::new(Source), CancellationTime);
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert_eq!(Pin::new(&mut watcher).poll(&mut cx), Poll::Pending);
    *WATCHER.lock().expect("watcher lock") = Some(watcher);

    let lifetime = Arc::new(());
    let retained = Arc::downgrade(&lifetime);
    let subject = TrackedSubject {
        id: 1,
        _lifetime: lifetime,
    };
    // The third admission clock read falls after connectivity passes and before map insertion.
    NOW_CALLS_UNTIL_CANCEL.store(3, Ordering::Release);

    assert!(gate.admit(&subject).await.is_err());
    drop(subject);

    assert!(retained.upgrade().is_none());
}

// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use policy_gate::TimeDriver;

#[derive(Clone)]
pub(crate) struct TestTimeDriver {
    inner: Arc<Mutex<ClockState>>,
}

struct ClockState {
    now: Instant,
    next_sleep_id: u64,
    sleepers: Vec<SleeperRegistration>,
}

struct SleeperRegistration {
    id: u64,
    deadline: Instant,
    state: Arc<SleepState>,
}

#[derive(Default)]
struct SleepState {
    ready: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

struct TestSleep {
    clock: Arc<Mutex<ClockState>>,
    id: Option<u64>,
    state: Arc<SleepState>,
}

impl Default for TestTimeDriver {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ClockState {
                // Instant has no public constant; this value is an opaque epoch and is never
                // compared with elapsed wall time.
                now: Instant::now(),
                next_sleep_id: 0,
                sleepers: Vec::new(),
            })),
        }
    }
}

impl TestTimeDriver {
    pub(crate) fn now(&self) -> Instant {
        self.inner.lock().expect("test clock lock").now
    }

    pub(crate) async fn advance(&self, duration: Duration) {
        let wakers = {
            let mut clock = self.inner.lock().expect("test clock lock");
            clock.now += duration;
            let now = clock.now;
            let mut wakers = Vec::new();
            clock.sleepers.retain(|sleeper| {
                if sleeper.deadline > now {
                    return true;
                }
                sleeper.state.ready.store(true, Ordering::Release);
                if let Some(waker) = sleeper.state.waker.lock().expect("sleep waker lock").take() {
                    wakers.push(waker);
                }
                false
            });
            wakers
        };
        for waker in wakers {
            waker.wake();
        }
        tokio::task::yield_now().await;
    }
}

impl Future for TestSleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.state.ready.load(Ordering::Acquire) {
            return Poll::Ready(());
        }
        *self.state.waker.lock().expect("sleep waker lock") = Some(cx.waker().clone());
        if self.state.ready.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

impl Drop for TestSleep {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            self.clock
                .lock()
                .expect("test clock lock")
                .sleepers
                .retain(|sleeper| sleeper.id != id);
        }
        self.state.waker.lock().expect("sleep waker lock").take();
    }
}

impl TimeDriver for TestTimeDriver {
    fn now(&self) -> Instant {
        self.now()
    }

    fn sleep_until(&self, deadline: Instant) -> impl Future<Output = ()> + Send {
        let state = Arc::new(SleepState::default());
        let mut id = None;
        {
            let mut clock = self.inner.lock().expect("test clock lock");
            if deadline <= clock.now {
                state.ready.store(true, Ordering::Release);
            } else {
                let sleep_id = clock.next_sleep_id;
                clock.next_sleep_id = clock.next_sleep_id.wrapping_add(1);
                clock.sleepers.push(SleeperRegistration {
                    id: sleep_id,
                    deadline,
                    state: Arc::clone(&state),
                });
                id = Some(sleep_id);
            }
        }
        TestSleep {
            clock: Arc::clone(&self.inner),
            id,
            state,
        }
    }

    fn yield_now(&self) -> impl Future<Output = ()> + Send {
        let mut yielded = false;
        core::future::poll_fn(move |cx| {
            if yielded {
                Poll::Ready(())
            } else {
                yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
    }
}

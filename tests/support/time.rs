// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::cell::RefCell;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::thread_local;
use std::time::Instant;

use policy_gate::TimeDriver;

struct ClockState {
    now: Instant,
    next_sleep_id: u64,
    sleepers: Vec<Sleeper>,
}

struct Sleeper {
    id: u64,
    deadline: Instant,
    waker: Option<Waker>,
}

thread_local! {
    static CLOCK: RefCell<Option<ClockState>> = const { RefCell::new(None) };
}

fn with_clock<R>(f: impl FnOnce(&mut ClockState) -> R) -> R {
    CLOCK.with(|clock| {
        f(clock
            .borrow_mut()
            .as_mut()
            .expect("TestTimeDriver::new() must run before the clock is used"))
    })
}

/// Test [`TimeDriver`] backed by one manually advanced clock per OS thread.
#[derive(Clone, Copy)]
pub(crate) struct TestTimeDriver;

impl TestTimeDriver {
    pub(crate) fn new() -> Self {
        CLOCK.with(|clock| {
            *clock.borrow_mut() = Some(ClockState {
                now: Instant::now(),
                next_sleep_id: 0,
                sleepers: Vec::new(),
            });
        });
        Self
    }

    #[allow(dead_code, clippy::unused_self)]
    pub(crate) fn now(self) -> Instant {
        with_clock(|clock| clock.now)
    }

    #[allow(clippy::unused_self)]
    pub(crate) async fn advance(self, duration: Duration) {
        let wakers = with_clock(|clock| {
            clock.now += duration;
            let now = clock.now;
            let mut wakers = Vec::new();
            clock.sleepers.retain_mut(|sleeper| {
                if sleeper.deadline > now {
                    return true;
                }
                if let Some(waker) = sleeper.waker.take() {
                    wakers.push(waker);
                }
                false
            });
            wakers
        });
        for waker in wakers {
            waker.wake();
        }
        tokio::task::yield_now().await;
    }
}

struct TestSleep {
    id: Option<u64>,
    fired: bool,
}

impl Future for TestSleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.fired {
            return Poll::Ready(());
        }
        let Some(id) = this.id else {
            this.fired = true;
            return Poll::Ready(());
        };
        with_clock(|clock| {
            if let Some(sleeper) = clock.sleepers.iter_mut().find(|s| s.id == id) {
                sleeper.waker = Some(cx.waker().clone());
                Poll::Pending
            } else {
                this.fired = true;
                Poll::Ready(())
            }
        })
    }
}

impl Drop for TestSleep {
    fn drop(&mut self) {
        let Some(id) = self.id else { return };
        CLOCK.with(|clock| {
            if let Some(clock) = clock.borrow_mut().as_mut() {
                clock.sleepers.retain(|sleeper| sleeper.id != id);
            }
        });
    }
}

impl TimeDriver for TestTimeDriver {
    fn now() -> Instant {
        with_clock(|clock| clock.now)
    }

    fn sleep_until(deadline: Instant) -> impl Future<Output = ()> + Send {
        with_clock(|clock| {
            if deadline <= clock.now {
                TestSleep {
                    id: None,
                    fired: true,
                }
            } else {
                let id = clock.next_sleep_id;
                clock.next_sleep_id = clock.next_sleep_id.wrapping_add(1);
                clock.sleepers.push(Sleeper {
                    id,
                    deadline,
                    waker: None,
                });
                TestSleep {
                    id: Some(id),
                    fired: false,
                }
            }
        })
    }

    fn yield_now() -> impl Future<Output = ()> + Send {
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

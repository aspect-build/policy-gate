// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::future::{Future, ready};
use core::time::Duration;
use std::time::Instant;

use futures_util::FutureExt;
use policy_gate::{TimeDriver, TimeoutElapsed, TokioTimeDriver};

#[derive(Clone, Copy)]
struct ImmediateTimeDriver;

impl TimeDriver for ImmediateTimeDriver {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep_until(&self, _deadline: Instant) -> impl Future<Output = ()> + Send {
        ready(())
    }

    fn yield_now(&self) -> impl Future<Output = ()> + Send {
        ready(())
    }
}

#[test]
fn custom_drivers_are_statically_dispatched_and_timeouts_win_ties() {
    let driver = ImmediateTimeDriver;
    let deadline = driver.now() + Duration::from_secs(1);
    let result = driver
        .timeout_at(deadline, ready(42))
        .now_or_never()
        .expect("the immediate driver completes synchronously");

    assert_eq!(result, Err(TimeoutElapsed));
    assert_eq!(core::mem::size_of::<TokioTimeDriver>(), 0);
}

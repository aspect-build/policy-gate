// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll};
use core::time::Duration;
use std::sync::Arc;

use futures_util::task::{ArcWake, waker};
use policy_gate::{TimeDriver, TimeoutElapsed};

#[path = "support/time.rs"]
mod time;
use time::TestTimeDriver;

#[derive(Default)]
struct WakeCounter(AtomicUsize);

impl ArcWake for WakeCounter {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.0.fetch_add(1, Ordering::AcqRel);
    }
}

#[tokio::test]
async fn timeout_wins_when_operation_and_deadline_become_ready_together() {
    let driver = TestTimeDriver::default();
    let deadline = driver.now() + Duration::from_secs(1);
    let operation_driver = driver.clone();
    let timeout_driver = driver.clone();
    let result = tokio::spawn(async move {
        timeout_driver
            .timeout_at(deadline, operation_driver.sleep_until(deadline))
            .await
    });
    tokio::task::yield_now().await;

    driver.advance(Duration::from_millis(999)).await;
    assert!(!result.is_finished());
    driver.advance(Duration::from_millis(1)).await;
    assert_eq!(
        result.await.expect("timeout task joins"),
        Err(TimeoutElapsed)
    );
}

#[tokio::test]
async fn dropping_sleep_removes_its_waker() {
    let driver = TestTimeDriver::default();
    let wake_counter = Arc::new(WakeCounter::default());
    let task_waker = waker(Arc::clone(&wake_counter));
    let mut cancelled_context = Context::from_waker(&task_waker);
    let mut cancelled = Box::pin(driver.sleep_until(driver.now() + Duration::from_secs(1)));
    assert_eq!(
        Pin::new(&mut cancelled).poll(&mut cancelled_context),
        Poll::Pending
    );

    drop(cancelled);
    driver.advance(Duration::from_secs(1)).await;

    assert_eq!(wake_counter.0.load(Ordering::Acquire), 0);
}

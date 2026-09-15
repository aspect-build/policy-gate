// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::future::Future;
use core::time::Duration;
use std::time::Instant;

use futures_util::FutureExt;

/// Monotonic clock and asynchronous waiting used by a policy gate.
///
/// All clones must share one clock domain. A sleep must be cancellation-safe: dropping its future
/// cancels the wait without affecting later sleeps.
pub trait TimeDriver: Clone + Send + Sync + Sized + 'static {
    /// Returns the current monotonic time.
    fn now(&self) -> Instant;

    /// Waits until `deadline` according to the same clock returned by [`TimeDriver::now`].
    fn sleep_until(&self, deadline: Instant) -> impl Future<Output = ()> + Send;

    /// Yields execution back to the asynchronous runtime once.
    fn yield_now(&self) -> impl Future<Output = ()> + Send;

    /// Waits for `duration` according to this driver.
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send {
        let deadline = self.now().checked_add(duration);
        async move {
            match deadline {
                Some(deadline) => self.sleep_until(deadline).await,
                None => core::future::pending().await,
            }
        }
    }

    /// Runs `future` until it completes or `duration` elapses.
    fn timeout<F>(
        &self,
        duration: Duration,
        future: F,
    ) -> impl Future<Output = Result<F::Output, TimeoutElapsed>> + Send
    where
        F: Future + Send,
    {
        let deadline = self.now().checked_add(duration);
        async move {
            match deadline {
                Some(deadline) => self.timeout_at(deadline, future).await,
                None => Ok(future.await),
            }
        }
    }

    /// Runs `future` until it completes or `deadline` is reached.
    ///
    /// The timeout wins if both futures become ready in the same poll. The losing future is
    /// dropped before this method returns.
    fn timeout_at<F>(
        &self,
        deadline: Instant,
        future: F,
    ) -> impl Future<Output = Result<F::Output, TimeoutElapsed>> + Send
    where
        F: Future + Send,
    {
        async move {
            if self.now() >= deadline {
                return Err(TimeoutElapsed);
            }
            let delay = self.sleep_until(deadline).fuse();
            let future = future.fuse();
            futures_util::pin_mut!(delay, future);
            futures_util::select_biased! {
                () = delay => Err(TimeoutElapsed),
                output = future => Ok(output),
            }
        }
    }
}

/// Error returned when a [`TimeDriver`] deadline elapses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeoutElapsed;

impl core::fmt::Display for TimeoutElapsed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("deadline elapsed")
    }
}

impl core::error::Error for TimeoutElapsed {}

/// Tokio-backed default [`TimeDriver`].
///
/// Its trait implementation requires the default `tokio` feature and a Tokio timer context.
#[derive(Clone, Copy, Debug, Default)]
pub struct TokioTimeDriver;

#[cfg(feature = "tokio")]
impl TimeDriver for TokioTimeDriver {
    fn now(&self) -> Instant {
        tokio::time::Instant::now().into_std()
    }

    fn sleep_until(&self, deadline: Instant) -> impl Future<Output = ()> + Send {
        tokio::time::sleep_until(deadline.into())
    }

    fn yield_now(&self) -> impl Future<Output = ()> + Send {
        tokio::task::yield_now()
    }
}

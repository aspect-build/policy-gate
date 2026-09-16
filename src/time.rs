// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::future::Future;
use core::time::Duration;
use std::time::Instant;

use futures_util::FutureExt;

/// Monotonic clock and asynchronous waiting used by a policy gate.
///
/// A driver is a pure clock-domain selector: it carries no per-instance state, and every method
/// is an associated function. A sleep must be cancellation-safe: dropping its future cancels the
/// wait without affecting later sleeps. Per-instance clock state is unsupported — a driver that
/// needs to be distinguished from another of the same type must be a distinct type.
pub trait TimeDriver: Clone + Send + Sync + Sized + 'static {
    /// Returns the current monotonic time.
    #[must_use]
    fn now() -> Instant;

    /// Waits until `deadline` according to the same clock returned by [`TimeDriver::now`].
    #[must_use]
    fn sleep_until(deadline: Instant) -> impl Future<Output = ()> + Send;

    /// Yields execution back to the asynchronous runtime once.
    #[must_use]
    fn yield_now() -> impl Future<Output = ()> + Send;

    /// Waits for `duration` according to this driver.
    #[must_use]
    fn sleep(duration: Duration) -> impl Future<Output = ()> + Send {
        let deadline = Self::now().checked_add(duration);
        async move {
            match deadline {
                Some(deadline) => Self::sleep_until(deadline).await,
                None => core::future::pending().await,
            }
        }
    }

    /// Runs `future` until it completes or `duration` elapses.
    #[must_use]
    fn timeout<F>(
        duration: Duration,
        future: F,
    ) -> impl Future<Output = Result<F::Output, TimeoutElapsed>> + Send
    where
        F: Future + Send,
    {
        let deadline = Self::now().checked_add(duration);
        async move {
            match deadline {
                Some(deadline) => Self::timeout_at(deadline, future).await,
                None => Ok(future.await),
            }
        }
    }

    /// Runs `future` until it completes or `deadline` is reached.
    ///
    /// The timeout wins if both futures become ready in the same poll. The losing future is
    /// dropped before this method returns.
    #[must_use]
    fn timeout_at<F>(
        deadline: Instant,
        future: F,
    ) -> impl Future<Output = Result<F::Output, TimeoutElapsed>> + Send
    where
        F: Future + Send,
    {
        async move {
            if Self::now() >= deadline {
                return Err(TimeoutElapsed);
            }
            let delay = Self::sleep_until(deadline).fuse();
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
    fn now() -> Instant {
        tokio::time::Instant::now().into_std()
    }

    fn sleep_until(deadline: Instant) -> impl Future<Output = ()> + Send {
        tokio::time::sleep_until(deadline.into())
    }

    fn yield_now() -> impl Future<Output = ()> + Send {
        tokio::task::yield_now()
    }
}

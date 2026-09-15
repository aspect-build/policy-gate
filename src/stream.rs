// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::Arc;
use std::time::Instant;

use futures_util::FutureExt;
use futures_util::future::BoxFuture;
use http_body::{Body, Frame, SizeHint};

use crate::gate::{Admission, DecisionSource, Permit, PermitState, Subject};
use crate::layer::{BodySide, GateContext, StreamRejection, StreamRejectionResponse};
use crate::metrics::PolicyGateMetrics;
use crate::time::TimeDriver;

type BoxError = Box<dyn core::error::Error + Send + Sync>;
type Readmission = BoxFuture<'static, Result<Admission, crate::AdmissionUnavailable>>;
type PermitTransition = BoxFuture<'static, Permit>;

/// Body wrapper that cuts active streams when their subject becomes denied.
#[pin_project::pin_project]
pub(crate) struct EnforcedBody<
    B,
    T: Subject,
    C: DecisionSource<T>,
    M: PolicyGateMetrics,
    R: StreamRejectionResponse,
    D,
> {
    #[pin]
    inner: B,
    subject: T,
    permit: Option<Permit>,
    transition: Option<PermitTransition>,
    context: Arc<GateContext<T, C, M, D>>,
    response: R,
    // Polled once per frame so policy recovery does not stall the stream.
    readmission: Option<Readmission>,
    // Suppresses another attempt until one admission budget has elapsed.
    last_readmission_failure: Option<Instant>,
    side: BodySide,
    ended: bool,
}

impl<
    B,
    T: Subject,
    C: DecisionSource<T>,
    M: PolicyGateMetrics,
    R: StreamRejectionResponse,
    D: TimeDriver,
> EnforcedBody<B, T, C, M, R, D>
{
    /// Wraps one request or response body with subject context.
    pub(crate) fn new(
        inner: B,
        subject: T,
        permit: Permit,
        context: Arc<GateContext<T, C, M, D>>,
        response: R,
        side: BodySide,
    ) -> Self {
        Self {
            inner,
            subject,
            permit: Some(permit),
            transition: None,
            context,
            response,
            readmission: None,
            last_readmission_failure: None,
            side,
            ended: false,
        }
    }
}

impl<B, T, C, M, R, D> Body for EnforcedBody<B, T, C, M, R, D>
where
    B: Body,
    B::Error: Into<BoxError>,
    T: Subject,
    C: DecisionSource<T> + 'static,
    M: PolicyGateMetrics,
    R: StreamRejectionResponse,
    D: TimeDriver,
{
    type Data = B::Data;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();
        if *this.ended {
            return Poll::Ready(None);
        }

        loop {
            if let Some(transition) = this.transition.as_mut() {
                match transition.as_mut().poll(cx) {
                    Poll::Pending => {
                        return poll_inner_terminal(this.inner.as_mut(), cx, this.ended);
                    }
                    Poll::Ready(permit) => {
                        *this.transition = None;
                        *this.permit = Some(permit);
                    }
                }
            }

            match this.permit.as_ref().expect("permit is present").state() {
                PermitState::Allowed => {
                    match poll_inner_terminal(this.inner.as_mut(), cx, this.ended) {
                        Poll::Pending => {
                            let mut permit = this.permit.take().expect("permit is present");
                            *this.transition = Some(
                                async move {
                                    permit.changed().await;
                                    permit
                                }
                                .boxed(),
                            );
                        }
                        ready @ Poll::Ready(_) => return ready,
                    }
                }
                PermitState::Denied => break,
                PermitState::Stale => {
                    if let Some(admission) = this.context.gate.try_cached(this.subject) {
                        *this.readmission = None;
                        *this.last_readmission_failure = None;
                        match admission {
                            Admission::Allowed(permit) => {
                                *this.permit = Some(permit);
                                continue;
                            }
                            Admission::Denied => break,
                        }
                    }
                    if this.readmission.is_none() {
                        let cooldown_elapsed = match *this.last_readmission_failure {
                            Some(failed_at) => {
                                this.context.gate.now().saturating_duration_since(failed_at)
                                    >= this.context.gate.admission_timeout()
                            }
                            None => true,
                        };
                        if cooldown_elapsed {
                            let gate = this.context.gate.clone();
                            let subject = (*this.subject).clone();
                            *this.readmission =
                                Some(async move { gate.admit(subject).await }.boxed());
                        }
                    }
                    // Admission is polled once per frame, so it never makes this body pending.
                    if let Some(readmission) = this.readmission.as_mut() {
                        match readmission.as_mut().poll(cx) {
                            Poll::Pending => {}
                            Poll::Ready(result) => {
                                *this.readmission = None;
                                match result {
                                    Ok(Admission::Allowed(permit)) => {
                                        *this.permit = Some(permit);
                                        *this.last_readmission_failure = None;
                                        continue;
                                    }
                                    Ok(Admission::Denied) => {
                                        *this.last_readmission_failure = None;
                                        break;
                                    }
                                    Err(_) => {
                                        *this.last_readmission_failure =
                                            Some(this.context.gate.now());
                                    }
                                }
                            }
                        }
                    }
                    return poll_inner_terminal(this.inner.as_mut(), cx, this.ended);
                }
            }
        }

        *this.ended = true;
        this.context.metrics.stream_cutoff();
        match this
            .response
            .stream_denied(*this.side, &this.context.rejection_message)
        {
            StreamRejection::Trailers(trailers) => Poll::Ready(Some(Ok(Frame::trailers(trailers)))),
            StreamRejection::Error(error) => Poll::Ready(Some(Err(error))),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.ended
    }

    fn size_hint(&self) -> SizeHint {
        if self.ended {
            SizeHint::with_exact(0)
        } else {
            // A future denial can truncate all remaining data.
            SizeHint::new()
        }
    }
}

fn poll_inner_terminal<B: Body>(
    inner: Pin<&mut B>,
    cx: &mut Context<'_>,
    ended: &mut bool,
) -> Poll<Option<Result<Frame<B::Data>, BoxError>>>
where
    B::Error: Into<BoxError>,
{
    match inner.poll_frame(cx) {
        Poll::Ready(None) => {
            *ended = true;
            Poll::Ready(None)
        }
        Poll::Ready(Some(Ok(frame))) => {
            if frame.is_trailers() {
                *ended = true;
            }
            Poll::Ready(Some(Ok(frame)))
        }
        Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error.into()))),
        Poll::Pending => Poll::Pending,
    }
}

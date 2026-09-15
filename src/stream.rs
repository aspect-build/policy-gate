// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::Arc;

use futures_util::FutureExt;
use futures_util::future::BoxFuture;
use http_body::{Body, Frame, SizeHint};

use crate::gate::{Admission, AdmissionState, DecisionSource, Observed, Subject};
use crate::layer::{BodySide, BoxBodyError, GateContext, StreamRejection, StreamRejectionResponse};
use crate::metrics::PolicyGateMetrics;
use crate::time::TimeDriver;

type Readmission<D> = BoxFuture<'static, Result<Admission<D>, crate::AdmissionUnavailable>>;

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
    admission: Admission<D>,
    context: Arc<GateContext<T, C, M, D>>,
    response: R,
    // Polled once per frame so policy recovery does not stall the stream.
    readmission: Option<Readmission<D>>,
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
        admission: Admission<D>,
        context: Arc<GateContext<T, C, M, D>>,
        response: R,
        side: BodySide,
    ) -> Self {
        Self {
            inner,
            subject,
            admission,
            context,
            response,
            readmission: None,
            side,
            ended: false,
        }
    }
}

impl<B, T, C, M, R, D> Body for EnforcedBody<B, T, C, M, R, D>
where
    B: Body,
    B::Error: Into<BoxBodyError>,
    T: Subject,
    C: DecisionSource<T> + 'static,
    M: PolicyGateMetrics,
    R: StreamRejectionResponse,
    D: TimeDriver,
{
    type Data = B::Data;
    type Error = BoxBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();
        if *this.ended {
            return Poll::Ready(None);
        }

        loop {
            // Recheck on every body poll. No change observer wakes an idle connection.
            match this.admission.observe() {
                Observed::Allowed => {
                    return poll_inner_terminal(this.inner.as_mut(), cx, this.ended);
                }
                Observed::Denied | Observed::Expired => break,
                Observed::Stale => {
                    if let Some(admission) = this.context.gate.try_cached(this.subject) {
                        *this.readmission = None;
                        if admission.is_allowed() {
                            *this.admission = admission;
                            continue;
                        }
                        if admission.state() == AdmissionState::Denied {
                            break;
                        }
                    }
                    if this.readmission.is_none() {
                        let gate = this.context.gate.clone();
                        let subject = (*this.subject).clone();
                        *this.readmission = Some(async move { gate.admit(&subject).await }.boxed());
                    }
                    // Admission is polled once per frame, so it never makes this body pending.
                    if let Some(readmission) = this.readmission.as_mut() {
                        match readmission.as_mut().poll(cx) {
                            Poll::Pending => {}
                            Poll::Ready(result) => {
                                *this.readmission = None;
                                match result {
                                    Ok(admission) if admission.is_allowed() => {
                                        *this.admission = admission;
                                        continue;
                                    }
                                    Ok(admission)
                                        if admission.state() == AdmissionState::Denied =>
                                    {
                                        break;
                                    }
                                    Ok(_) => continue,
                                    Err(_) => {
                                        let gate = this.context.gate.clone();
                                        let subject = (*this.subject).clone();
                                        let delay = gate.admission_timeout();
                                        *this.readmission = Some(
                                            async move { gate.admit_after(&subject, delay).await }
                                                .boxed(),
                                        );
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
) -> Poll<Option<Result<Frame<B::Data>, BoxBodyError>>>
where
    B::Error: Into<BoxBodyError>,
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

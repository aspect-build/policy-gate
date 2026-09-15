// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use http::header::{CONTENT_TYPE, HeaderValue};
use http::{HeaderMap, Response};

use crate::{
    AdmissionUnavailable, BodyAdapter, BodySide, RejectionResponse, StreamRejection,
    StreamRejectionResponse,
};

/// Renders enforcement failures using tonic's gRPC status encoding.
///
/// Every rejection is an HTTP 200 response whose gRPC status lives in the headers, so gRPC clients
/// see a status rather than a transport error:
///
/// | Outcome | gRPC code |
/// | --- | --- |
/// | denied | `FAILED_PRECONDITION` |
/// | missing subject | `FAILED_PRECONDITION` |
/// | unavailable | `UNAVAILABLE` |
///
/// A denial that lands mid-stream ends a response body with `FAILED_PRECONDITION` trailers, and
/// fails a request body with the equivalent [`tonic::Status`] error.
///
/// Requires the `tonic-layer` feature.
#[derive(Clone, Copy, Debug, Default)]
pub struct TonicRejectionResponse;

impl<A: BodyAdapter> RejectionResponse<A> for TonicRejectionResponse {
    fn denied(self, body: A, message: &str) -> Response<A::Body> {
        status_response(body, tonic::Code::FailedPrecondition, message)
    }

    fn missing_subject(self, body: A, message: &str) -> Response<A::Body> {
        status_response(body, tonic::Code::FailedPrecondition, message)
    }

    fn unavailable(
        self,
        body: A,
        _error: AdmissionUnavailable,
        message: &str,
    ) -> Response<A::Body> {
        status_response(body, tonic::Code::Unavailable, message)
    }
}

impl StreamRejectionResponse for TonicRejectionResponse {
    fn stream_denied(self, side: BodySide, message: &str) -> StreamRejection {
        match side {
            BodySide::Response => {
                StreamRejection::Trailers(status_headers(tonic::Code::FailedPrecondition, message))
            }
            BodySide::Request => StreamRejection::Error(
                tonic::Status::failed_precondition(message.to_owned()).into(),
            ),
        }
    }
}

fn status_response<A: BodyAdapter>(body: A, code: tonic::Code, message: &str) -> Response<A::Body> {
    let status = tonic::Status::new(code, message.to_owned());
    let mut response = Response::new(body.make_body(bytes::Bytes::new()));
    status
        .add_header(response.headers_mut())
        .expect("tonic status creates valid gRPC response headers");
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/grpc"));
    response
}

fn status_headers(code: tonic::Code, message: &str) -> HeaderMap {
    let status = tonic::Status::new(code, message.to_owned());
    let mut headers = HeaderMap::with_capacity(2);
    status
        .add_header(&mut headers)
        .expect("tonic status creates valid gRPC trailer headers");
    headers
}

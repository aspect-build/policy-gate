// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

//! Runs an Axum service with authentication before policy enforcement.
//!
//! The authentication middleware owns token parsing and validation. It inserts a trusted subject
//! into the request extensions only after validation succeeds. `PolicyGateLayer` reads that
//! extension; it never handles credentials itself.

use core::future::Future;
use std::sync::Arc;

use axum::Router;
use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::get;
use futures_util::stream::{self, Pending};
use policy_gate::{
    AxumBodyAdapter, Decision, DecisionChange, DecisionSource, DecisionSourceError, PolicyGate,
    PolicyGateConfig, PolicyGateLayer, PolicyGateLayerConfig, RequestPolicy,
};

#[derive(Clone)]
struct AuthenticatedSubject(String);

#[derive(Clone, Copy)]
struct SubjectFromAuthentication;

impl RequestPolicy<String> for SubjectFromAuthentication {
    fn subject<B>(&self, request: &http::Request<B>) -> Option<String> {
        request
            .extensions()
            .get::<AuthenticatedSubject>()
            .map(|subject| subject.0.clone())
    }

    fn enforce_request_body<B>(&self, _request: &http::Request<B>) -> bool {
        false
    }
}

struct ExampleDecisionSource;

impl DecisionSource<String> for ExampleDecisionSource {
    type Changes = Pending<Result<DecisionChange<String>, DecisionSourceError>>;

    fn get_subject_decision(
        &self,
        subject: &String,
    ) -> impl Future<Output = Result<Option<Decision>, DecisionSourceError>> + Send {
        let decision = if subject == "user-123" {
            Decision::Allowed
        } else {
            Decision::Denied
        };
        async move { Ok(Some(decision)) }
    }

    fn watch_subject_decisions(
        &self,
    ) -> impl Future<Output = Result<Self::Changes, DecisionSourceError>> + Send {
        core::future::ready(Ok(stream::pending()))
    }
}

async fn authenticate(mut request: Request, next: Next) -> Result<Response, StatusCode> {
    let subject = validate_bearer(request.headers()).ok_or(StatusCode::UNAUTHORIZED)?;
    request.extensions_mut().insert(subject);
    Ok(next.run(request).await)
}

fn validate_bearer(headers: &HeaderMap) -> Option<AuthenticatedSubject> {
    let token = headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")?;

    // Replace this demonstration check with signature, issuer, audience, and expiry validation.
    (token == "example-token").then(|| AuthenticatedSubject("user-123".to_owned()))
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let config = PolicyGateConfig::builder()
        .build()
        .expect("default gate configuration is valid");
    let (gate, watcher, _health) = PolicyGate::new(&config, Arc::new(ExampleDecisionSource));
    tokio::spawn(watcher);

    let gate_layer = PolicyGateLayer::new(
        gate,
        &PolicyGateLayerConfig::new(
            "the authenticated subject is not allowed",
            "authentication did not provide a subject",
        ),
        SubjectFromAuthentication,
        AxumBodyAdapter,
    );

    // Layers run from bottom to top: authentication validates and inserts the subject before the
    // policy gate reads it.
    let app = Router::new()
        .route("/", get(|| async { "allowed" }))
        .layer(gate_layer)
        .layer(middleware::from_fn(authenticate));

    let address = std::env::var("POLICY_GATE_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".to_owned());
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .expect("bind example listener");
    let address = listener.local_addr().expect("read listener address");
    println!("try: curl -H 'authorization: Bearer example-token' http://{address}/");
    axum::serve(listener, app).await.expect("serve example");
}

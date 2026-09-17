// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

#![cfg(feature = "tonic-server")]

use core::pin::Pin;

use futures_core::Stream;
use policy_gate::policy_proto::policy_authority_server::{PolicyAuthority, PolicyAuthorityServer};
use policy_gate::policy_proto::{
    GetSubjectDecisionRequest, GetSubjectDecisionResponse, SubjectDecisionChange,
    WatchSubjectDecisionsRequest,
};
use tonic::{Request, Response, Status};

struct StubAuthority(&'static str);

#[tonic::async_trait]
impl PolicyAuthority for StubAuthority {
    async fn get_subject_decision(
        &self,
        _request: Request<GetSubjectDecisionRequest>,
    ) -> Result<Response<GetSubjectDecisionResponse>, Status> {
        Ok(Response::new(GetSubjectDecisionResponse {
            decision: 1,
            scope: self.0.into(),
        }))
    }

    type WatchSubjectDecisionsStream =
        Pin<Box<dyn Stream<Item = Result<SubjectDecisionChange, Status>> + Send>>;

    async fn watch_subject_decisions(
        &self,
        _request: Request<WatchSubjectDecisionsRequest>,
    ) -> Result<Response<Self::WatchSubjectDecisionsStream>, Status> {
        Ok(Response::new(Box::pin(tokio_stream::iter([Ok(
            SubjectDecisionChange {
                subject_id: "tenant".into(),
                decision: 1,
                scope: self.0.into(),
            },
        )]))))
    }
}

#[test]
fn public_bindings_construct_a_policy_authority_server() {
    let _server = PolicyAuthorityServer::new(StubAuthority("cache"));
}

#[cfg(feature = "tonic-client")]
#[tokio::test]
async fn unary_and_watch_require_exact_scope_echoes() -> Result<(), Box<dyn std::error::Error>> {
    use policy_gate::{DecisionSource, DecisionSourceErrorKind, TonicDecisionSource};
    use tokio_stream::StreamExt;

    for echo in ["cache", "", "bes"] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let incoming = futures_util::stream::unfold(listener, |listener| async {
            Some((listener.accept().await.map(|(socket, _)| socket), listener))
        });
        let server = tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(PolicyAuthorityServer::new(StubAuthority(echo)))
                .serve_with_incoming(incoming),
        );
        let channel = tonic::transport::Endpoint::from_shared(endpoint)?
            .connect()
            .await?;
        let source = TonicDecisionSource::<String>::from_channel(channel, "cache");
        let unary = source.get_subject_decision(&"tenant".to_owned()).await;
        let change = source
            .watch_subject_decisions()
            .await?
            .next()
            .await
            .ok_or("watch closed")?;
        if echo == "cache" {
            assert!(unary.is_ok());
            assert!(change.is_ok());
        } else {
            assert_eq!(unary.unwrap_err().kind(), DecisionSourceErrorKind::Wire);
            assert_eq!(change.unwrap_err().kind(), DecisionSourceErrorKind::Wire);
        }
        server.abort();
    }
    Ok(())
}

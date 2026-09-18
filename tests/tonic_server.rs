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

const OPAQUE_PAYLOAD: &str = "not JSON: \0\r\n café 🐄 ";

struct StubAuthority(&'static str);

#[tonic::async_trait]
impl PolicyAuthority for StubAuthority {
    async fn get_subject_decision(
        &self,
        request: Request<GetSubjectDecisionRequest>,
    ) -> Result<Response<GetSubjectDecisionResponse>, Status> {
        let subject = request.into_inner().subject_id;
        let decision = match subject.as_str() {
            "denied" => 2,
            "unspecified" => 0,
            "unknown" => 99,
            "permanent" => return Err(Status::permission_denied("rejected")),
            "transient" => return Err(Status::unavailable("retry")),
            _ => 1,
        };
        Ok(Response::new(GetSubjectDecisionResponse {
            decision,
            scope: self.0.into(),
            payload: if subject == "tenant" {
                String::new()
            } else {
                OPAQUE_PAYLOAD.into()
            },
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
        let with_payload = source
            .get_subject_decision_with_payload(&"opaque".to_owned())
            .await;
        let change = source
            .watch_subject_decisions()
            .await?
            .next()
            .await
            .ok_or("watch closed")?;
        if echo == "cache" {
            assert!(unary.is_ok());
            assert!(with_payload.is_ok());
            assert!(change.is_ok());
        } else {
            assert_eq!(unary.unwrap_err().kind(), DecisionSourceErrorKind::Wire);
            assert_eq!(
                with_payload.err().unwrap().kind(),
                DecisionSourceErrorKind::Wire
            );
            assert_eq!(change.unwrap_err().kind(), DecisionSourceErrorKind::Wire);
        }
        server.abort();
    }
    Ok(())
}

#[cfg(feature = "tonic-client")]
#[tokio::test]
async fn raw_payload_is_opt_in_and_preserves_unary_validation()
-> Result<(), Box<dyn std::error::Error>> {
    use policy_gate::{Decision, DecisionSource, DecisionSourceErrorKind, TonicDecisionSource};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let incoming = futures_util::stream::unfold(listener, |listener| async {
        Some((listener.accept().await.map(|(socket, _)| socket), listener))
    });
    let server = tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(PolicyAuthorityServer::new(StubAuthority("cache")))
            .serve_with_incoming(incoming),
    );
    let channel = tonic::transport::Endpoint::from_shared(endpoint)?
        .connect()
        .await?;
    let source = TonicDecisionSource::<String>::from_channel(channel, "cache");

    for (subject, decision) in [
        ("opaque", Decision::Allowed),
        ("denied", Decision::Denied),
        ("tenant", Decision::Allowed),
    ] {
        let subject = subject.to_owned();
        let result = source
            .get_subject_decision_with_payload(&subject)
            .await?
            .ok_or("missing decision")?;
        assert_eq!(result.decision, decision);
        assert!(result.valid_until.is_none());
        if subject == "tenant" {
            // An empty proto3 string is omitted on the wire, exactly as in an old authority's response.
            assert!(result.payload.is_none());
        } else {
            assert_eq!(
                result.payload.as_deref().map(String::as_bytes),
                Some(OPAQUE_PAYLOAD.as_bytes())
            );
        }
        assert_eq!(source.get_subject_decision(&subject).await?, Some(decision));
        let unit = source
            .get_subject_decision_result(&subject)
            .await?
            .ok_or("missing decision")?;
        assert_eq!(unit.decision, decision);
        assert!(unit.payload.is_none());
        assert!(unit.valid_until.is_none());
    }
    let subject = "unspecified".to_owned();
    assert!(
        source
            .get_subject_decision_with_payload(&subject)
            .await?
            .is_none()
    );
    assert!(source.get_subject_decision(&subject).await?.is_none());
    for (subject, kind) in [
        ("unknown", DecisionSourceErrorKind::Wire),
        ("permanent", DecisionSourceErrorKind::Permanent),
        ("transient", DecisionSourceErrorKind::Transient),
    ] {
        let subject = subject.to_owned();
        assert_eq!(
            source
                .get_subject_decision_with_payload(&subject)
                .await
                .err()
                .ok_or("expected error")?
                .kind(),
            kind
        );
        assert_eq!(
            source
                .get_subject_decision(&subject)
                .await
                .unwrap_err()
                .kind(),
            kind
        );
    }
    server.abort();
    Ok(())
}

#[test]
fn payload_is_wire_compatible_with_the_old_response_schema() {
    use prost::Message;

    #[derive(Clone, PartialEq, Message)]
    struct OldResponse {
        #[prost(int32, tag = "1")]
        decision: i32,
        #[prost(string, tag = "2")]
        scope: String,
    }

    let old = OldResponse {
        decision: 1,
        scope: "cache".into(),
    };
    let mut new = GetSubjectDecisionResponse::decode(old.encode_to_vec().as_slice()).unwrap();
    assert!(new.payload.is_empty());
    assert_eq!(new.encode_to_vec(), old.encode_to_vec());
    new.payload = OPAQUE_PAYLOAD.into();
    let encoded = new.encode_to_vec();
    assert_eq!(
        GetSubjectDecisionResponse::decode(encoded.as_slice())
            .unwrap()
            .payload
            .as_bytes(),
        OPAQUE_PAYLOAD.as_bytes()
    );
    assert_eq!(OldResponse::decode(encoded.as_slice()).unwrap(), old);
}

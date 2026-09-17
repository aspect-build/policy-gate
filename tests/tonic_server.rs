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

struct StubAuthority;

#[tonic::async_trait]
impl PolicyAuthority for StubAuthority {
    async fn get_subject_decision(
        &self,
        _request: Request<GetSubjectDecisionRequest>,
    ) -> Result<Response<GetSubjectDecisionResponse>, Status> {
        Err(Status::unimplemented("test stub"))
    }

    type WatchSubjectDecisionsStream =
        Pin<Box<dyn Stream<Item = Result<SubjectDecisionChange, Status>> + Send>>;

    async fn watch_subject_decisions(
        &self,
        _request: Request<WatchSubjectDecisionsRequest>,
    ) -> Result<Response<Self::WatchSubjectDecisionsStream>, Status> {
        Err(Status::unimplemented("test stub"))
    }
}

#[test]
fn public_bindings_construct_a_policy_authority_server() {
    let _server = PolicyAuthorityServer::new(StubAuthority);
}

// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use sha2::{Digest, Sha256};

#[test]
fn canonical_policy_proto_has_expected_sha256() {
    // The pinned hash is of the LF form; Windows checkouts may convert line endings.
    let text = include_str!("../../proto/aspect/policy/gate/v1/policy_authority.proto")
        .replace("\r\n", "\n");
    assert_eq!(
        format!("{:x}", Sha256::digest(text.as_bytes())),
        "416af0c4938fda55d896d18bb6e5ab7759053f86ab7d4d59deda18d118fd974e"
    );
}

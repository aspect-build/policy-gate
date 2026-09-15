// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use sha2::{Digest, Sha256};

#[test]
fn canonical_policy_proto_has_expected_sha256() {
    // The pinned hash is of the LF form; Windows checkouts may convert line endings.
    let text = include_str!("../../proto/aspect/policy/gate/v1/policy_authority.proto")
        .replace("\r\n", "\n");
    assert_eq!(
        format!("{:x}", Sha256::digest(text.as_bytes())),
        "f2311efb3927c8c1254b683644d4c8f70fc1f81873a060a59c925dcf208bae70"
    );
}

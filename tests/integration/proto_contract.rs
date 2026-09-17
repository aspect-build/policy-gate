// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use std::fs;
use std::path::PathBuf;

#[test]
fn canonical_policy_proto_matches_generated_rust() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let output = root
        .join("target")
        .join(format!("policy-proto-{}", std::process::id()));
    fs::create_dir_all(&output)
        .unwrap_or_else(|error| panic!("creating output directory: {error}"));

    let mut prost = tonic_prost_build::Config::new();
    prost.protoc_executable(
        protoc_bin_vendored::protoc_bin_path()
            .unwrap_or_else(|error| panic!("locating protoc: {error}")),
    );
    tonic_prost_build::configure()
        .out_dir(&output)
        .client_mod_attribute(
            "aspect.policy.gate.v1",
            "#[cfg(feature = \"tonic-client\")]",
        )
        .server_mod_attribute(
            "aspect.policy.gate.v1",
            "#[cfg(feature = \"tonic-server\")]",
        )
        .compile_with_config(
            prost,
            &[root.join("proto/aspect/policy/gate/v1/policy_authority.proto")],
            &[root.join("proto")],
        )
        .unwrap_or_else(|error| panic!("generating policy proto: {error}"));

    let generated = output.join("aspect.policy.gate.v1.rs");
    let checked_in = root.join("src/policy_proto.rs");
    let generated = format!(
        "// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.\n\n{}",
        fs::read_to_string(&generated)
            .unwrap_or_else(|error| panic!("reading generated policy proto: {error}"))
    );
    if std::env::var_os("UPDATE_POLICY_PROTO").is_some() {
        fs::write(&checked_in, &generated)
            .unwrap_or_else(|error| panic!("updating generated policy proto: {error}"));
    } else {
        assert_eq!(
            fs::read_to_string(&checked_in)
                .unwrap_or_else(|error| panic!("reading checked-in policy proto: {error}"))
                .replace("\r\n", "\n"),
            generated.replace("\r\n", "\n"),
            "src/policy_proto.rs is stale; regenerate it with UPDATE_POLICY_PROTO=1 cargo test --all-features --test integration canonical_policy_proto_matches_generated_rust"
        );
    }
    fs::remove_dir_all(output).unwrap_or_else(|error| panic!("removing output directory: {error}"));
}

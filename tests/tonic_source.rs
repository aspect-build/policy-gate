// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

#![cfg(feature = "tonic-client")]

use core::time::Duration;

use policy_gate::{ScopeEchoPolicy, TonicDecisionSource, TonicDecisionSourceConfig};

#[test]
fn tonic_source_configuration_is_strict_by_default() {
    let config = TonicDecisionSourceConfig::new("http://authority.test:50051", "bes");

    assert_eq!(config.endpoint(), "http://authority.test:50051");
    assert_eq!(config.scope(), "bes");
    assert_eq!(config.connect_timeout(), Duration::from_secs(2));
    assert_eq!(config.scope_echo_policy(), ScopeEchoPolicy::Strict);
}

#[test]
fn tonic_source_configuration_exposes_rollout_compatibility() {
    let config = TonicDecisionSourceConfig::new("http://authority.test:50051", "bes")
        .with_connect_timeout(Duration::from_secs(3))
        .with_scope_echo_policy(ScopeEchoPolicy::AllowEmpty);

    assert_eq!(config.connect_timeout(), Duration::from_secs(3));
    assert_eq!(config.scope_echo_policy(), ScopeEchoPolicy::AllowEmpty);
}

#[test]
fn tonic_source_rejects_an_invalid_endpoint() {
    let config = TonicDecisionSourceConfig::new("not a URI", "bes");

    TonicDecisionSource::<String>::connect_lazy(&config).expect_err("endpoint must be validated");
}

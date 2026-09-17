// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

#![cfg(feature = "tonic-client")]

use core::time::Duration;

use policy_gate::{TonicDecisionSource, TonicDecisionSourceConfig};

#[test]
fn tonic_source_configuration_defaults() {
    let config = TonicDecisionSourceConfig::new("http://authority.test:50051", "bes");

    assert_eq!(config.endpoint(), "http://authority.test:50051");
    assert_eq!(config.scope(), "bes");
    assert_eq!(config.connect_timeout(), Duration::from_secs(2));
}

#[test]
fn tonic_source_rejects_an_invalid_endpoint() {
    let config = TonicDecisionSourceConfig::new("not a URI", "bes");

    TonicDecisionSource::<String>::connect_lazy(&config).expect_err("endpoint must be validated");
}

// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::time::Duration;

use policy_gate::{
    ConfigError, DEFAULT_ADMISSION_TIMEOUT, DEFAULT_INITIAL_ADMISSION_RETRY_DELAY,
    DEFAULT_INITIAL_RECONNECT_DELAY, DEFAULT_MAX_ADMISSION_RETRY_DELAY,
    DEFAULT_MAX_RECONNECT_DELAY, DEFAULT_MAX_SUBJECTS, DEFAULT_PERMANENT_FAILURE_COOLDOWN,
    DEFAULT_SNAPSHOT_REPUBLISH_INTERVAL, DEFAULT_SUBJECT_TTL, DEFAULT_UNARY_TIMEOUT,
    DEFAULT_WATCH_EVENTS_PER_YIELD, PolicyGateConfig, PolicyGateConfigBuilder,
    PolicyGateLayerConfig, Subject,
};

const fn config() -> PolicyGateConfigBuilder {
    PolicyGateConfig::builder()
}

#[test]
fn builder_uses_public_defaults() {
    let defaults = config().build().expect("defaults validate");
    assert_eq!(defaults.unary_timeout(), DEFAULT_UNARY_TIMEOUT);
    assert_eq!(defaults.admission_timeout(), DEFAULT_ADMISSION_TIMEOUT);
    assert_eq!(
        defaults.initial_admission_retry_delay(),
        DEFAULT_INITIAL_ADMISSION_RETRY_DELAY
    );
    assert_eq!(
        defaults.max_admission_retry_delay(),
        DEFAULT_MAX_ADMISSION_RETRY_DELAY
    );
    assert_eq!(
        defaults.permanent_failure_cooldown(),
        DEFAULT_PERMANENT_FAILURE_COOLDOWN
    );
    assert_eq!(
        defaults.snapshot_republish_interval(),
        DEFAULT_SNAPSHOT_REPUBLISH_INTERVAL
    );
    assert_eq!(
        defaults.initial_reconnect_delay(),
        DEFAULT_INITIAL_RECONNECT_DELAY
    );
    assert_eq!(defaults.max_reconnect_delay(), DEFAULT_MAX_RECONNECT_DELAY);
    assert_eq!(
        defaults.watch_events_per_yield(),
        DEFAULT_WATCH_EVENTS_PER_YIELD
    );
    assert_eq!(defaults.max_subjects(), DEFAULT_MAX_SUBJECTS);
    assert_eq!(defaults.subject_ttl(), DEFAULT_SUBJECT_TTL);
    assert_eq!(defaults.decision_freshness_ttl(), None);
}

#[test]
fn layer_configuration_preserves_rejection_messages() {
    let layer = PolicyGateLayerConfig::new("denied", "subject is required");
    assert_eq!(layer.denied_message(), "denied");
    assert_eq!(layer.missing_subject_message(), "subject is required");
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct OpaqueSubject(u64);

#[test]
fn core_subject_does_not_require_string_conversion() {
    fn assert_subject<T: Subject>() {}
    assert_subject::<OpaqueSubject>();
}

fn assert_config_error(builder: PolicyGateConfigBuilder, expected: ConfigError) {
    assert_eq!(
        builder.build().expect_err("configuration must fail"),
        expected
    );
}

#[test]
fn unary_timeout_cannot_exceed_admission_timeout() {
    assert_config_error(
        config()
            .unary_timeout(Duration::from_secs(3))
            .admission_timeout(Duration::from_secs(2)),
        ConfigError::UnaryExceedsAdmission,
    );
}

#[test]
fn admission_timeout_must_fit_an_instant_deadline() {
    assert_config_error(
        config().admission_timeout(Duration::MAX),
        ConfigError::AdmissionDeadlineOverflow,
    );
}

#[test]
fn admission_retry_delays_must_be_positive_and_ordered() {
    assert_config_error(
        config().initial_admission_retry_delay(Duration::ZERO),
        ConfigError::InitialAdmissionRetryDelayZero,
    );
    assert_config_error(
        config()
            .initial_admission_retry_delay(Duration::from_secs(2))
            .max_admission_retry_delay(Duration::from_secs(1)),
        ConfigError::InitialRetryExceedsMaximum,
    );
}

#[test]
fn snapshot_republish_interval_must_fit_an_instant_deadline() {
    assert_config_error(
        config().snapshot_republish_interval(Duration::MAX),
        ConfigError::DurationOverflow("snapshot republish interval"),
    );
}

#[test]
fn reconnect_delays_must_be_positive_and_ordered() {
    assert_config_error(
        config().initial_reconnect_delay(Duration::ZERO),
        ConfigError::InitialReconnectDelayZero,
    );
    assert_config_error(
        config()
            .initial_reconnect_delay(Duration::from_secs(2))
            .max_reconnect_delay(Duration::from_secs(1)),
        ConfigError::InitialReconnectExceedsMaximum,
    );
}

#[test]
fn watcher_yield_batch_must_be_positive() {
    assert_config_error(
        config().watch_events_per_yield(0),
        ConfigError::WatchEventsPerYieldZero,
    );
}

#[test]
fn maximum_subject_count_must_be_positive() {
    let error = config()
        .max_subjects(0)
        .build()
        .expect_err("zero subject capacity must fail");
    assert_eq!(error, ConfigError::MaxSubjectsZero);
    assert!(error.to_string().contains("greater than zero"));
}

#[test]
fn decision_freshness_ttl_is_independently_optional() {
    let configured = config()
        .decision_freshness_ttl(Duration::from_secs(30))
        .build()
        .expect("freshness TTL validates without another setting");
    assert_eq!(
        configured.decision_freshness_ttl(),
        Some(Duration::from_secs(30))
    );
}

#[test]
fn decision_freshness_ttl_must_be_positive() {
    assert_config_error(
        config().decision_freshness_ttl(Duration::ZERO),
        ConfigError::DecisionFreshnessTtlZero,
    );
}

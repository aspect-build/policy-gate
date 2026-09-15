// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::time::Duration;

use axum_core::body::Body;
use http::Request;
use policy_gate::{
    ConfigError, DEFAULT_ADMISSION_TIMEOUT, DEFAULT_INITIAL_ADMISSION_RETRY_DELAY,
    DEFAULT_INITIAL_RECONNECT_DELAY, DEFAULT_MAX_ADMISSION_RETRY_DELAY,
    DEFAULT_MAX_RECONNECT_DELAY, DEFAULT_MAX_SUBJECTS, DEFAULT_PERMANENT_FAILURE_COOLDOWN,
    DEFAULT_SNAPSHOT_REPUBLISH_INTERVAL, DEFAULT_SUBJECT_TTL, DEFAULT_UNARY_TIMEOUT,
    DEFAULT_WATCH_EVENTS_PER_YIELD, PolicyGateConfig, PolicyGateConfigBuilder, RequestPolicy,
    Subject,
};
#[cfg(feature = "tonic-client")]
use policy_gate::{PolicyGateLayerConfig, TonicDecisionSourceConfig};

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
}

#[test]
#[cfg(feature = "tonic-client")]
fn transport_and_layer_configuration_are_separate_from_the_engine() {
    let tonic =
        TonicDecisionSourceConfig::new("https://source.example.test", "org.example/build-events");
    let layer = PolicyGateLayerConfig::new("denied", "subject is required");
    assert_eq!(tonic.scope(), "org.example/build-events");
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

#[test]
fn timeouts_and_subject_ttl_are_bounded() {
    let error = config()
        .unary_timeout(Duration::from_secs(3))
        .admission_timeout(Duration::from_secs(2))
        .build()
        .expect_err("unary timeout beyond admission deadline must fail");
    assert_eq!(error, ConfigError::UnaryExceedsAdmission);
    assert!(error.to_string().contains("must not exceed"));

    let error = config()
        .admission_timeout(Duration::MAX)
        .build()
        .expect_err("an admission deadline that Instant cannot represent must fail");
    assert_eq!(error, ConfigError::AdmissionDeadlineOverflow);
    assert!(error.to_string().contains("Instant deadline"));

    let error = config()
        .initial_admission_retry_delay(Duration::ZERO)
        .build()
        .expect_err("zero initial retry delay must fail");
    assert_eq!(error, ConfigError::InitialAdmissionRetryDelayZero);

    let error = config()
        .initial_admission_retry_delay(Duration::from_secs(2))
        .max_admission_retry_delay(Duration::from_secs(1))
        .build()
        .expect_err("initial retry delay beyond its maximum must fail");
    assert_eq!(error, ConfigError::InitialRetryExceedsMaximum);

    let error = config()
        .snapshot_republish_interval(Duration::MAX)
        .build()
        .expect_err("an unrepresentable snapshot interval must fail");
    assert_eq!(
        error,
        ConfigError::DurationOverflow("snapshot republish interval")
    );

    let error = config()
        .initial_reconnect_delay(Duration::ZERO)
        .build()
        .expect_err("zero initial reconnect delay must fail");
    assert_eq!(error, ConfigError::InitialReconnectDelayZero);

    let error = config()
        .initial_reconnect_delay(Duration::from_secs(2))
        .max_reconnect_delay(Duration::from_secs(1))
        .build()
        .expect_err("initial reconnect delay beyond its maximum must fail");
    assert_eq!(error, ConfigError::InitialReconnectExceedsMaximum);

    let error = config()
        .watch_events_per_yield(0)
        .build()
        .expect_err("zero watch events per yield must fail");
    assert_eq!(error, ConfigError::WatchEventsPerYieldZero);
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

struct StringPolicy;

impl RequestPolicy<String> for StringPolicy {
    fn subject<B>(&self, request: &Request<B>) -> Option<String> {
        request.extensions().get::<String>().cloned()
    }

    fn enforce_request_body<B>(&self, _request: &Request<B>) -> bool {
        false
    }
}

#[test]
fn policy_chooses_its_subject_type() {
    let mut request = Request::new(Body::empty());
    request.extensions_mut().insert("subject-a".to_owned());
    assert_eq!(StringPolicy.subject(&request).as_deref(), Some("subject-a"));
}

# policy-gate

`policy-gate` continuously enforces decisions supplied by an external policy source. It can gate
new work and terminate denied streams when their request or response bodies are next polled.

The core is transport-neutral. Optional features provide Tower middleware, an Axum body adapter,
and a tonic client and response renderer for the included policy-authority protocol.

```rust,no_run
use std::sync::Arc;

use policy_gate::{PolicyGate, PolicyGateConfig};

# async fn example<C>(source: Arc<C>) -> Result<(), Box<dyn std::error::Error>>
# where C: policy_gate::DecisionSource<String> {
let (gate, watcher, _health) = PolicyGate::new(&PolicyGateConfig::builder().build()?, source);
tokio::spawn(watcher);

let admission = gate.admit(&"organization-123".to_owned()).await?;
if admission.is_allowed() {
    // Start work; recheck `admission.is_allowed()` before each subsequent activity.
}
# Ok(())
# }
```

## Features

| Feature | Purpose |
| --- | --- |
| `tokio` | Default `TimeDriver` implementation and convenience constructors |
| `tower-layer` | Transport-neutral Tower middleware and streaming body enforcement |
| `axum-body` | `AxumBodyAdapter` for type-erased Axum bodies |
| `tonic-client` | Scope-bound tonic decision source and private protobuf bindings |
| `tonic-layer` | gRPC rejection and stream-termination rendering |

The default feature set enables Tokio scheduling and the tonic decision source. Enable only the
runtime and transport adapters a service uses; use `default-features = false` for the core gate.

## HTTP middleware example

[`examples/http_middleware.rs`](examples/http_middleware.rs) shows an Axum service with two
separate middleware stages: authentication validates a bearer token and inserts a trusted subject
into request extensions, then `PolicyGateLayer` admits that subject and checks current policy
before forwarding each body frame. Run it with:

```shell
cargo run --example http_middleware --features axum-body
```

## Runtime contract

The `DecisionWatcher` returned by `PolicyGate::new` must be continuously polled. Dropping the
watcher future, including by aborting the task that polls it, stops new admissions and marks existing
admission handles stale. Dropping a Tokio task's `JoinHandle` only detaches the task and does not
cancel it. Decision-source loss fails new admission closed after the configured deadline; already
admitted streams observe `Stale` and may continue while readmission is attempted.

Admission handles expose synchronous `state()`, `is_allowed()`, and `check()` checks. Authority changes
never wake an otherwise idle connection: denial is enforced on its next body poll, and ordinary
stale state starts readmission then. `PolicyGate::admit()` is the async coordination point and
concurrent calls for the same subject join one in-flight authority lookup.

## Decision freshness

`subject_ttl` remains a sliding idle-cache eviction policy. Absolute decision freshness is a
separate opt-in safeguard configured with a finite freshness TTL. A refresh window can additionally
refresh cached decisions on access shortly before expiry.

```rust
# use core::time::Duration;
# use policy_gate::PolicyGateConfig;
let config = PolicyGateConfig::builder()
    .decision_freshness_ttl(Duration::from_secs(60))
    .refresh_before_expiry(Duration::from_secs(10))
    .build()?;
# Ok::<(), policy_gate::ConfigError>(())
```

Admission handles carry the gate's concrete time driver as `Admission<D>` (defaulting to
`TokioTimeDriver`). Clock calls are statically dispatched; entries store no driver or clock callback.

The configured freshness deadline starts when a lookup completes, a proactive refresh completes, or an
authoritative watch change arrives;
ordinary cache access does not extend it. `Admission::is_allowed()` returns false for denied,
stale, or expired decisions; `state()` reports expiration as `Stale`. Admission refetches an expired
cached decision. Request and response stream bodies cut off on their next poll after expiration,
before delivering more traffic. With the default zero refresh window, an entirely idle stream stays
idle: there is no expiration timer, background scan, or authority-change observer. With a nonzero
refresh window, the first cache read within that window starts one background lookup. Concurrent
reads do not start another lookup while it is pending. A failed refresh does not extend the
deadline and may be retried by a later read after `permanent_failure_cooldown`, regardless of the
error kind. A zero cooldown permits retry on the next read. Enqueue timeouts and cancellation do
not start a cooldown. A cached access waits at most
`refresh_enqueue_timeout` (100 ms by default) for queue capacity. A new watch decision installs a new
absolute deadline; watch disconnects and eviction retain their existing stale/readmission recovery
behavior. The default `DEFAULT_DECISION_FRESHNESS_TTL` is exactly `Duration::MAX`, a never-expire
sentinel that is not converted into an `Instant`. Freshness and background refresh are disabled by
default, so existing users retain the original request and unary-call behavior.

A source may override `DecisionSource::get_subject_decision_result` and return
`DecisionResult<P> { decision, payload, valid_until }`. `valid_until: None` preserves configured
freshness. `Some(deadline)` caps both decision and payload validity, even when configured freshness
is disabled. Use the gate's `TimeDriver` clock domain and retain the original `Instant` when reusing
a result; each lookup must not restart its lifetime. A result expired at publication uses admission retry
backoff or, during refresh, preserves the prior unexpired snapshot and starts failure cooldown.
A successful result that already lands inside the refresh window waits half its remaining effective
lifetime before becoming refresh-eligible. Results outside that window keep the configured refresh start.
Existing sources implementing only the binary lookup continue to use the default adapter without changes.

For a retained admission on a long-lived outbound Tonic stream, use `check()` on each event and
let the caller spawn `refresh()`. The existing handle observes a successful renewal in place.
Keep at most one refresh task in flight per stream, because the signal stays true until the task
claims the entry. For example, in a handler returning `Result<_, tonic::Status>`:

```rust,ignore
use policy_gate::AdmissionState;

let admission = gate.admit(&subject).await
    .map_err(|_| tonic::Status::unavailable("policy unavailable"))?;
let mut refresh: Option<tokio::task::JoinHandle<()>> = None;
while let Some(event) = outbound.message().await? {
    let (state, refresh_due) = admission.check();
    match state {
        AdmissionState::Allowed => {}
        AdmissionState::Denied => return Err(tonic::Status::failed_precondition("policy denied")),
        AdmissionState::Stale => return Err(tonic::Status::unavailable("policy stale")),
    }
    if refresh_due && refresh.as_ref().is_none_or(tokio::task::JoinHandle::is_finished) {
        refresh = Some(tokio::spawn(gate.refresh(subject.clone(), admission.clone())));
    }
    handle(event).await?;
}
```

`check()` never starts a lookup or renews `subject_ttl`; configure that TTL to cover the
pre-refresh idle interval, or later map activity may evict the entry before its first refresh.
`refresh()` renews the matching entry's idle TTL even outside the refresh window; a mismatched subject or replaced entry is a
no-op. Its future only hands work to the watcher and waits at most `refresh_enqueue_timeout`
for queue capacity. Dropping its task handle detaches it; aborting during enqueue safely releases
the claim. The library spawns no tasks. Choose a refresh window larger than the event gaps you
need to cover: no events means no refresh, and the first event after expiry sees `Stale`.
`state()` and `is_allowed()` remain observation-only. The Tower body wrapper does not start
retained-handle refreshes automatically.

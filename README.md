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

Admission handles expose only synchronous `state()` and `is_allowed()` checks. Authority changes
never wake an otherwise idle connection: denial is enforced on its next body poll, and ordinary
stale state starts readmission then. `PolicyGate::admit()` is the async coordination point and
concurrent calls for the same subject join one in-flight authority lookup.

## Decision freshness

`subject_ttl` remains a sliding idle-cache eviction policy. Absolute decision freshness is a
separate opt-in safeguard configured with a finite freshness TTL.

```rust
# use core::time::Duration;
# use policy_gate::PolicyGateConfig;
let config = PolicyGateConfig::builder()
    .decision_freshness_ttl(Duration::from_secs(60))
    .build()?;
# Ok::<(), policy_gate::ConfigError>(())
```

Admission handles carry the gate's concrete time driver as `Admission<D>` (defaulting to
`TokioTimeDriver`). Clock calls are statically dispatched; entries store no driver or clock callback.

The freshness deadline starts when a lookup completes or an authoritative watch change arrives;
ordinary cache access does not extend it. `Admission::is_allowed()` returns false for denied,
stale, or expired decisions; `state()` reports expiration as `Stale`. Admission refetches an expired
cached decision. Request and response stream bodies cut off on their next poll after expiration,
before delivering more traffic. An entirely idle stream stays idle: there is no expiration timer,
background scan, or authority-change observer. A new watch decision installs a new absolute deadline;
watch disconnects and eviction retain their existing stale/readmission recovery behavior. The default
`DEFAULT_DECISION_FRESHNESS_TTL` is exactly `Duration::MAX`, a never-expire sentinel that is not
converted into an `Instant`. This keeps freshness disabled by default,
so existing users retain the original request and unary-call behavior.

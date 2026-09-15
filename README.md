# policy-gate

`policy-gate` continuously enforces decisions supplied by an external policy source. It can gate
new work and notify or terminate active streams when a subject's decision changes.

The core is transport-neutral. Optional features provide Tower middleware, an Axum body adapter,
and a tonic client and response renderer for the included policy-authority protocol.

```rust,no_run
use std::sync::Arc;

use policy_gate::{Admission, PolicyGate, PolicyGateConfig};

# async fn example<C>(source: Arc<C>) -> Result<(), Box<dyn std::error::Error>>
# where C: policy_gate::DecisionSource<String> {
let (gate, watcher, _health) = PolicyGate::new(&PolicyGateConfig::builder().build()?, source);
tokio::spawn(watcher);

match gate.admit("organization-123".to_owned()).await? {
    Admission::Allowed(mut permit) => {
        // `permit.changed().await` observes later denial or invalidation.
        let _ = &mut permit;
    }
    Admission::Denied => {}
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
into request extensions, then `PolicyGateLayer` admits that subject and observes later policy
changes. Run it with:

```shell
cargo run --example http_middleware --features axum-body
```

## Runtime contract

The `DecisionWatcher` returned by `PolicyGate::new` must be continuously polled. Dropping it stops new
admissions and marks existing permits stale. Decision-source loss fails new admission closed after the
configured deadline; already admitted streams observe `Stale` and may continue while readmission is
attempted.

## Decision freshness

`subject_ttl` remains a sliding idle-cache eviction policy. Absolute decision freshness is a
separate opt-in safeguard: configure both a freshness TTL and a refresh-ahead interval shorter than
that TTL.

```rust
# use core::time::Duration;
# use policy_gate::PolicyGateConfig;
let config = PolicyGateConfig::builder()
    .decision_freshness_ttl(Duration::from_secs(60))
    .decision_refresh_ahead(Duration::from_secs(10))
    .build()?;
# Ok::<(), policy_gate::ConfigError>(())
```

The freshness deadline starts when a lookup completes or an authoritative watch change arrives;
ordinary cache access does not extend it. The watcher proactively makes one refresh lookup when a
subject still has a live permit at the refresh-ahead point. Subjects without live permits are not
refreshed solely for freshness. If no refresh succeeds before the absolute deadline, the cached
decision and its permits become stale and the next admission must fetch a new decision. Freshness
is disabled by default, so existing users keep the original request and unary-call behavior.

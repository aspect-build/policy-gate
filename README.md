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

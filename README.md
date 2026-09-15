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

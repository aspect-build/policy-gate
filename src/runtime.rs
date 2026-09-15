// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use std::sync::Arc;

use crate::PolicyGateConfig;
use crate::gate::{DecisionSource, PolicyGate, Subject};
use crate::layer::{
    BodyAdapter, HttpRejectionResponse, PolicyGateLayer, PolicyGateLayerConfig, RejectionResponse,
    RequestPolicy,
};
use crate::metrics::{NoopPolicyGateMetrics, PolicyGateMetrics};
use crate::time::{TimeDriver, TokioTimeDriver};
use crate::watcher::{DecisionSourceHealth, DecisionWatcher};

/// The one policy-gate runtime shared by every enabled server in a process.
///
/// Bundles the pieces [`PolicyGate::new_with_metrics`] and [`PolicyGateLayer`] would otherwise be
/// wired up by hand, all bound to a single decision source. Destructure it, move `watcher` into a
/// task, clone `layer` into each server, and keep `health` for readiness probes:
///
/// ```
/// use policy_gate::{
///     BodyAdapter, DecisionSource, PolicyGateLayer, PolicyGateRuntime, RequestPolicy, Subject,
/// };
///
/// /// Starts the watch loop and hands back the layer each server applies.
/// fn start<P, T, C, A>(runtime: PolicyGateRuntime<P, T, C, A>) -> PolicyGateLayer<P, T, C, A>
/// where
///     P: RequestPolicy<T>,
///     T: Subject,
///     C: DecisionSource<T>,
///     A: BodyAdapter,
/// {
///     tokio::spawn(runtime.watcher);
///     runtime.layer
/// }
/// ```
///
/// Admissions fail closed until the watcher runs, so spawn it before serving traffic; see the
/// [runtime contract](crate#runtime-contract).
///
/// Requires the `tower-layer` feature.
pub struct PolicyGateRuntime<
    P,
    T,
    C,
    A,
    M = NoopPolicyGateMetrics,
    R = HttpRejectionResponse,
    D = TokioTimeDriver,
> where
    P: RequestPolicy<T>,
    T: Subject,
    C: DecisionSource<T>,
    A: BodyAdapter,
    M: PolicyGateMetrics,
    R: RejectionResponse<A>,
{
    /// Gate for code that admits subjects outside the HTTP path.
    pub gate: PolicyGate<T, C, M, D>,
    /// Middleware layer to apply to each served stack.
    pub layer: PolicyGateLayer<P, T, C, A, M, R, D>,
    /// Watch loop that must be polled for the lifetime of the process.
    pub watcher: DecisionWatcher<T, C, M, D>,
    /// Decision-source connectivity, for health and readiness reporting.
    pub health: Arc<DecisionSourceHealth<D>>,
    /// Copy of the metrics handle the runtime was built with.
    pub metrics: M,
}

impl<P, T, C, A, M, R, D> core::fmt::Debug for PolicyGateRuntime<P, T, C, A, M, R, D>
where
    P: RequestPolicy<T>,
    T: Subject,
    C: DecisionSource<T>,
    A: BodyAdapter,
    M: PolicyGateMetrics,
    R: RejectionResponse<A>,
    D: TimeDriver,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PolicyGateRuntime").finish_non_exhaustive()
    }
}

#[cfg(feature = "tokio")]
impl<P, T, C, A> PolicyGateRuntime<P, T, C, A>
where
    P: RequestPolicy<T>,
    T: Subject,
    C: DecisionSource<T> + 'static,
    A: BodyAdapter,
{
    /// Constructs the runtime around a caller-supplied decision source.
    ///
    /// Discards metrics and renders rejections as plain HTTP.
    #[must_use]
    pub fn new_with_client(
        gate_config: &PolicyGateConfig,
        layer_config: &PolicyGateLayerConfig,
        client: Arc<C>,
        policy: P,
        body: A,
    ) -> Self {
        Self::new_with_client_and_metrics(
            gate_config,
            layer_config,
            client,
            policy,
            body,
            NoopPolicyGateMetrics,
        )
    }
}

#[cfg(feature = "tokio")]
impl<P, T, C, A, M> PolicyGateRuntime<P, T, C, A, M>
where
    P: RequestPolicy<T>,
    T: Subject,
    C: DecisionSource<T> + 'static,
    A: BodyAdapter,
    M: PolicyGateMetrics,
{
    /// Constructs the runtime with caller-owned metric handling.
    ///
    /// Renders rejections as plain HTTP.
    #[must_use]
    pub fn new_with_client_and_metrics(
        gate_config: &PolicyGateConfig,
        layer_config: &PolicyGateLayerConfig,
        client: Arc<C>,
        policy: P,
        body: A,
        metrics: M,
    ) -> Self {
        Self::new_with_client_metrics_and_response(
            gate_config,
            layer_config,
            client,
            policy,
            body,
            metrics,
            HttpRejectionResponse,
        )
    }
}

#[cfg(feature = "tokio")]
impl<P, T, C, A, M, R> PolicyGateRuntime<P, T, C, A, M, R>
where
    P: RequestPolicy<T>,
    T: Subject,
    C: DecisionSource<T> + 'static,
    A: BodyAdapter,
    M: PolicyGateMetrics,
    R: RejectionResponse<A>,
{
    /// Constructs the runtime with caller-owned metrics and response rendering.
    ///
    /// The widest constructor: pass `response` to render rejections for the host transport, such
    /// as `TonicRejectionResponse` from the `tonic-layer` feature.
    #[must_use]
    pub fn new_with_client_metrics_and_response(
        gate_config: &PolicyGateConfig,
        layer_config: &PolicyGateLayerConfig,
        client: Arc<C>,
        policy: P,
        body: A,
        metrics: M,
        response: R,
    ) -> Self {
        Self::new_with_client_metrics_response_and_time_driver(
            gate_config,
            layer_config,
            client,
            policy,
            body,
            metrics,
            response,
            TokioTimeDriver,
        )
    }
}

impl<P, T, C, A, M, R, D> PolicyGateRuntime<P, T, C, A, M, R, D>
where
    P: RequestPolicy<T>,
    T: Subject,
    C: DecisionSource<T> + 'static,
    A: BodyAdapter,
    M: PolicyGateMetrics,
    R: RejectionResponse<A>,
    D: TimeDriver,
{
    /// Constructs the runtime with caller-owned metrics, response rendering, and time driver.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_client_metrics_response_and_time_driver(
        gate_config: &PolicyGateConfig,
        layer_config: &PolicyGateLayerConfig,
        client: Arc<C>,
        policy: P,
        body: A,
        metrics: M,
        response: R,
        time: D,
    ) -> Self {
        let (gate, watcher, health) =
            PolicyGate::new_with_metrics_and_time_driver(gate_config, client, metrics, time);
        let metrics = gate.metrics();
        let layer =
            PolicyGateLayer::new_with_response(gate.clone(), layer_config, policy, body, response);
        Self {
            gate,
            layer,
            watcher,
            health,
            metrics,
        }
    }
}

impl<P, T, C, A, D> PolicyGateRuntime<P, T, C, A, NoopPolicyGateMetrics, HttpRejectionResponse, D>
where
    P: RequestPolicy<T>,
    T: Subject,
    C: DecisionSource<T> + 'static,
    A: BodyAdapter,
    D: TimeDriver,
{
    /// Constructs the runtime with a caller-provided time driver.
    ///
    /// Discards metrics and renders rejections as plain HTTP.
    #[must_use]
    pub fn new_with_client_and_time_driver(
        gate_config: &PolicyGateConfig,
        layer_config: &PolicyGateLayerConfig,
        client: Arc<C>,
        policy: P,
        body: A,
        time: D,
    ) -> Self {
        Self::new_with_client_metrics_response_and_time_driver(
            gate_config,
            layer_config,
            client,
            policy,
            body,
            NoopPolicyGateMetrics,
            HttpRejectionResponse,
            time,
        )
    }
}

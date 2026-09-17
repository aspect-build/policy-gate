// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::marker::PhantomData;
use core::time::Duration;
use std::sync::Arc;

use crate::{
    Decision, DecisionResult, DecisionSource, DecisionSourceError, DecisionSourceErrorKind,
    Subject, TimeDriver, TokioTimeDriver,
};

/// Transforms payloads within the lookup timeout. Sources must supply payloads for validation.
pub trait DecisionTransform<T: Subject>: Send + Sync + 'static {
    type Raw: Send + Sync + 'static;
    type Payload: Send + Sync + 'static;

    /// Returns the value and remaining lifetime from this call's start; `Duration::MAX` adds no cap.
    ///
    /// # Errors
    /// Returns a source error if validation fails.
    fn transform(
        &self,
        subject: &T,
        raw: Arc<Self::Raw>,
    ) -> impl Future<Output = Result<(Self::Payload, Duration), DecisionSourceError>> + Send;
}

/// Transforms payloads inside the existing single flight. `D` must match the gate's clock.
/// Missing payloads skip transformation. Watch changes still clear payloads.
pub struct TransformSource<S, V, D = TokioTimeDriver> {
    source: Arc<S>,
    transform: V,
    _time: PhantomData<D>,
}

impl<S, V, D> TransformSource<S, V, D> {
    #[must_use]
    pub fn new(source: Arc<S>, transform: V) -> Self {
        Self {
            source,
            transform,
            _time: PhantomData,
        }
    }
}

impl<T, S, V, D> DecisionSource<T, V::Payload> for TransformSource<S, V, D>
where
    T: Subject,
    V: DecisionTransform<T>,
    S: DecisionSource<T, V::Raw>,
    D: TimeDriver,
{
    type Changes = S::Changes;

    async fn get_subject_decision(
        &self,
        subject: &T,
    ) -> Result<Option<Decision>, DecisionSourceError> {
        let result = self.get_subject_decision_result(subject).await?;
        Ok(result.map(|result| result.decision))
    }

    async fn get_subject_decision_result(
        &self,
        subject: &T,
    ) -> Result<Option<DecisionResult<V::Payload>>, DecisionSourceError> {
        let raw = self.source.get_subject_decision_result(subject).await?;
        let Some(raw) = raw else { return Ok(None) };
        let mut valid_until = raw.valid_until;
        let payload = if let Some(payload) = raw.payload {
            let now = D::now();
            let (payload, lifetime) = self.transform.transform(subject, payload).await?;
            if lifetime != Duration::MAX {
                let deadline = now.checked_add(lifetime).ok_or_else(|| {
                    DecisionSourceError::new(
                        DecisionSourceErrorKind::Wire,
                        "transformed payload lifetime overflows the clock",
                    )
                })?;
                valid_until = Some(valid_until.map_or(deadline, |cap| cap.min(deadline)));
            }
            Some(Arc::new(payload))
        } else {
            None
        };
        Ok(Some(DecisionResult {
            decision: raw.decision,
            payload,
            valid_until,
        }))
    }

    async fn watch_subject_decisions(&self) -> Result<Self::Changes, DecisionSourceError> {
        self.source.watch_subject_decisions().await
    }
}

// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::hash::Hash;
use core::marker::PhantomData;
use core::num::NonZeroUsize;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::Instant;

use arc_swap::{ArcSwap, ArcSwapOption};
use async_watch::{Receiver, Sender};
use futures_channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures_core::Stream;
use futures_util::FutureExt;
use futures_util::future::{AbortHandle, Abortable, Aborted, BoxFuture, Shared};
use lru::LruCache;
use parking_lot::Mutex;

use crate::metrics::{NoopPolicyGateMetrics, PolicyGateMetrics};
use crate::time::{TimeDriver, TimeoutElapsed, TokioTimeDriver};
use crate::watcher::DecisionWatcher;
use crate::{
    Decision, DecisionChange, DecisionSourceError, DecisionSourceErrorKind, PolicyGateConfig,
};

/// Subject identifier accepted by the policy-gate runtime.
///
/// Implemented for every type that satisfies its bounds, so a caller never implements it by hand.
/// Subjects are cloned and hashed on the admission path, which favors small keys such as a
/// `u64` or a `Uuid` over an owned `String`.
pub trait Subject: Clone + Eq + Hash + Send + Sync + 'static {}

impl<T> Subject for T where T: Clone + Eq + Hash + Send + Sync + 'static {}

/// Scope-bound decision-source operations used by the gate.
///
/// Each implementation instance represents exactly one scope. Transport adapters are
/// responsible for validating any scope echo before returning normalized typed changes.
///
/// Both methods are called from the gate's own tasks and must not block the async runtime. The
/// gate applies [`PolicyGateConfig::unary_timeout`](crate::PolicyGateConfig::unary_timeout) to
/// every admission or refresh lookup and reopens the watch with backoff, so an implementation
/// needs no timeout or retry logic of its own. It does need to classify failures: the
/// [`kind`](DecisionSourceError::kind) of a returned error decides whether the gate retries the
/// call, fails admission, or counts a protocol violation.
pub trait DecisionSource<T: Subject>: Send + Sync + 'static {
    /// Stream returned by this decision-source implementation.
    type Changes: Stream<Item = Result<DecisionChange<T>, DecisionSourceError>> + Send + 'static;

    /// Fetches the current authoritative decision for one subject.
    ///
    /// Returning `Ok(None)` states that the authority holds no decision; the gate treats that as a
    /// transient failure and retries within the admission deadline.
    ///
    /// # Errors
    ///
    /// Returns a [`DecisionSourceError`] whose kind tells the gate whether the call may be
    /// retried.
    fn get_subject_decision(
        &self,
        subject: &T,
    ) -> impl Future<Output = Result<Option<Decision>, DecisionSourceError>> + Send;

    /// Opens the stream of normalized changes for this decision source's bound scope.
    ///
    /// The gate drops every cached verdict each time a watch opens or closes, so a fresh stream
    /// must be able to re-establish state for any subject the caller asks about again. Ending the
    /// stream or yielding an error closes the watch, and the watcher reopens it after a jittered
    /// backoff.
    ///
    /// # Errors
    ///
    /// Returns a [`DecisionSourceError`] when the stream cannot be opened.
    fn watch_subject_decisions(
        &self,
    ) -> impl Future<Output = Result<Self::Changes, DecisionSourceError>> + Send;
}

/// Current state of a subject admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionState {
    /// The subject is still allowed.
    Allowed,
    /// The authority has denied the subject; admitted work must stop.
    Denied,
    /// No authoritative state is known any more, because the watch went down or the subject was
    /// evicted from the cache, or the decision expired.
    ///
    /// Expired entries can receive a new authoritative watch decision. Eviction and watch
    /// disconnection are terminal for the admission; readmit the subject to obtain a new one.
    Stale,
}

/// Activity-checked decision for a subject, whether allowed or denied.
///
/// An admission reports the subject's live state rather than the verdict captured at admission, which
/// is what lets long-running work react to a later denial. It holds no capacity and does not keep
/// its subject cached: eviction or a watch failure moves it to [`AdmissionState::Stale`].
///
/// Read [`Admission::state`] or [`Admission::is_allowed`] before each activity. Authority changes
/// update the shared entry but never wake a handle; admission lookups coordinate through
/// [`PolicyGate::admit`].
/// Its default type parameter is [`TokioTimeDriver`]; the parameter selects a clock domain and
/// carries no per-instance state.
#[derive(Clone)]
pub struct Admission<D = TokioTimeDriver> {
    entry: Arc<Entry>,
    _time: PhantomData<D>,
}

impl<D: TimeDriver> core::fmt::Debug for Admission<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Admission")
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

impl<D: TimeDriver> Admission<D> {
    /// Returns the current state, treating an expired decision as [`AdmissionState::Stale`].
    ///
    /// Expiration is checked lazily: this read does not mutate the entry or start asynchronous work.
    #[must_use]
    pub fn state(&self) -> AdmissionState {
        match self.observe() {
            Observed::Allowed => AdmissionState::Allowed,
            Observed::Denied => AdmissionState::Denied,
            Observed::Expired | Observed::Stale => AdmissionState::Stale,
        }
    }

    /// Returns whether the current decision is allowed, authoritative, and unexpired.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        self.state() == AdmissionState::Allowed
    }

    pub(crate) fn observe(&self) -> Observed {
        self.entry.observed_at(D::now())
    }
}

/// Admission failed because no authoritative verdict was available before the deadline.
///
/// This is a fail-closed outcome, not a denial: the authority never answered. Callers usually map
/// it to a retryable response such as HTTP 503.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionUnavailable;

impl core::fmt::Display for AdmissionUnavailable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("policy decision source is unavailable")
    }
}

impl core::error::Error for AdmissionUnavailable {}

/// Transport-neutral subject admission gate.
///
/// Cloning is cheap and every clone shares one cache, one decision source, and one watcher, so a
/// process holds a single gate per scope and hands out clones.
///
/// The gate is only as live as its [`DecisionWatcher`]: see the
/// [runtime contract](crate#runtime-contract).
pub struct PolicyGate<
    T: Subject,
    C: DecisionSource<T>,
    M: PolicyGateMetrics = NoopPolicyGateMetrics,
    D = TokioTimeDriver,
> {
    state: Arc<GateState<T, C, M, D>>,
    metrics: M,
}

impl<T: Subject, C: DecisionSource<T>, M: PolicyGateMetrics, D: TimeDriver> Clone
    for PolicyGate<T, C, M, D>
{
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            metrics: self.metrics,
        }
    }
}

impl<T: Subject, C: DecisionSource<T>, M: PolicyGateMetrics, D: TimeDriver> core::fmt::Debug
    for PolicyGate<T, C, M, D>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PolicyGate")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "tokio")]
impl<T: Subject, C: DecisionSource<T>> PolicyGate<T, C> {
    /// Constructs a gate and its single process-wide decision watcher.
    ///
    /// The returned watcher must be continuously polled. Dropping it stops new admissions and
    /// marks existing admission handles stale.
    ///
    /// The third value is a health handle, shared with the watcher, that reports decision-source
    /// connectivity for readiness probes.
    #[must_use]
    pub fn new(config: &PolicyGateConfig, client: Arc<C>) -> crate::PolicyGateParts<T, C> {
        Self::new_with_metrics(config, client, NoopPolicyGateMetrics)
    }
}

#[cfg(feature = "tokio")]
impl<T: Subject, C: DecisionSource<T>, M: PolicyGateMetrics> PolicyGate<T, C, M> {
    /// Constructs a gate with caller-owned metric handling.
    ///
    /// Behaves like [`PolicyGate::new`], but every gate, watcher, and middleware event is reported
    /// to `metrics`.
    #[must_use]
    pub fn new_with_metrics(
        config: &PolicyGateConfig,
        client: Arc<C>,
        metrics: M,
    ) -> crate::PolicyGateParts<T, C, M> {
        Self::new_with_metrics_and_time_driver(config, client, metrics, TokioTimeDriver)
    }
}

impl<T: Subject, C: DecisionSource<T>, D: TimeDriver> PolicyGate<T, C, NoopPolicyGateMetrics, D> {
    /// Constructs a gate with a caller-supplied time driver.
    #[must_use]
    pub fn new_with_time_driver(
        config: &PolicyGateConfig,
        client: Arc<C>,
        time: D,
    ) -> crate::PolicyGateParts<T, C, NoopPolicyGateMetrics, D> {
        Self::new_with_metrics_and_time_driver(config, client, NoopPolicyGateMetrics, time)
    }
}

impl<T: Subject, C: DecisionSource<T>, M: PolicyGateMetrics, D: TimeDriver> PolicyGate<T, C, M, D> {
    /// Constructs a gate with caller-owned metric handling and time driver.
    #[must_use]
    pub fn new_with_metrics_and_time_driver(
        config: &PolicyGateConfig,
        client: Arc<C>,
        metrics: M,
        time: D,
    ) -> crate::PolicyGateParts<T, C, M, D> {
        let (connected, connectivity) = async_watch::channel(false);
        let (state, refreshes) =
            GateState::new(Arc::clone(&client), config, metrics, time, connectivity);
        let (watcher, health) =
            DecisionWatcher::new(Arc::clone(&state), client, metrics, connected, refreshes);
        (Self { state, metrics }, watcher, health)
    }

    /// Returns a cached authoritative admission without waiting or issuing I/O.
    ///
    /// This is the cached path and performs no I/O. `None` means the snapshot cannot answer — the
    /// subject is unknown, its verdict is still being fetched, its cached state went stale or
    /// expired, or the watch is down — and the caller should fall back to [`PolicyGate::admit`].
    #[must_use]
    pub fn try_cached(&self, subject: &T) -> Option<Admission<D>> {
        self.state.check(subject)
    }

    /// Resolves an authoritative admission within the configured deadline.
    ///
    /// Waits for the watch to be connected, then serves the cached verdict or fetches one,
    /// retrying transient failures with backoff until
    /// [`PolicyGateConfig::admission_timeout`](crate::PolicyGateConfig::admission_timeout)
    /// elapses. Concurrent admissions of the same subject share one lookup.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionUnavailable`] when no authoritative decision is available before the
    /// configured admission deadline, when the lookup fails with
    /// [`DecisionSourceErrorKind::Permanent`](crate::DecisionSourceErrorKind::Permanent) or
    /// [`Wire`](crate::DecisionSourceErrorKind::Wire), or after the watcher future has been dropped.
    pub async fn admit(&self, subject: &T) -> Result<Admission<D>, AdmissionUnavailable> {
        self.state.admit(subject).await.ok_or(AdmissionUnavailable)
    }

    /// Returns a copy of the caller-provided metrics handle.
    #[must_use]
    pub const fn metrics(&self) -> M {
        self.metrics
    }

    #[cfg(feature = "tower-layer")]
    pub(crate) fn admission_timeout(&self) -> Duration {
        self.state.admission_timeout()
    }

    #[cfg(feature = "tower-layer")]
    pub(crate) async fn admit_after(
        &self,
        subject: &T,
        delay: Duration,
    ) -> Result<Admission<D>, AdmissionUnavailable> {
        D::sleep(delay).await;
        self.admit(subject).await
    }
}

/// Locally observable lifecycle state of a subject entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum EntryState {
    Pending,
    Allowed,
    Denied,
    Stale,
}

impl From<Decision> for EntryState {
    fn from(decision: Decision) -> Self {
        match decision {
            Decision::Allowed => Self::Allowed,
            Decision::Denied => Self::Denied,
        }
    }
}

pub(crate) enum Observed {
    Allowed,
    Denied,
    Expired,
    Stale,
}

type FetchResult = Result<Decision, DecisionSourceError>;
type Generation = triomphe::Arc<()>;
type PendingFuture = Shared<BoxFuture<'static, Result<FetchResult, Aborted>>>;

struct PendingFetch {
    generation: Generation,
    future: PendingFuture,
    abort: AbortHandle,
}

struct RefreshState {
    generation: Generation,
    refresh_in_flight: bool,
}

impl PendingFetch {
    fn future(&self) -> PendingFuture {
        self.future.clone()
    }

    fn abort(&self) {
        self.abort.abort();
    }
}

/// Shared subject state observed by admissions and active streams.
// Streams poll state per frame; this prevents updates to neighboring subject entries from
// causing false sharing on 64- or 128-byte cache lines.
#[repr(align(128))]
pub(crate) struct Entry {
    // Low two bits encode state; the upper bits encode nanoseconds since `epoch`.
    current: AtomicU64,
    epoch: Instant,
    pending: ArcSwapOption<PendingFetch>,
    refresh: Mutex<RefreshState>,
}

impl core::fmt::Debug for Entry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Entry")
            .field(
                "state",
                &decode_entry_state(self.current.load(Ordering::Acquire)),
            )
            .finish_non_exhaustive()
    }
}

const STATE_MASK: u64 = 0b11;
const NO_EXPIRY: u64 = (1_u64 << 62) - 1;
const MAX_FINITE_DEADLINE: u64 = NO_EXPIRY - 1;

impl Entry {
    fn pending(epoch: Instant, fetch: Arc<PendingFetch>) -> Self {
        Self {
            current: AtomicU64::new(Self::word(EntryState::Pending, NO_EXPIRY)),
            epoch,
            pending: ArcSwapOption::from(Some(fetch)),
            refresh: Mutex::new(RefreshState {
                generation: Generation::new(()),
                refresh_in_flight: false,
            }),
        }
    }

    fn state_at(&self, now: Instant) -> EntryState {
        let decision = self.current.load(Ordering::Acquire);
        if self.is_expired_at(decision, now) {
            EntryState::Stale
        } else {
            decode_entry_state(decision)
        }
    }

    fn observed_at(&self, now: Instant) -> Observed {
        let decision = self.current.load(Ordering::Acquire);
        if self.is_expired_at(decision, now) {
            return Observed::Expired;
        }
        match decode_entry_state(decision) {
            EntryState::Pending => {
                unreachable!("an admission is created only from an authoritative state")
            }
            EntryState::Stale => Observed::Stale,
            EntryState::Allowed => Observed::Allowed,
            EntryState::Denied => Observed::Denied,
        }
    }

    fn verdict_at(&self, now: Instant) -> Option<Decision> {
        let decision = self.current.load(Ordering::Acquire);
        if self.is_expired_at(decision, now) {
            return None;
        }
        match decode_entry_state(decision) {
            EntryState::Allowed => Some(Decision::Allowed),
            EntryState::Denied => Some(Decision::Denied),
            EntryState::Pending | EntryState::Stale => None,
        }
    }

    fn compare_exchange(
        &self,
        current: EntryState,
        new: EntryState,
        deadline: u64,
    ) -> Result<(), EntryState> {
        let mut previous = self.current.load(Ordering::Acquire);
        loop {
            let previous_state = decode_entry_state(previous);
            if previous_state != current {
                return Err(previous_state);
            }
            match self.current.compare_exchange_weak(
                previous,
                Self::word(new, deadline),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(changed) => previous = changed,
            }
        }
    }

    fn compare_exchange_authoritative(
        &self,
        current: EntryState,
        new: EntryState,
        deadline: u64,
    ) -> Result<(), EntryState> {
        let mut refresh = self.refresh.lock();
        self.compare_exchange(current, new, deadline)?;
        refresh.generation = Generation::new(());
        refresh.refresh_in_flight = false;
        Ok(())
    }

    fn deadline_after(&self, now: Instant, ttl: Duration) -> u64 {
        if ttl == Duration::MAX {
            return NO_EXPIRY;
        }
        let now = self.tick(now);
        let Ok(ttl) = u64::try_from(ttl.as_nanos()) else {
            return now;
        };
        // An unrepresentable finite deadline is immediately expired.
        now.checked_add(ttl)
            .filter(|deadline| *deadline < NO_EXPIRY)
            .unwrap_or(now)
    }

    const fn word(state: EntryState, deadline: u64) -> u64 {
        (deadline << 2) | state as u64
    }

    fn tick(&self, now: Instant) -> u64 {
        u64::try_from(now.saturating_duration_since(self.epoch).as_nanos())
            .unwrap_or(MAX_FINITE_DEADLINE)
            .min(MAX_FINITE_DEADLINE)
    }

    fn is_expired_at(&self, decision: u64, now: Instant) -> bool {
        let deadline = decision >> 2;
        deadline != NO_EXPIRY && self.tick(now) >= deadline
    }

    fn deadline_instant(&self, decision: u64) -> Option<Instant> {
        let deadline = decision >> 2;
        if deadline == NO_EXPIRY {
            return None;
        }
        self.epoch.checked_add(Duration::from_nanos(deadline))
    }

    fn begin_refresh_if_due(
        &self,
        now: Instant,
        freshness_ttl: Duration,
        refresh_after: Duration,
    ) -> Option<Generation> {
        let mut refresh = self.refresh.lock();
        let decision = self.current.load(Ordering::Acquire);
        if !matches!(
            decode_entry_state(decision),
            EntryState::Allowed | EntryState::Denied
        ) {
            return None;
        }
        let fresh_until = self.deadline_instant(decision)?;
        let refresh_at = fresh_until.checked_sub(freshness_ttl.checked_sub(refresh_after)?)?;
        if now < refresh_at || now >= fresh_until || refresh.refresh_in_flight {
            return None;
        }
        refresh.refresh_in_flight = true;
        Some(Generation::clone(&refresh.generation))
    }

    fn apply_refresh_result<D: TimeDriver>(
        &self,
        generation: &Generation,
        result: &FetchResult,
        ttl: Duration,
    ) {
        let mut refresh = self.refresh.lock();
        if !Generation::ptr_eq(&refresh.generation, generation) || !refresh.refresh_in_flight {
            return;
        }
        refresh.refresh_in_flight = false;
        let now = D::now();
        let current = self.current.load(Ordering::Acquire);
        if !matches!(
            decode_entry_state(current),
            EntryState::Allowed | EntryState::Denied
        ) || self.is_expired_at(current, now)
        {
            return;
        }
        if let Ok(decision) = result {
            self.current.store(
                Self::word((*decision).into(), self.deadline_after(now, ttl)),
                Ordering::Release,
            );
            refresh.generation = Generation::new(());
        }
    }

    fn refresh_is_current<D: TimeDriver>(&self, generation: &Generation) -> bool {
        let refresh = self.refresh.lock();
        if !Generation::ptr_eq(&refresh.generation, generation) || !refresh.refresh_in_flight {
            return false;
        }
        let current = self.current.load(Ordering::Acquire);
        matches!(
            decode_entry_state(current),
            EntryState::Allowed | EntryState::Denied
        ) && !self.is_expired_at(current, D::now())
    }

    fn pending_operation(&self) -> Option<Arc<PendingFetch>> {
        self.pending.load_full()
    }

    fn pending_generation(&self, generation: &Generation) -> Option<Arc<PendingFetch>> {
        self.pending_operation()
            .filter(|pending| Generation::ptr_eq(&pending.generation, generation))
    }

    fn pending_is(&self, pending: &Arc<PendingFetch>) -> bool {
        self.pending_operation()
            .is_some_and(|current| Arc::ptr_eq(&current, pending))
    }

    fn replace_pending(
        &self,
        generation: &Generation,
        replacement: Option<Arc<PendingFetch>>,
    ) -> bool {
        let Some(current) = self.pending_generation(generation) else {
            return false;
        };
        let previous = self
            .pending
            .compare_and_swap(&Some(Arc::clone(&current)), replacement);
        previous
            .as_ref()
            .is_some_and(|previous| Arc::ptr_eq(previous, &current))
    }

    fn abort_pending(&self) {
        if let Some(pending) = self.pending.swap(None) {
            pending.abort();
        }
    }

    fn admission<D: TimeDriver>(entry: Arc<Self>) -> Option<Admission<D>> {
        entry.verdict_at(D::now())?;
        Some(Admission {
            entry,
            _time: PhantomData,
        })
    }

    fn invalidate(&self) {
        let mut refresh = self.refresh.lock();
        let mut previous = self.current.load(Ordering::Acquire);
        loop {
            let stale = (previous & !STATE_MASK) | EntryState::Stale as u64;
            match self.current.compare_exchange_weak(
                previous,
                stale,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(changed) => previous = changed,
            }
        }
        refresh.generation = Generation::new(());
        refresh.refresh_in_flight = false;
        drop(refresh);
        self.abort_pending();
    }
}

struct SubjectSlot {
    entry: Arc<Entry>,
    last_touched: u64,
}

impl SubjectSlot {
    fn touch(&mut self, tick: u64) {
        self.last_touched = self.last_touched.max(tick);
    }
}

struct SubjectMap<T> {
    entries: Mutex<LruCache<T, SubjectSlot>>,
    subject_ttl: Duration,
    activity_epoch: Instant,
    shape_dirty: Arc<AtomicBool>,
}

impl<T: Subject> SubjectMap<T> {
    fn new(
        max_subjects: usize,
        subject_ttl: Duration,
        shape_dirty: Arc<AtomicBool>,
        activity_epoch: Instant,
    ) -> Self {
        Self {
            entries: Mutex::new(LruCache::new(
                NonZeroUsize::new(max_subjects).expect("validated subject capacity is nonzero"),
            )),
            subject_ttl,
            activity_epoch,
            shape_dirty,
        }
    }

    fn get_or_insert_with(
        &self,
        subject: &T,
        now: Instant,
        create: impl FnOnce() -> Arc<Entry>,
    ) -> Arc<Entry> {
        let tick = self.tick(now);
        let mut entries = self.entries.lock();
        if let Some(slot) = entries.get_mut(subject) {
            slot.touch(tick);
            let entry = Arc::clone(&slot.entry);
            self.evict(&mut entries, tick);
            return entry;
        }
        self.evict(&mut entries, tick);
        let entry = create();
        let evicted = entries.push(
            subject.clone(),
            SubjectSlot {
                entry: Arc::clone(&entry),
                last_touched: tick,
            },
        );
        if let Some((_, slot)) = evicted {
            slot.entry.invalidate();
            self.shape_dirty.store(true, Ordering::Release);
        }
        self.evict(&mut entries, tick);
        entry
    }

    fn touch(&self, subject: &T, entry: &Entry, now: Instant) {
        let tick = self.tick(now);
        let mut entries = self.entries.lock();
        if entries
            .peek(subject)
            .is_some_and(|slot| core::ptr::eq::<Entry>(slot.entry.as_ref(), entry))
        {
            let slot = entries
                .get_mut(subject)
                .expect("the matching entry remains present while the map is locked");
            slot.touch(tick);
        }
        self.evict(&mut entries, tick);
    }

    fn peek(&self, subject: &T, now: Instant) -> Option<Arc<Entry>> {
        let tick = self.tick(now);
        let mut entries = self.entries.lock();
        self.evict(&mut entries, tick);
        entries.peek(subject).map(|slot| Arc::clone(&slot.entry))
    }

    fn remove(&self, subject: &T, now: Instant) -> bool {
        let mut entries = self.entries.lock();
        self.evict(&mut entries, self.tick(now));
        entries.pop(subject).is_some_and(|slot| {
            slot.entry.invalidate();
            true
        })
    }

    fn remove_if(
        &self,
        subject: &T,
        now: Instant,
        predicate: impl FnOnce(&Arc<Entry>) -> bool,
    ) -> bool {
        let mut entries = self.entries.lock();
        self.evict(&mut entries, self.tick(now));
        if !entries
            .peek(subject)
            .is_some_and(|slot| predicate(&slot.entry))
        {
            return false;
        }
        entries.pop(subject).is_some_and(|slot| {
            slot.entry.invalidate();
            true
        })
    }

    fn for_each(&self, mut visit: impl FnMut(&T, &Arc<Entry>)) {
        for (subject, slot) in self.entries.lock().iter() {
            visit(subject, &slot.entry);
        }
    }

    fn apply_if_current<R>(
        &self,
        subject: &T,
        entry: &Arc<Entry>,
        now: Instant,
        apply: impl FnOnce() -> R,
    ) -> Option<R> {
        let mut entries = self.entries.lock();
        self.evict(&mut entries, self.tick(now));
        if !entries
            .peek(subject)
            .is_some_and(|slot| Arc::ptr_eq(&slot.entry, entry))
        {
            return None;
        }
        Some(apply())
    }

    fn clear(&self) {
        let mut entries = self.entries.lock();
        for (_, slot) in entries.iter() {
            slot.entry.invalidate();
        }
        entries.clear();
    }

    fn tick(&self, now: Instant) -> u64 {
        u64::try_from(
            now.saturating_duration_since(self.activity_epoch)
                .as_nanos(),
        )
        .unwrap_or(u64::MAX)
    }

    fn evict(&self, entries: &mut LruCache<T, SubjectSlot>, now: u64) {
        let subject_ttl = u64::try_from(self.subject_ttl.as_nanos()).unwrap_or(u64::MAX);
        loop {
            let expired = entries
                .peek_lru()
                .is_some_and(|(_, slot)| now.saturating_sub(slot.last_touched) > subject_ttl);
            if !expired {
                break;
            }
            let Some((_, slot)) = entries.pop_lru() else {
                break;
            };
            slot.entry.invalidate();
            self.shape_dirty.store(true, Ordering::Release);
        }
    }
}

type SubjectSnapshot<T> = HashMap<T, Arc<Entry>>;

struct PublishState {
    generation: u64,
    next_allowed: Instant,
}

pub(crate) type DecisionRefreshFuture = BoxFuture<'static, ()>;

/// Owns authoritative subject state and its cached read snapshot.
pub(crate) struct GateState<T: Subject, C: DecisionSource<T>, M: PolicyGateMetrics, D> {
    client: Arc<C>,
    connected: Receiver<bool>,
    disconnected_since: Arc<Mutex<Option<Instant>>>,
    subjects: SubjectMap<T>,
    snapshot: ArcSwap<SubjectSnapshot<T>>,
    /// Every snapshot store happens under this lock; `generation` rejects rebuilds that started
    /// before a clear, and `connected` rejects rebuilds that started during one.
    publish: Mutex<PublishState>,
    shape_dirty: Arc<AtomicBool>,
    refreshes: UnboundedSender<DecisionRefreshFuture>,
    config: PolicyGateConfig,
    metrics: M,
    _time: PhantomData<D>,
}

impl<T: Subject, C: DecisionSource<T>, M: PolicyGateMetrics, D: TimeDriver> core::fmt::Debug
    for GateState<T, C, M, D>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GateState")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<T: Subject, C: DecisionSource<T>, M: PolicyGateMetrics, D: TimeDriver> GateState<T, C, M, D> {
    /// Constructs one process-wide decision-source state.
    pub(crate) fn new(
        client: Arc<C>,
        config: &PolicyGateConfig,
        metrics: M,
        _time: D,
        connected: Receiver<bool>,
    ) -> (Arc<Self>, UnboundedReceiver<DecisionRefreshFuture>) {
        let now = D::now();
        let shape_dirty = Arc::new(AtomicBool::new(false));
        let (refreshes, refresh_requests) = futures_channel::mpsc::unbounded();
        let state = Arc::new(Self {
            client,
            connected,
            disconnected_since: Arc::new(Mutex::new(Some(now))),
            subjects: SubjectMap::new(
                config.max_subjects(),
                config.subject_ttl(),
                Arc::clone(&shape_dirty),
                now,
            ),
            snapshot: ArcSwap::from_pointee(HashMap::new()),
            publish: Mutex::new(PublishState {
                generation: 0,
                next_allowed: now,
            }),
            shape_dirty,
            refreshes,
            config: *config,
            metrics,
            _time: PhantomData,
        });
        (state, refresh_requests)
    }

    /// Returns the total admission time budget.
    pub(crate) const fn admission_timeout(&self) -> Duration {
        self.config.admission_timeout()
    }

    pub(crate) const fn initial_reconnect_delay(&self) -> Duration {
        self.config.initial_reconnect_delay()
    }

    pub(crate) const fn max_reconnect_delay(&self) -> Duration {
        self.config.max_reconnect_delay()
    }

    pub(crate) const fn watch_events_per_yield(&self) -> usize {
        self.config.watch_events_per_yield()
    }

    pub(crate) fn disconnected_since(&self) -> Arc<Mutex<Option<Instant>>> {
        Arc::clone(&self.disconnected_since)
    }

    fn decision_deadline(&self, entry: &Entry) -> u64 {
        entry.deadline_after(D::now(), self.config.decision_freshness_ttl())
    }

    /// Reads subject state through the snapshot and records its map recency.
    pub(crate) fn check(self: &Arc<Self>, subject: &T) -> Option<Admission<D>> {
        let snapshot = self.snapshot.load();
        let entry = snapshot.get(subject)?;
        // Pending and stale entries read as snapshot misses.
        entry.verdict_at(D::now())?;
        self.subjects.touch(subject, entry, D::now());
        self.admission_on_access(subject, Arc::clone(entry))
    }

    /// Resolves an authoritative subject verdict within the admission budget.
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn admit(self: &Arc<Self>, subject: &T) -> Option<Admission<D>> {
        let Some(deadline) = D::now().checked_add(self.config.admission_timeout()) else {
            return self.admission_timed_out();
        };
        let mut retry_delay = self.config.initial_admission_retry_delay();
        let mut connected = self.connected.clone();

        // A disconnect clears the map and marks entries Stale, so the connection is rechecked
        // after each await and Stale retries.
        // Lost races restart immediately; only a failed unary attempt takes the retry backoff.
        loop {
            let connected_or_closed = async {
                loop {
                    if *connected.borrow() {
                        return true;
                    }
                    if connected.changed().await.is_err() {
                        return false;
                    }
                }
            };
            match D::timeout_at(deadline, connected_or_closed).await {
                Ok(true) => {}
                Ok(false) => return None,
                Err(TimeoutElapsed) => return self.admission_timed_out(),
            }

            let mut inserted = false;
            let now = D::now();
            let entry = self.subjects.get_or_insert_with(subject, now, || {
                inserted = true;
                Arc::new_cyclic(|entry| {
                    Entry::pending(
                        now,
                        self.new_fetch_after(entry.clone(), subject.clone(), None),
                    )
                })
            });
            if inserted {
                self.shape_dirty.store(true, Ordering::Release);
            } else if self.snapshot.load().get(subject).is_none() {
                // Heal snapshot drift on this subject's next admission.
                self.shape_dirty.store(true, Ordering::Release);
            }
            self.republish_if_due();
            let now = D::now();
            if now >= deadline {
                return self.admission_timed_out();
            }
            if !*connected.borrow() {
                let removed = self
                    .subjects
                    .remove_if(subject, now, |current| Arc::ptr_eq(current, &entry));
                if removed {
                    self.shape_dirty.store(true, Ordering::Release);
                }
                continue;
            }

            let pending = match entry.state_at(D::now()) {
                EntryState::Allowed | EntryState::Denied => {
                    self.metrics.map_hit();
                    if let Some(admission) = self.admission_on_access(subject, entry) {
                        return Some(admission);
                    }
                    continue;
                }
                EntryState::Pending => {
                    let Some(fetch) = entry.pending_operation() else {
                        continue;
                    };
                    if !matches!(entry.state_at(D::now()), EntryState::Pending)
                        || !entry.pending_is(&fetch)
                    {
                        continue;
                    }
                    (entry, fetch)
                }
                EntryState::Stale => {
                    let removed = self.subjects.remove_if(subject, D::now(), |current| {
                        if !Arc::ptr_eq(current, &entry) {
                            return false;
                        }
                        matches!(current.state_at(D::now()), EntryState::Stale)
                    });
                    if removed {
                        self.shape_dirty.store(true, Ordering::Release);
                    }
                    self.republish_if_due();
                    continue;
                }
            };

            let (entry, fetch) = pending;
            // The fetch bounds one attempt; this outer deadline also covers the retry loop.
            let result = D::timeout_at(deadline, async {
                let fetch = fetch.future().fuse();
                let connection_change = connected.changed().fuse();
                futures_util::pin_mut!(fetch, connection_change);
                futures_util::select! {
                    result = fetch => Some(result),
                    _ = connection_change => None,
                }
            })
            .await;
            let result = match result {
                Ok(Some(Ok(result))) => result,
                Ok(Some(Err(Aborted)) | None) => continue,
                Err(_) => {
                    // An authoritative transition may race the deadline notification.
                    if let Some(admission) = self.admission_on_access(subject, entry) {
                        return Some(admission);
                    }
                    return self.admission_timed_out();
                }
            };
            if !*connected.borrow() {
                continue;
            }
            match entry.state_at(D::now()) {
                EntryState::Allowed | EntryState::Denied => {
                    if let Some(admission) = self.admission_on_access(subject, entry) {
                        return Some(admission);
                    }
                    continue;
                }
                EntryState::Pending | EntryState::Stale => {
                    if result.is_ok() {
                        continue;
                    }
                }
            }
            if result.as_ref().is_err_and(is_permanent_status) {
                return None;
            }

            self.metrics.admission_retry();
            if D::timeout_at(deadline, D::sleep(retry_delay))
                .await
                .is_err()
            {
                return self.admission_timed_out();
            }
            retry_delay = retry_delay
                .saturating_mul(2)
                .min(self.config.max_admission_retry_delay());
        }
    }

    fn new_fetch_after(
        self: &Arc<Self>,
        entry: Weak<Entry>,
        subject: T,
        delay: Option<Duration>,
    ) -> Arc<PendingFetch> {
        // `delay` is the permanent-failure cooldown; it starts when the first joiner polls.
        let client = Arc::clone(&self.client);
        let metrics = self.metrics;
        let unary_timeout = self.config.unary_timeout();
        let gate = Arc::downgrade(self);
        let generation = Generation::new(());
        let completion_generation = Generation::clone(&generation);
        let (abort, registration) = AbortHandle::new_pair();
        let future = Abortable::new(
            async move {
                if let Some(delay) = delay {
                    D::sleep(delay).await;
                }
                metrics.unary_call();
                let result = async {
                    let decision = D::timeout(unary_timeout, client.get_subject_decision(&subject))
                        .await
                        .map_err(|_| {
                            DecisionSourceError::new(
                                DecisionSourceErrorKind::Transient,
                                "subject state lookup timed out",
                            )
                        })??;
                    decision.ok_or_else(|| {
                        DecisionSourceError::new(
                            DecisionSourceErrorKind::Transient,
                            "decision source holds no decision for the subject",
                        )
                    })
                }
                .await;
                if result
                    .as_ref()
                    .is_err_and(|error| error.kind() == DecisionSourceErrorKind::Wire)
                {
                    metrics.wire_failure();
                }
                if result.is_err() {
                    metrics.unary_failure();
                }
                if let (Some(gate), Some(entry)) = (gate.upgrade(), entry.upgrade()) {
                    gate.apply_fetch_result(&subject, &entry, &completion_generation, &result);
                }
                result
            },
            registration,
        )
        .boxed()
        .shared();
        Arc::new(PendingFetch {
            generation,
            future,
            abort,
        })
    }

    fn apply_fetch_result(
        self: &Arc<Self>,
        subject: &T,
        entry: &Arc<Entry>,
        generation: &Generation,
        result: &FetchResult,
    ) {
        if entry.pending_generation(generation).is_none() {
            return;
        }
        if let Ok(decision) = result {
            // A watch event that wins this CAS supplies the verdict that stands.
            if entry
                .compare_exchange_authoritative(
                    EntryState::Pending,
                    (*decision).into(),
                    self.decision_deadline(entry),
                )
                .is_ok()
            {
                entry.replace_pending(generation, None);
            }
            return;
        }

        if result.as_ref().is_err_and(is_permanent_status) {
            if matches!(entry.state_at(D::now()), EntryState::Pending) {
                let retry = self.new_fetch_after(
                    Arc::downgrade(entry),
                    subject.clone(),
                    Some(self.config.permanent_failure_cooldown()),
                );
                entry.replace_pending(generation, Some(retry));
            }
            return;
        }

        // remove_if runs its predicate under the map lock, making the
        // Pending -> Stale transition and removal one indivisible operation.
        let removed = self.subjects.remove_if(subject, D::now(), |current| {
            if !Arc::ptr_eq(current, entry) || current.pending_generation(generation).is_none() {
                return false;
            }
            entry
                .compare_exchange(EntryState::Pending, EntryState::Stale, NO_EXPIRY)
                .is_ok()
        });
        if removed {
            self.shape_dirty.store(true, Ordering::Release);
        }
        self.republish_if_due();
    }

    fn admission_timed_out(&self) -> Option<Admission<D>> {
        self.metrics.admission_timeout();
        None
    }

    fn admission_on_access(
        self: &Arc<Self>,
        subject: &T,
        entry: Arc<Entry>,
    ) -> Option<Admission<D>> {
        let admission = Entry::admission(Arc::clone(&entry))?;
        self.refresh_on_access(subject, entry);
        Some(admission)
    }

    fn refresh_on_access(self: &Arc<Self>, subject: &T, entry: Arc<Entry>) {
        let refresh_after = self.config.decision_refresh_after();
        if refresh_after == Duration::MAX {
            return;
        }
        let Some(generation) = entry.begin_refresh_if_due(
            D::now(),
            self.config.decision_freshness_ttl(),
            refresh_after,
        ) else {
            return;
        };
        let refresh = self.new_decision_refresh(subject.clone(), entry, generation);
        let _ = self.refreshes.unbounded_send(refresh);
    }

    fn refresh_is_current(&self, subject: &T, entry: &Arc<Entry>, generation: &Generation) -> bool {
        self.subjects
            .apply_if_current(subject, entry, D::now(), || {
                entry.refresh_is_current::<D>(generation)
            })
            .unwrap_or(false)
    }

    fn new_decision_refresh(
        self: &Arc<Self>,
        subject: T,
        entry: Arc<Entry>,
        generation: Generation,
    ) -> DecisionRefreshFuture {
        let client = Arc::clone(&self.client);
        let metrics = self.metrics;
        let unary_timeout = self.config.unary_timeout();
        let gate = Arc::downgrade(self);
        async move {
            let Some(current_gate) = gate.upgrade() else {
                return;
            };
            if !current_gate.refresh_is_current(&subject, &entry, &generation) {
                return;
            }
            drop(current_gate);
            metrics.unary_call();
            let result = async {
                let decision = D::timeout(unary_timeout, client.get_subject_decision(&subject))
                    .await
                    .map_err(|_| {
                        DecisionSourceError::new(
                            DecisionSourceErrorKind::Transient,
                            "subject decision refresh timed out",
                        )
                    })??;
                decision.ok_or_else(|| {
                    DecisionSourceError::new(
                        DecisionSourceErrorKind::Transient,
                        "decision source holds no decision for the subject",
                    )
                })
            }
            .await;
            if result
                .as_ref()
                .is_err_and(|error| error.kind() == DecisionSourceErrorKind::Wire)
            {
                metrics.wire_failure();
            }
            if result.is_err() {
                metrics.unary_failure();
            }
            if let Some(gate) = gate.upgrade() {
                gate.subjects
                    .apply_if_current(&subject, &entry, D::now(), || {
                        entry.apply_refresh_result::<D>(
                            &generation,
                            &result,
                            gate.config.decision_freshness_ttl(),
                        );
                    });
            }
        }
        .boxed()
    }

    /// Marks the watch connected after clearing state from the prior connection.
    pub(crate) fn watch_connected(&self, connected: &Sender<bool>) {
        // Clear before publishing connected so no state from the old watch is served.
        self.publish_empty(|| {});
        self.subjects.clear();
        connected
            .send(true)
            .expect("gate state retains its receiver");
        self.metrics.set_watch_connected(true);
    }

    /// Marks a continuously open watch as healthy.
    pub(crate) fn watch_stable(&self) {
        *self.disconnected_since.lock() = None;
    }

    /// Marks the watch disconnected before clearing its subject state.
    pub(crate) fn watch_disconnected(&self, connected: &Sender<bool>) {
        self.publish_empty(|| {
            connected
                .send(false)
                .expect("gate state retains its receiver");
            self.metrics.set_watch_connected(false);
            self.mark_disconnected();
        });
        self.subjects.clear();
    }

    /// Applies one watch change to a subject already known to this process.
    pub(crate) fn apply_change(&self, change: &DecisionChange<T>) {
        let subject = &change.subject;
        // Absent subjects are ignored: a vanished entry is re-admitted by its stream or next request.
        if let Some(decision) = change.decision {
            let entry = self.subjects.peek(subject, D::now());
            self.republish_if_due();
            if let Some(entry) = entry {
                let next = decision.into();
                loop {
                    match decode_entry_state(entry.current.load(Ordering::Acquire)) {
                        EntryState::Stale => break,
                        current @ (EntryState::Pending
                        | EntryState::Allowed
                        | EntryState::Denied) => match entry.compare_exchange_authoritative(
                            current,
                            next,
                            self.decision_deadline(&entry),
                        ) {
                            Ok(()) => {
                                entry.abort_pending();
                                break;
                            }
                            Err(
                                EntryState::Pending
                                | EntryState::Allowed
                                | EntryState::Denied
                                | EntryState::Stale,
                            ) => {}
                        },
                    }
                }
            }
        } else {
            let removed = self.subjects.remove(subject, D::now());
            if removed {
                self.shape_dirty.store(true, Ordering::Release);
            }
            self.republish_if_due();
        }
    }

    /// Rate-limited snapshot rebuild run by the slow-path operation that finds the dirty flag
    /// after the window; until it runs, a new subject's requests take the map path in `admit`.
    fn republish_if_due(&self) {
        if !self.shape_dirty.load(Ordering::Acquire) {
            return;
        }
        let generation = {
            let mut publish = self.publish.lock();
            let now = D::now();
            if now < publish.next_allowed {
                return;
            }
            publish.next_allowed = now + self.config.snapshot_republish_interval();
            publish.generation
        };

        self.shape_dirty.store(false, Ordering::Release);
        let mut entries = HashMap::new();
        self.subjects.for_each(|subject, entry| {
            entries.insert(subject.clone(), Arc::clone(entry));
        });

        let publish = self.publish.lock();
        // `connected` flips false under this lock, so a rebuild that claimed after a disconnect's
        // empty publish but copied the map before its clear is dropped here.
        if publish.generation == generation && *self.connected.borrow() {
            self.snapshot.store(Arc::new(entries));
            self.metrics.snapshot_republish();
        }
    }

    fn mark_disconnected(&self) {
        let mut since = self.disconnected_since.lock();
        if since.is_none() {
            *since = Some(D::now());
        }
    }
}

impl<T: Subject, C: DecisionSource<T>, M: PolicyGateMetrics, D: TimeDriver> GateState<T, C, M, D> {
    fn publish_empty(&self, after_publish: impl FnOnce()) {
        let mut publish = self.publish.lock();
        publish.generation += 1;
        // The empty snapshot publish is the disconnect linearization point.
        self.snapshot.store(Arc::new(HashMap::new()));
        after_publish();
    }
}

const fn decode_entry_state(decision: u64) -> EntryState {
    match decision & STATE_MASK {
        0 => EntryState::Pending,
        1 => EntryState::Allowed,
        2 => EntryState::Denied,
        3 => EntryState::Stale,
        _ => unreachable!(),
    }
}

const fn is_permanent_status(error: &DecisionSourceError) -> bool {
    matches!(
        error.kind(),
        DecisionSourceErrorKind::Permanent | DecisionSourceErrorKind::Wire
    )
}

// Copyright 2026 Aspect Build Systems, Inc. All rights reserved.

use core::hash::Hash;
use core::num::NonZeroUsize;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use core::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use async_watch::{Receiver, Sender};
use futures_core::Stream;
use futures_util::FutureExt;
use futures_util::future::{BoxFuture, Shared};
use lru::LruCache;
use parking_lot::Mutex;
use triomphe::Arc as TriompheArc;

use crate::metrics::{NoopPolicyGateMetrics, PolicyGateMetrics};
use crate::time::{TimeDriver, TokioTimeDriver};
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
/// every admission or freshness lookup and reopens the watch with backoff, so an implementation
/// needs no timeout or retry logic of its own. It does need to classify failures: the
/// [`kind`](DecisionSourceError::kind) of a returned error decides whether the gate retries the
/// call, fails admission, or counts a protocol violation.
pub trait DecisionSource<T: Subject>: Send + Sync + 'static {
    /// Stream returned by this decision-source implementation.
    type Changes: Stream<Item = Result<DecisionChange<T>, DecisionSourceError>> + Send + 'static;

    /// Fetches the current authoritative decision for one subject.
    ///
    /// Returning [`Decision::Unspecified`] states that the authority holds no decision; the gate
    /// treats that as a transient failure and retries within the admission deadline.
    ///
    /// # Errors
    ///
    /// Returns a [`DecisionSourceError`] whose kind tells the gate whether the call may be
    /// retried.
    fn get_subject_decision(
        &self,
        subject: &T,
    ) -> impl Future<Output = Result<Decision, DecisionSourceError>> + Send;

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

/// Result of an authoritative admission attempt.
#[derive(Debug)]
pub enum Admission {
    /// The subject is allowed and the returned permit observes later changes.
    Allowed(Permit),
    /// The subject is currently denied.
    Denied,
}

/// Observable state of an admitted permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermitState {
    /// The subject is still allowed.
    Allowed,
    /// The authority has denied the subject; admitted work must stop.
    Denied,
    /// No authoritative state is known any more, because the watch went down or the subject was
    /// evicted from the cache.
    ///
    /// This state is terminal for the permit: a new verdict arrives only through
    /// [`PolicyGate::try_cached`] or [`PolicyGate::admit`].
    Stale,
}

/// Opaque observation handle for a successfully admitted subject.
///
/// A permit reports the subject's live state rather than the verdict captured at admission, which
/// is what lets long-running work react to a later denial. It holds no capacity and does not keep
/// its subject cached: eviction or a watch failure moves it to [`PermitState::Stale`].
///
/// Clones observe the same subject independently, so each clone can await its own transitions.
pub struct Permit {
    entry: TriompheArc<Entry>,
    changes: Receiver<EntryState>,
    observed: PermitState,
    tracks_refresh: bool,
}

impl Clone for Permit {
    fn clone(&self) -> Self {
        let entry = TriompheArc::clone(&self.entry);
        let changes = entry.subscribe();
        let observed = self.state();
        if self.tracks_refresh {
            Self::increment_live_count(&entry);
        }
        Self {
            entry,
            changes,
            observed,
            tracks_refresh: self.tracks_refresh,
        }
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        if self.tracks_refresh {
            Self::decrement_live_count(&self.entry);
        }
    }
}

impl core::fmt::Debug for Permit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Permit")
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

impl Permit {
    fn from_admission(entry: TriompheArc<Entry>) -> Option<Self> {
        let changes = entry.subscribe();
        let tracks_refresh = entry.freshness_signal.refresh_enabled();
        if tracks_refresh {
            Self::increment_live_count(&entry);
        }
        if !matches!(entry.state(), EntryState::Allowed) {
            if tracks_refresh {
                Self::decrement_live_count(&entry);
            }
            return None;
        }
        Some(Self {
            entry,
            changes,
            observed: PermitState::Allowed,
            tracks_refresh,
        })
    }

    fn increment_live_count(entry: &Entry) {
        if entry.live_permits.fetch_add(1, Ordering::AcqRel) == 0 {
            entry.freshness_signal.schedule_entry(entry);
        }
    }

    fn decrement_live_count(entry: &Entry) {
        let prior = entry.live_permits.fetch_sub(1, Ordering::AcqRel);
        assert!(prior > 0, "a permit decrements its live count exactly once");
        // A scheduled refresh may now be unnecessary. The watcher will discover that at the
        // already-scheduled refresh point, so dropping a permit never needs to wake it.
    }

    /// Returns the current permit state using one atomic load.
    #[must_use]
    pub fn state(&self) -> PermitState {
        match self.entry.state() {
            EntryState::Allowed => PermitState::Allowed,
            EntryState::Denied => PermitState::Denied,
            EntryState::Stale => PermitState::Stale,
            EntryState::Pending => {
                unreachable!("a permit is created only from an authoritative allowed state")
            }
        }
    }

    /// Waits until the permit transitions, then returns its new state.
    ///
    /// Observation continues past a denial, so a subject the authority allows again reports
    /// [`PermitState::Allowed`] on a later call. Only the current state is reported, never a
    /// backlog: a subject that is denied and allowed again between two calls reports nothing,
    /// because its state never differs from the one already returned. [`PermitState::Stale`] is
    /// terminal, and this method never completes again after returning it; readmit the subject
    /// instead.
    ///
    /// Cancelling this future loses no state change: the next call returns as soon as the state
    /// differs from the one already reported.
    pub async fn changed(&mut self) -> PermitState {
        loop {
            let state = self.state();
            if state != self.observed {
                self.observed = state;
                return state;
            }
            let _ = self.changes.changed().await;
        }
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
    /// marks existing permits stale.
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
        let state = GateState::new(Arc::clone(&client), config, metrics, time);
        let (watcher, health) = DecisionWatcher::new(Arc::clone(&state), client, metrics);
        (Self { state, metrics }, watcher, health)
    }

    /// Returns a cached authoritative admission without waiting or issuing I/O.
    ///
    /// This is the cached path and performs no I/O. `None` means the snapshot cannot answer — the
    /// subject is unknown, its verdict is still being fetched, its cached state went stale, or the
    /// watch is down — and the caller should fall back to [`PolicyGate::admit`].
    #[must_use]
    pub fn try_cached(&self, subject: &T) -> Option<Admission> {
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
    /// [`Wire`](crate::DecisionSourceErrorKind::Wire), or when the watcher is stopping.
    pub async fn admit(&self, subject: T) -> Result<Admission, AdmissionUnavailable> {
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
        subject: T,
        delay: Duration,
    ) -> Result<Admission, AdmissionUnavailable> {
        self.state.time.sleep(delay).await;
        self.admit(subject).await
    }
}

/// Authoritative admission outcome for a subject.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Verdict {
    Allowed,
    Denied,
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

impl From<Verdict> for EntryState {
    fn from(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Allowed => Self::Allowed,
            Verdict::Denied => Self::Denied,
        }
    }
}

type PendingFetch = Shared<BoxFuture<'static, Result<Verdict, DecisionSourceError>>>;

struct Observable<T> {
    sender: Sender<T>,
    receiver: Receiver<T>,
}

impl<T> Observable<T> {
    fn new(value: T) -> Self {
        let (sender, receiver) = async_watch::channel(value);
        Self { sender, receiver }
    }

    fn send(&self, value: T) {
        assert!(
            self.sender.send(value).is_ok(),
            "observable retains its receiver"
        );
    }

    fn subscribe(&self) -> Receiver<T> {
        self.receiver.clone()
    }
}

impl<T: Copy> Observable<T> {
    fn get(&self) -> T {
        *self.receiver.borrow()
    }
}

struct FreshnessSignal {
    freshness_enabled: bool,
    refresh_ahead: Option<Duration>,
    scheduled: Mutex<Option<Instant>>,
    changes: Observable<()>,
}

impl FreshnessSignal {
    fn new(freshness_enabled: bool, refresh_ahead: Option<Duration>) -> Self {
        Self {
            freshness_enabled,
            refresh_ahead,
            scheduled: Mutex::new(None),
            changes: Observable::new(()),
        }
    }

    fn schedule_entry(&self, entry: &Entry) {
        if !self.freshness_enabled {
            return;
        }
        if let Some(deadline) = entry.next_freshness_deadline(self.refresh_ahead) {
            self.schedule(deadline);
        }
    }

    fn schedule(&self, deadline: Instant) {
        let mut scheduled = self.scheduled.lock();
        if scheduled.is_some_and(|current| current <= deadline) {
            return;
        }
        *scheduled = Some(deadline);
        drop(scheduled);
        self.changes.send(());
    }

    fn take_scheduled(&self) -> Option<Instant> {
        self.scheduled.lock().take()
    }

    const fn freshness_enabled(&self) -> bool {
        self.freshness_enabled
    }

    const fn refresh_enabled(&self) -> bool {
        self.refresh_ahead.is_some()
    }

    fn subscribe(&self) -> Receiver<()> {
        self.changes.subscribe()
    }
}

#[derive(Debug)]
struct FreshnessState {
    generation: u64,
    fresh_until: Option<Instant>,
    refresh_attempted: bool,
    refresh_in_flight: bool,
}

/// Shared subject state observed by admissions and active streams.
// Streams poll state per frame; this prevents updates to neighboring subject entries from
// causing false sharing on 64- or 128-byte cache lines.
#[repr(align(128))]
pub(crate) struct Entry {
    // Atomic representation of EntryState.
    state: AtomicU8,
    last_touched: AtomicU64,
    fetch: Mutex<Option<PendingFetch>>,
    transitions: Observable<EntryState>,
    live_permits: AtomicUsize,
    freshness: Mutex<FreshnessState>,
    freshness_signal: Arc<FreshnessSignal>,
}

impl core::fmt::Debug for Entry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Entry")
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

impl Entry {
    fn pending(fetch: PendingFetch, freshness_signal: Arc<FreshnessSignal>) -> Self {
        Self {
            state: AtomicU8::new(EntryState::Pending as u8),
            last_touched: AtomicU64::new(0),
            fetch: Mutex::new(Some(fetch)),
            transitions: Observable::new(EntryState::Pending),
            live_permits: AtomicUsize::new(0),
            freshness: Mutex::new(FreshnessState {
                generation: 0,
                fresh_until: None,
                refresh_attempted: false,
                refresh_in_flight: false,
            }),
            freshness_signal,
        }
    }

    /// Loads the current entry state.
    pub(crate) fn state(&self) -> EntryState {
        decode_entry_state(self.state.load(Ordering::Acquire))
    }

    fn verdict(&self) -> Option<Verdict> {
        match self.state() {
            EntryState::Allowed => Some(Verdict::Allowed),
            EntryState::Denied => Some(Verdict::Denied),
            EntryState::Pending | EntryState::Stale => None,
        }
    }

    fn store(&self, state: EntryState) {
        self.state.store(state as u8, Ordering::Release);
        self.transitions.send(state);
    }

    fn compare_exchange(&self, current: EntryState, new: EntryState) -> Result<(), EntryState> {
        let result = self
            .state
            .compare_exchange(
                current as u8,
                new as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(decode_entry_state);
        if result.is_ok() {
            self.transitions.send(new);
        }
        result
    }

    fn subscribe(&self) -> Receiver<EntryState> {
        self.transitions.subscribe()
    }

    fn touch(&self, tick: u64) {
        self.last_touched.fetch_max(tick, Ordering::Relaxed);
    }

    fn admission(entry: TriompheArc<Self>) -> Option<Admission> {
        match entry.state() {
            EntryState::Allowed => Permit::from_admission(entry).map(Admission::Allowed),
            EntryState::Denied => Some(Admission::Denied),
            EntryState::Pending | EntryState::Stale => None,
        }
    }

    fn invalidate(&self) {
        if !self.freshness_signal.freshness_enabled() {
            self.store(EntryState::Stale);
            *self.fetch.lock() = None;
            return;
        }
        let mut freshness = self.freshness.lock();
        self.store(EntryState::Stale);
        if self.freshness_signal.refresh_enabled() {
            freshness.refresh_in_flight = false;
        }
        drop(freshness);
        *self.fetch.lock() = None;
    }

    fn compare_exchange_authoritative(
        &self,
        current: EntryState,
        new: EntryState,
        now: Instant,
        ttl: Option<Duration>,
        notify_scheduler: bool,
    ) -> Result<(), EntryState> {
        if ttl.is_none() {
            return self.compare_exchange(current, new);
        }
        let mut freshness = self.freshness.lock();
        self.compare_exchange(current, new)?;
        if self.freshness_signal.refresh_enabled() {
            freshness.generation = freshness.generation.wrapping_add(1);
            freshness.refresh_attempted = false;
            freshness.refresh_in_flight = false;
        }
        freshness.fresh_until = ttl.map(|ttl| {
            now.checked_add(ttl)
                .expect("validated freshness TTL produces an Instant")
        });
        drop(freshness);
        if notify_scheduler {
            self.freshness_signal.schedule_entry(self);
        }
        Ok(())
    }

    fn expire_if_due(&self, now: Instant) -> bool {
        let mut freshness = self.freshness.lock();
        let expired = freshness
            .fresh_until
            .is_some_and(|fresh_until| now >= fresh_until);
        if !expired || !matches!(self.state(), EntryState::Allowed | EntryState::Denied) {
            return false;
        }
        self.store(EntryState::Stale);
        if self.freshness_signal.refresh_enabled() {
            freshness.refresh_in_flight = false;
        }
        drop(freshness);
        *self.fetch.lock() = None;
        true
    }

    fn next_freshness_deadline(&self, refresh_ahead: Option<Duration>) -> Option<Instant> {
        if !matches!(self.state(), EntryState::Allowed | EntryState::Denied) {
            return None;
        }
        let freshness = self.freshness.lock();
        let fresh_until = freshness.fresh_until?;
        if let Some(refresh_ahead) = refresh_ahead {
            if self.live_permits.load(Ordering::Acquire) > 0 && !freshness.refresh_attempted {
                return fresh_until.checked_sub(refresh_ahead);
            }
        }
        Some(fresh_until)
    }

    fn begin_refresh_if_due(&self, now: Instant, refresh_ahead: Duration) -> Option<u64> {
        if !matches!(self.state(), EntryState::Allowed | EntryState::Denied)
            || self.live_permits.load(Ordering::Acquire) == 0
        {
            return None;
        }
        let mut freshness = self.freshness.lock();
        let fresh_until = freshness.fresh_until?;
        let refresh_at = fresh_until.checked_sub(refresh_ahead)?;
        if now < refresh_at || now >= fresh_until || freshness.refresh_attempted {
            return None;
        }
        freshness.refresh_attempted = true;
        freshness.refresh_in_flight = true;
        Some(freshness.generation)
    }

    fn apply_refresh_result(
        &self,
        generation: u64,
        result: &Result<Verdict, DecisionSourceError>,
        now: Instant,
        ttl: Duration,
    ) {
        let mut freshness = self.freshness.lock();
        if freshness.generation != generation || !freshness.refresh_in_flight {
            return;
        }
        freshness.refresh_in_flight = false;
        if freshness
            .fresh_until
            .is_some_and(|fresh_until| now >= fresh_until)
        {
            if matches!(self.state(), EntryState::Allowed | EntryState::Denied) {
                self.store(EntryState::Stale);
            }
        } else if let Ok(verdict) = result {
            freshness.generation = freshness.generation.wrapping_add(1);
            freshness.fresh_until = Some(
                now.checked_add(ttl)
                    .expect("validated freshness TTL produces an Instant"),
            );
            freshness.refresh_attempted = false;
            self.store((*verdict).into());
        }
        drop(freshness);
    }
}

struct SubjectSlot {
    entry: TriompheArc<Entry>,
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
        subject: T,
        now: Instant,
        create: impl FnOnce() -> TriompheArc<Entry>,
    ) -> TriompheArc<Entry> {
        let tick = self.tick(now);
        let mut entries = self.entries.lock();
        if let Some(slot) = entries.get_mut(&subject) {
            slot.entry.touch(tick);
            let entry = TriompheArc::clone(&slot.entry);
            self.evict(&mut entries, tick);
            return entry;
        }
        self.evict(&mut entries, tick);
        let entry = create();
        entry.touch(tick);
        let evicted = entries.push(
            subject,
            SubjectSlot {
                entry: TriompheArc::clone(&entry),
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
            slot.entry.touch(tick);
        }
        self.evict(&mut entries, tick);
    }

    fn peek(&self, subject: &T, now: Instant) -> Option<TriompheArc<Entry>> {
        let tick = self.tick(now);
        let mut entries = self.entries.lock();
        self.evict(&mut entries, tick);
        entries
            .peek(subject)
            .map(|slot| TriompheArc::clone(&slot.entry))
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
        predicate: impl FnOnce(&TriompheArc<Entry>) -> bool,
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

    fn for_each(&self, mut visit: impl FnMut(&T, &TriompheArc<Entry>)) {
        for (subject, slot) in self.entries.lock().iter() {
            visit(subject, &slot.entry);
        }
    }

    fn for_each_at(&self, now: Instant, mut visit: impl FnMut(&T, &TriompheArc<Entry>)) {
        let mut entries = self.entries.lock();
        self.evict(&mut entries, self.tick(now));
        for (subject, slot) in entries.iter() {
            visit(subject, &slot.entry);
        }
    }

    fn apply_if_current<R>(
        &self,
        subject: &T,
        entry: &TriompheArc<Entry>,
        now: Instant,
        apply: impl FnOnce() -> R,
    ) -> Option<R> {
        let mut entries = self.entries.lock();
        self.evict(&mut entries, self.tick(now));
        entries
            .peek(subject)
            .is_some_and(|slot| TriompheArc::ptr_eq(&slot.entry, entry))
            .then(apply)
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
            let expired = entries.peek_lru().is_some_and(|(_, slot)| {
                now.saturating_sub(slot.entry.last_touched.load(Ordering::Relaxed)) > subject_ttl
            });
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

type SubjectSnapshot<T> = HashMap<T, TriompheArc<Entry>>;

struct PublishState {
    generation: u64,
    next_allowed: Instant,
}

pub(crate) struct DecisionRefresh<T: Subject> {
    subject: T,
    entry: TriompheArc<Entry>,
    generation: u64,
    result: Result<Verdict, DecisionSourceError>,
}

pub(crate) type DecisionRefreshFuture<T> = BoxFuture<'static, DecisionRefresh<T>>;

/// Owns authoritative subject state and its cached read snapshot.
pub(crate) struct GateState<T: Subject, C: DecisionSource<T>, M: PolicyGateMetrics, D> {
    client: Arc<C>,
    time: D,
    connected: Observable<bool>,
    disconnected_since: Arc<Mutex<Option<Instant>>>,
    subjects: SubjectMap<T>,
    snapshot: ArcSwap<SubjectSnapshot<T>>,
    /// Every snapshot store happens under this lock; `generation` rejects rebuilds that started
    /// before a clear, and `connected` rejects rebuilds that started during one.
    publish: Mutex<PublishState>,
    shape_dirty: Arc<AtomicBool>,
    freshness_signal: Arc<FreshnessSignal>,
    config: PolicyGateConfig,
    stopping: AtomicBool,
    metrics: M,
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
    pub(crate) fn new(client: Arc<C>, config: &PolicyGateConfig, metrics: M, time: D) -> Arc<Self> {
        let now = time.now();
        let shape_dirty = Arc::new(AtomicBool::new(false));
        let freshness_signal = Arc::new(FreshnessSignal::new(
            config.decision_freshness_ttl().is_some(),
            config.decision_refresh_ahead(),
        ));
        Arc::new(Self {
            client,
            time,
            connected: Observable::new(false),
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
            freshness_signal,
            config: *config,
            stopping: AtomicBool::new(false),
            metrics,
        })
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

    pub(crate) fn time_driver(&self) -> D {
        self.time.clone()
    }

    pub(crate) fn freshness_changes(&self) -> Receiver<()> {
        self.freshness_signal.subscribe()
    }

    pub(crate) fn take_scheduled_freshness_deadline(&self) -> Option<Instant> {
        self.freshness_signal.take_scheduled()
    }

    pub(crate) const fn freshness_enabled(&self) -> bool {
        self.config.decision_freshness_ttl().is_some()
    }

    pub(crate) const fn refresh_enabled(&self) -> bool {
        self.config.decision_refresh_ahead().is_some()
    }

    /// Reads subject state through the snapshot and records its map recency.
    pub(crate) fn check(&self, subject: &T) -> Option<Admission> {
        let snapshot = self.snapshot.load();
        let entry = snapshot.get(subject)?;
        if self.freshness_enabled() {
            entry.expire_if_due(self.time.now());
        }
        // Pending and stale entries read as snapshot misses.
        entry.verdict()?;
        self.subjects.touch(subject, entry, self.time.now());
        Entry::admission(TriompheArc::clone(entry))
    }

    /// Resolves an authoritative subject verdict within the admission budget.
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn admit(&self, subject: T) -> Option<Admission> {
        let Some(deadline) = self.time.now().checked_add(self.config.admission_timeout()) else {
            return self.admission_timed_out();
        };
        let mut retry_delay = self.config.initial_admission_retry_delay();
        let mut connected = self.connected.subscribe();

        // A disconnect clears the map and marks entries Stale, so the connection is rechecked
        // after each await and Stale retries.
        // Lost races restart immediately; only a failed unary attempt takes the retry backoff.
        loop {
            if self.stopping.load(Ordering::Acquire) {
                return None;
            }
            let connected_or_stopping = async {
                loop {
                    if *connected.borrow() || self.stopping.load(Ordering::Acquire) {
                        return;
                    }
                    if connected.changed().await.is_err() {
                        return;
                    }
                }
            };
            let Ok(()) = self.time.timeout_at(deadline, connected_or_stopping).await else {
                return self.admission_timed_out();
            };
            if self.stopping.load(Ordering::Acquire) {
                return None;
            }

            let mut inserted = false;
            let entry = self
                .subjects
                .get_or_insert_with(subject.clone(), self.time.now(), || {
                    inserted = true;
                    TriompheArc::new(Entry::pending(
                        self.new_fetch_after(subject.clone(), None),
                        Arc::clone(&self.freshness_signal),
                    ))
                });
            if inserted {
                self.shape_dirty.store(true, Ordering::Release);
            } else if self.snapshot.load().get(&subject).is_none() {
                // Heal snapshot drift on this subject's next admission.
                self.shape_dirty.store(true, Ordering::Release);
            }
            self.republish_if_due();
            if self.time.now() >= deadline {
                return self.admission_timed_out();
            }
            if !*connected.borrow() {
                continue;
            }

            if self.freshness_enabled() {
                entry.expire_if_due(self.time.now());
            }
            let pending = match entry.state() {
                EntryState::Allowed | EntryState::Denied => {
                    self.metrics.map_hit();
                    if let Some(admission) = Entry::admission(entry) {
                        return Some(admission);
                    }
                    continue;
                }
                EntryState::Pending => {
                    // Subscribe before rechecking state so a watch verdict cannot be missed
                    // between observation and parking this admission.
                    let transitions = entry.subscribe();
                    if !matches!(entry.state(), EntryState::Pending) {
                        continue;
                    }
                    let fetch = entry.fetch.lock().clone();
                    match fetch {
                        Some(fetch) => (entry, fetch, transitions),
                        None => continue,
                    }
                }
                EntryState::Stale => {
                    let removed = self
                        .subjects
                        .remove_if(&subject, self.time.now(), |current| {
                            if !TriompheArc::ptr_eq(current, &entry) {
                                return false;
                            }
                            matches!(current.state(), EntryState::Stale)
                        });
                    if removed {
                        self.shape_dirty.store(true, Ordering::Release);
                    }
                    self.republish_if_due();
                    continue;
                }
            };

            let (entry, fetch, mut transitions) = pending;
            let completed_fetch = fetch.clone();
            // The fetch bounds one attempt; this outer deadline also covers the retry loop.
            let result = self
                .time
                .timeout_at(deadline, async {
                    let fetch = fetch.fuse();
                    let connection_change = connected.changed().fuse();
                    let entry_change = transitions.changed().fuse();
                    futures_util::pin_mut!(fetch, connection_change, entry_change);
                    futures_util::select! {
                        result = fetch => Some(result),
                        _ = connection_change => None,
                        _ = entry_change => None,
                    }
                })
                .await;
            let result = match result {
                Ok(Some(result)) => result,
                Ok(None) => {
                    if self.stopping.load(Ordering::Acquire) {
                        return None;
                    }
                    continue;
                }
                Err(_) => {
                    // An authoritative transition may race the deadline notification.
                    if let Some(admission) = Entry::admission(entry) {
                        return Some(admission);
                    }
                    return self.admission_timed_out();
                }
            };
            if !self.apply_fetch_result(
                subject.clone(),
                &entry,
                &completed_fetch,
                &result,
                deadline,
            ) {
                return self.admission_timed_out();
            }
            if !*connected.borrow() {
                continue;
            }
            match entry.state() {
                EntryState::Allowed | EntryState::Denied => {
                    if let Some(admission) = Entry::admission(entry) {
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
            if self
                .time
                .timeout_at(deadline, self.time.sleep(retry_delay))
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

    fn new_fetch_after(&self, subject: T, delay: Option<Duration>) -> PendingFetch {
        // `delay` is the permanent-failure cooldown; it starts when the first joiner polls.
        let client = Arc::clone(&self.client);
        let time = self.time.clone();
        let metrics = self.metrics;
        let unary_timeout = self.config.unary_timeout();
        async move {
            if let Some(delay) = delay {
                time.sleep(delay).await;
            }
            metrics.unary_call();
            let result = async {
                let state = time
                    .timeout(unary_timeout, client.get_subject_decision(&subject))
                    .await
                    .map_err(|_| {
                        DecisionSourceError::new(
                            DecisionSourceErrorKind::Transient,
                            "subject state lookup timed out",
                        )
                    })??;
                match state {
                    Decision::Allowed => Ok(Verdict::Allowed),
                    Decision::Denied => Ok(Verdict::Denied),
                    Decision::Unspecified => Err(DecisionSourceError::new(
                        DecisionSourceErrorKind::Transient,
                        "decision source returned a non-authoritative decision",
                    )),
                }
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
            result
        }
        .boxed()
        .shared()
    }

    fn apply_fetch_result(
        &self,
        subject: T,
        entry: &TriompheArc<Entry>,
        completed_fetch: &PendingFetch,
        result: &Result<Verdict, DecisionSourceError>,
        deadline: Instant,
    ) -> bool {
        if let Ok(verdict) = result {
            // A watch event that wins this CAS supplies the verdict that stands.
            match entry.compare_exchange_authoritative(
                EntryState::Pending,
                (*verdict).into(),
                self.time.now(),
                self.config.decision_freshness_ttl(),
                true,
            ) {
                Ok(()) => *entry.fetch.lock() = None,
                Err(
                    EntryState::Pending
                    | EntryState::Allowed
                    | EntryState::Denied
                    | EntryState::Stale,
                ) => {}
            }
            return true;
        }

        if result.as_ref().is_err_and(is_permanent_status) {
            let retry =
                self.new_fetch_after(subject, Some(self.config.permanent_failure_cooldown()));
            // The cooldown starts when a later caller first polls it, so idle bad subjects are free
            // while active ones make at most one decision-source call per second.
            let mut fetch = entry.fetch.lock();
            if matches!(entry.state(), EntryState::Pending)
                && fetch
                    .as_ref()
                    .is_some_and(|fetch| Shared::ptr_eq(fetch, completed_fetch))
            {
                *fetch = Some(retry);
            }
            return true;
        }

        // remove_if runs its predicate under the map lock, making the
        // Pending -> Stale transition and removal one indivisible operation.
        let removed = self
            .subjects
            .remove_if(&subject, self.time.now(), |current| {
                if !TriompheArc::ptr_eq(current, entry) {
                    return false;
                }
                entry
                    .compare_exchange(EntryState::Pending, EntryState::Stale)
                    .is_ok()
            });
        if removed {
            self.shape_dirty.store(true, Ordering::Release);
        }
        self.republish_if_due();
        if self.time.now() >= deadline {
            return false;
        }
        true
    }

    fn admission_timed_out(&self) -> Option<Admission> {
        self.metrics.admission_timeout();
        None
    }

    pub(crate) fn freshness_expiry_work(&self) -> Option<Instant> {
        if !self.freshness_enabled() || self.refresh_enabled() {
            return None;
        }
        let now = self.time.now();
        let mut next = None;
        self.subjects.for_each_at(now, |_, entry| {
            entry.expire_if_due(now);
            if let Some(deadline) = entry.next_freshness_deadline(None) {
                next = Some(next.map_or(deadline, |current: Instant| current.min(deadline)));
            }
        });
        self.republish_if_due();
        next
    }

    pub(crate) fn freshness_work(&self) -> (Vec<DecisionRefreshFuture<T>>, Option<Instant>) {
        let (Some(_), Some(refresh_ahead)) = (
            self.config.decision_freshness_ttl(),
            self.config.decision_refresh_ahead(),
        ) else {
            return (Vec::new(), None);
        };
        let now = self.time.now();
        let mut due = Vec::new();
        let mut next = None;
        self.subjects.for_each_at(now, |subject, entry| {
            entry.expire_if_due(now);
            if let Some(generation) = entry.begin_refresh_if_due(now, refresh_ahead) {
                due.push((subject.clone(), TriompheArc::clone(entry), generation));
            }
            if let Some(deadline) = entry.next_freshness_deadline(Some(refresh_ahead)) {
                next = Some(next.map_or(deadline, |current: Instant| current.min(deadline)));
            }
        });
        self.republish_if_due();
        (
            due.into_iter()
                .map(|(subject, entry, generation)| {
                    self.new_decision_refresh(subject, entry, generation)
                })
                .collect(),
            next,
        )
    }

    pub(crate) fn apply_decision_refresh(&self, refresh: DecisionRefresh<T>) -> Option<Instant> {
        let now = self.time.now();
        let DecisionRefresh {
            subject,
            entry,
            generation,
            result,
        } = refresh;
        let next = self.subjects.apply_if_current(&subject, &entry, now, || {
            entry.apply_refresh_result(
                generation,
                &result,
                now,
                self.config
                    .decision_freshness_ttl()
                    .expect("refreshes exist only when freshness is enabled"),
            );
            entry.next_freshness_deadline(self.config.decision_refresh_ahead())
        });
        self.republish_if_due();
        next.flatten()
    }

    fn new_decision_refresh(
        &self,
        subject: T,
        entry: TriompheArc<Entry>,
        generation: u64,
    ) -> DecisionRefreshFuture<T> {
        let client = Arc::clone(&self.client);
        let time = self.time.clone();
        let metrics = self.metrics;
        let unary_timeout = self.config.unary_timeout();
        async move {
            metrics.unary_call();
            let result = async {
                let decision = time
                    .timeout(unary_timeout, client.get_subject_decision(&subject))
                    .await
                    .map_err(|_| {
                        DecisionSourceError::new(
                            DecisionSourceErrorKind::Transient,
                            "subject decision refresh timed out",
                        )
                    })??;
                match decision {
                    Decision::Allowed => Ok(Verdict::Allowed),
                    Decision::Denied => Ok(Verdict::Denied),
                    Decision::Unspecified => Err(DecisionSourceError::new(
                        DecisionSourceErrorKind::Transient,
                        "decision source returned a non-authoritative decision",
                    )),
                }
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
            DecisionRefresh {
                subject,
                entry,
                generation,
                result,
            }
        }
        .boxed()
    }

    /// Marks the watch connected after clearing state from the prior connection.
    pub(crate) fn watch_connected(&self) {
        // Clear before publishing connected so no state from the old watch is served.
        self.publish_empty(|| {});
        self.subjects.clear();
        self.connected.send(true);
        self.metrics.set_watch_connected(true);
    }

    /// Marks a continuously open watch as healthy.
    pub(crate) fn watch_stable(&self) {
        *self.disconnected_since.lock() = None;
    }

    /// Marks the watch disconnected before clearing its subject state.
    pub(crate) fn watch_disconnected(&self) {
        self.publish_empty(|| {
            self.connected.send(false);
            self.metrics.set_watch_connected(false);
            self.mark_disconnected();
        });
        self.subjects.clear();
    }

    /// Applies one watch change to a subject already known to this process.
    pub(crate) fn apply_change(&self, change: &DecisionChange<T>) -> Option<Instant> {
        let subject = &change.subject;
        // Absent subjects are ignored: a vanished entry is re-admitted by its stream or next request.
        if let Some(verdict) = decode_decision(change.decision) {
            let entry = self.subjects.peek(subject, self.time.now());
            self.republish_if_due();
            if let Some(entry) = entry {
                let next = verdict.into();
                loop {
                    match entry.state() {
                        EntryState::Stale => break,
                        current @ (EntryState::Pending
                        | EntryState::Allowed
                        | EntryState::Denied) => match entry.compare_exchange_authoritative(
                            current,
                            next,
                            self.time.now(),
                            self.config.decision_freshness_ttl(),
                            false,
                        ) {
                            Ok(()) => {
                                *entry.fetch.lock() = None;
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
                return entry.next_freshness_deadline(self.config.decision_refresh_ahead());
            }
        } else {
            let removed = self.subjects.remove(subject, self.time.now());
            if removed {
                self.shape_dirty.store(true, Ordering::Release);
            }
            self.republish_if_due();
        }
        None
    }

    /// Rate-limited snapshot rebuild run by the slow-path operation that finds the dirty flag
    /// after the window; until it runs, a new subject's requests take the map path in `admit`.
    fn republish_if_due(&self) {
        if !self.shape_dirty.load(Ordering::Acquire) {
            return;
        }
        let generation = {
            let mut publish = self.publish.lock();
            let now = self.time.now();
            if now < publish.next_allowed {
                return;
            }
            publish.next_allowed = now + self.config.snapshot_republish_interval();
            publish.generation
        };

        self.shape_dirty.store(false, Ordering::Release);
        let mut entries = HashMap::new();
        self.subjects.for_each(|subject, entry| {
            entries.insert(subject.clone(), TriompheArc::clone(entry));
        });

        let publish = self.publish.lock();
        // `connected` flips false under this lock, so a rebuild that claimed after a disconnect's
        // empty publish but copied the map before its clear is dropped here.
        if publish.generation == generation && self.connected.get() {
            self.snapshot.store(Arc::new(entries));
            self.metrics.snapshot_republish();
        }
    }

    fn mark_disconnected(&self) {
        let mut since = self.disconnected_since.lock();
        if since.is_none() {
            *since = Some(self.time.now());
        }
    }
}

impl<T: Subject, C: DecisionSource<T>, M: PolicyGateMetrics, D: TimeDriver> GateState<T, C, M, D> {
    /// Stops new admissions before shutdown tears down the watch.
    pub(crate) fn watch_stopping(&self) {
        self.stopping.store(true, Ordering::Release);
        self.publish_empty(|| {
            self.connected.send(false);
            self.metrics.set_watch_connected(false);
            self.mark_disconnected();
        });
        self.subjects.clear();
    }

    fn publish_empty(&self, after_publish: impl FnOnce()) {
        let mut publish = self.publish.lock();
        publish.generation += 1;
        // The empty snapshot publish is the disconnect linearization point.
        self.snapshot.store(Arc::new(HashMap::new()));
        after_publish();
    }
}

fn decode_entry_state(raw: u8) -> EntryState {
    match raw {
        0 => EntryState::Pending,
        1 => EntryState::Allowed,
        2 => EntryState::Denied,
        3 => EntryState::Stale,
        _ => unreachable!("entry state is always written from EntryState"),
    }
}

const fn decode_decision(state: Decision) -> Option<Verdict> {
    match state {
        Decision::Allowed => Some(Verdict::Allowed),
        Decision::Denied => Some(Verdict::Denied),
        Decision::Unspecified => None,
    }
}

const fn is_permanent_status(error: &DecisionSourceError) -> bool {
    matches!(
        error.kind(),
        DecisionSourceErrorKind::Permanent | DecisionSourceErrorKind::Wire
    )
}

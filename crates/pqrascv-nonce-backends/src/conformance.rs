//! Store-agnostic conformance suite for [`NonceLedger`] implementations.
//!
//! The functions in this module exercise the
//! [`NonceLedger` TTL & crash-recovery contract](pqrascv_core::nonce) against
//! *any* implementation, given a factory. They are invoked by this crate's
//! own tests against an in-memory fake (always-on in CI) and by the gated
//! live-server tests against real Redis / Postgres.
//!
//! Each `assert_*` function panics on contract violation (the conventional
//! shape for a reusable test helper), so callers wrap them in `#[test]`
//! functions. Panicking *is* their contract, so `missing_panics_doc` is
//! allowed module-wide rather than documented per function.

#![allow(clippy::missing_panics_doc)]

use pqrascv_core::error::PqRascvError;
use pqrascv_core::nonce::NonceLedger;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::rc::Rc;

// ── In-memory shared-store fake ────────────────────────────────────────────

/// Shared backing store for [`SharedMemoryNonceLedger`].
///
/// Models a single persistent store (Redis/Postgres) that multiple ledger
/// *handles* connect to. Cloning a [`SharedMemoryNonceLedger`] yields another
/// handle on the **same** store, mirroring two clients pointed at one server —
/// the substrate for the distributed-replay adversarial test.
#[derive(Debug, Default)]
struct SharedStore {
    /// Registered-but-unconsumed nonces → optional expiry deadline (secs).
    pending: BTreeMap<[u8; 32], Option<u64>>,
    consumed: BTreeSet<[u8; 32]>,
    consumed_order: VecDeque<[u8; 32]>,
    max_consumed: usize,
}

impl SharedStore {
    fn is_expired(deadline: Option<u64>, now: u64) -> bool {
        matches!(deadline, Some(deadline) if now > deadline)
    }
}

/// In-memory [`NonceLedger`] whose state lives in a shared, cloneable store.
///
/// This is the always-on conformance target and the fake used to demonstrate
/// distributed single-use unconditionally (two handles, one store). It honors
/// the same TTL and FIFO-eviction semantics as
/// `pqrascv_core::nonce::InMemoryNonceLedger`, but with shared ownership so a
/// nonce consumed via one handle is rejected via another.
#[derive(Clone, Debug)]
pub struct SharedMemoryNonceLedger {
    store: Rc<RefCell<SharedStore>>,
}

impl SharedMemoryNonceLedger {
    /// Creates a new ledger handle over a fresh shared store.
    ///
    /// `max_consumed` bounds the consumed-history FIFO; `0` selects
    /// [`pqrascv_core::nonce::DEFAULT_MAX_CONSUMED`].
    #[must_use]
    pub fn new(max_consumed: usize) -> Self {
        let max_consumed = if max_consumed == 0 {
            pqrascv_core::nonce::DEFAULT_MAX_CONSUMED
        } else {
            max_consumed
        };
        Self {
            store: Rc::new(RefCell::new(SharedStore {
                max_consumed,
                ..SharedStore::default()
            })),
        }
    }

    /// Returns a second handle on the **same** store (a "different node").
    #[must_use]
    pub fn handle(&self) -> Self {
        Self {
            store: Rc::clone(&self.store),
        }
    }

    /// Number of entries currently in the consumed set (test introspection).
    #[must_use]
    pub fn consumed_len(&self) -> usize {
        self.store.borrow().consumed.len()
    }

    fn register_inner(
        &mut self,
        nonce: [u8; 32],
        deadline: Option<u64>,
        now: u64,
    ) -> Result<pqrascv_core::nonce::NonceHandle, PqRascvError> {
        let mut store = self.store.borrow_mut();
        if let Some(&existing) = store.pending.get(&nonce) {
            if !SharedStore::is_expired(existing, now) {
                return Err(PqRascvError::InvalidNonce);
            }
        }
        if store.consumed.contains(&nonce) {
            return Err(PqRascvError::InvalidNonce);
        }
        store.pending.insert(nonce, deadline);
        drop(store);
        // Re-register through core's trait to obtain a NonceHandle without
        // duplicating its private constructor: core's InMemoryNonceLedger is
        // not shared, so we synthesize the handle via a throwaway ledger.
        synthesize_handle(nonce)
    }

    fn consume_inner(&mut self, nonce: &[u8; 32], now: u64) -> Result<(), PqRascvError> {
        let mut store = self.store.borrow_mut();
        match store.pending.remove(nonce) {
            None => Err(PqRascvError::InvalidNonce),
            Some(deadline) if SharedStore::is_expired(deadline, now) => {
                Err(PqRascvError::InvalidNonce)
            }
            Some(_) => {
                if store.consumed.len() >= store.max_consumed {
                    if let Some(oldest) = store.consumed_order.pop_front() {
                        store.consumed.remove(&oldest);
                    }
                }
                store.consumed.insert(*nonce);
                store.consumed_order.push_back(*nonce);
                Ok(())
            }
        }
    }
}

/// Produces a [`NonceHandle`](pqrascv_core::nonce::NonceHandle) for `nonce`.
///
/// `NonceHandle` has no public constructor (single-issue is enforced at the
/// type level), so we mint one via a throwaway core ledger.
fn synthesize_handle(nonce: [u8; 32]) -> Result<pqrascv_core::nonce::NonceHandle, PqRascvError> {
    use pqrascv_core::nonce::InMemoryNonceLedger;
    let mut tmp = InMemoryNonceLedger::default();
    tmp.register(nonce)
}

impl NonceLedger for SharedMemoryNonceLedger {
    fn register(
        &mut self,
        nonce: [u8; 32],
    ) -> Result<pqrascv_core::nonce::NonceHandle, PqRascvError> {
        self.register_inner(nonce, None, 0)
    }

    fn register_with_ttl(
        &mut self,
        nonce: [u8; 32],
        now: u64,
        ttl_secs: u64,
    ) -> Result<pqrascv_core::nonce::NonceHandle, PqRascvError> {
        let deadline = if ttl_secs == 0 {
            None
        } else {
            Some(now.saturating_add(ttl_secs))
        };
        self.register_inner(nonce, deadline, now)
    }

    fn consume(&mut self, nonce: &[u8; 32]) -> Result<(), PqRascvError> {
        self.consume_inner(nonce, 0)
    }

    fn consume_at(&mut self, nonce: &[u8; 32], now: u64) -> Result<(), PqRascvError> {
        self.consume_inner(nonce, now)
    }
}

// ── Contract assertions (store-agnostic) ───────────────────────────────────

/// (a) A fresh nonce registers and consumes exactly once.
pub fn assert_fresh_nonce_registers_and_consumes<L, F>(mut make: F)
where
    L: NonceLedger,
    F: FnMut() -> L,
{
    let mut ledger = make();
    let nonce = [0x01u8; 32];
    let handle = ledger
        .register(nonce)
        .expect("fresh register should succeed");
    assert_eq!(handle.as_bytes(), &nonce);
    ledger
        .consume(&nonce)
        .expect("first consume should succeed");
}

/// (b) A second consume of the same nonce is rejected (single-use).
pub fn assert_second_consume_rejected<L, F>(mut make: F)
where
    L: NonceLedger,
    F: FnMut() -> L,
{
    let mut ledger = make();
    let nonce = [0x02u8; 32];
    ledger.register(nonce).unwrap();
    ledger.consume(&nonce).unwrap();
    assert_eq!(
        ledger.consume(&nonce),
        Err(PqRascvError::InvalidNonce),
        "replay (second consume) must be rejected"
    );
}

/// Consuming an unknown nonce is rejected.
pub fn assert_unknown_nonce_rejected<L, F>(mut make: F)
where
    L: NonceLedger,
    F: FnMut() -> L,
{
    let mut ledger = make();
    assert_eq!(
        ledger.consume(&[0xEEu8; 32]),
        Err(PqRascvError::InvalidNonce),
        "consuming a never-registered nonce must be rejected"
    );
}

/// (c) After TTL expiry the nonce is evicted and re-registerable.
pub fn assert_ttl_expiry_evicts_and_allows_reregister<L, F>(mut make: F)
where
    L: NonceLedger,
    F: FnMut() -> L,
{
    let mut ledger = make();
    let nonce = [0x03u8; 32];
    ledger.register_with_ttl(nonce, 1_000, 60).unwrap();

    // At the deadline exactly (1_060): still live.
    // (Use a fresh nonce so we don't consume the one under test.)
    let live = [0x04u8; 32];
    ledger.register_with_ttl(live, 1_000, 60).unwrap();
    ledger
        .consume_at(&live, 1_060)
        .expect("deadline boundary is inclusive — still live");

    // Strictly past the deadline: expired, consume rejected.
    assert_eq!(
        ledger.consume_at(&nonce, 1_061),
        Err(PqRascvError::InvalidNonce),
        "consuming after TTL expiry must be rejected"
    );

    // The expired value can be registered fresh and consumed.
    ledger
        .register_with_ttl(nonce, 2_000, 60)
        .expect("expired nonce must be re-registerable");
    ledger
        .consume_at(&nonce, 2_010)
        .expect("re-registered nonce consumes once");
}

/// (d) Eviction bound is respected (FIFO) for a bounded impl.
///
/// `consumed_len` reports the current consumed-set size for the impl under
/// test. The factory must yield a ledger with `max_consumed == cap`.
pub fn assert_eviction_bound_respected<L, F, C>(mut make: F, cap: usize, consumed_len: C)
where
    L: NonceLedger,
    F: FnMut() -> L,
    C: Fn(&L) -> usize,
{
    assert!(cap > 0, "cap must be positive");
    let mut ledger = make();

    // Fill to the cap.
    for i in 0..cap {
        let mut nonce = [0u8; 32];
        nonce[0] = u8::try_from(i % 251).unwrap();
        nonce[1] = u8::try_from(i / 251).unwrap();
        nonce[2] = 0xA0;
        ledger.register(nonce).unwrap();
        ledger.consume(&nonce).unwrap();
    }
    assert_eq!(consumed_len(&ledger), cap, "consumed set should be at cap");

    // One more consume evicts the oldest; size stays at cap.
    let extra = [0xFFu8; 32];
    ledger.register(extra).unwrap();
    ledger.consume(&extra).unwrap();
    assert_eq!(
        consumed_len(&ledger),
        cap,
        "eviction bound must be maintained after overflow"
    );
}

/// Distributed single-use: a nonce consumed via handle A cannot be consumed
/// via handle B sharing the same store.
///
/// `make_pair` yields two handles over **one** store.
pub fn assert_distributed_single_use<L, F>(mut make_pair: F)
where
    L: NonceLedger,
    F: FnMut() -> (L, L),
{
    let (mut node_a, mut node_b) = make_pair();
    let nonce = [0x55u8; 32];

    // Either handle may register (shared store), node A consumes.
    node_a.register(nonce).unwrap();
    node_a.consume(&nonce).unwrap();

    // Node B, pointed at the same store, must reject the replayed nonce.
    assert_eq!(
        node_b.consume(&nonce),
        Err(PqRascvError::InvalidNonce),
        "a nonce consumed on one node must be rejected on another sharing the store"
    );
}

// ── Tests: run the contract against the in-memory shared-store fake ─────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> SharedMemoryNonceLedger {
        SharedMemoryNonceLedger::new(0)
    }

    #[test]
    fn fresh_nonce_registers_and_consumes() {
        assert_fresh_nonce_registers_and_consumes(fresh);
    }

    #[test]
    fn second_consume_rejected() {
        assert_second_consume_rejected(fresh);
    }

    #[test]
    fn unknown_nonce_rejected() {
        assert_unknown_nonce_rejected(fresh);
    }

    #[test]
    fn ttl_expiry_evicts_and_allows_reregister() {
        assert_ttl_expiry_evicts_and_allows_reregister(fresh);
    }

    #[test]
    fn eviction_bound_respected() {
        assert_eviction_bound_respected(
            || SharedMemoryNonceLedger::new(8),
            8,
            SharedMemoryNonceLedger::consumed_len,
        );
    }

    #[test]
    fn distributed_single_use_shared_store() {
        assert_distributed_single_use(|| {
            let a = SharedMemoryNonceLedger::new(0);
            let b = a.handle();
            (a, b)
        });
    }

    #[test]
    fn register_on_one_handle_consume_on_another() {
        // Cross-handle: A registers, B consumes, A replay rejected.
        let mut a = SharedMemoryNonceLedger::new(0);
        let mut b = a.handle();
        let nonce = [0x66u8; 32];
        a.register(nonce).unwrap();
        b.consume(&nonce).unwrap();
        assert_eq!(a.consume(&nonce), Err(PqRascvError::InvalidNonce));
    }
}

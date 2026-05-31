//! Cryptographic authentication for federation trust mutations.
//!
//! Federation governance previously trusted plain-string verifier identities:
//! any process that could name a member could approve a policy epoch, cast a
//! consensus vote, contribute a Byzantine quorum signature, or file temporal
//! ambiguity evidence against another verifier. This module closes that gap by
//! binding every such mutation to an ML-DSA-65 signature produced by the
//! claimed verifier's signing key, verified against the `public_key` carried in
//! that verifier's [`VerifierIdentity`](crate::verifier_identity::VerifierIdentity).
//!
//! # Domain separation
//!
//! Each mutation class is signed under a distinct context string
//! (`CTX_APPROVAL`, `CTX_VOTE`, `CTX_QUORUM`, `CTX_OBSERVER`). A signature
//! minted for one class cannot be replayed as another because ML-DSA-65
//! verification binds the context into the verification equation.
//!
//! # Canonical payloads
//!
//! The signed message is a deterministic, length-delimited encoding of every
//! field that defines the mutation's *scope* (federation id, epoch id,
//! attestation id, quorum id + state hash, observer/violator ids + clocks).
//! Length-prefixing prevents field-boundary ambiguity (a `"ab"+"c"` vs
//! `"a"+"bc"` collision), so a signature is valid only for the exact tuple it
//! was produced over — this is what makes a vote signed for attestation `A`
//! useless when replayed against attestation `B`.

use alloc::vec::Vec;

use crate::digest::TypedDigest;
use crate::federation_time::HybridLogicalClock;

/// ML-DSA-65 verifying-key length in bytes (FIPS 204 §5).
pub const ML_DSA_65_VK_LEN: usize = 1952;
/// ML-DSA-65 signature length in bytes.
pub const ML_DSA_65_SIG_LEN: usize = 3309;

/// Domain-separation context for federated policy-epoch approvals.
pub const CTX_APPROVAL: &[u8] = b"pqrascv-fed-approval-v1";
/// Domain-separation context for distributed-consensus votes.
pub const CTX_VOTE: &[u8] = b"pqrascv-fed-vote-v1";
/// Domain-separation context for Byzantine quorum-certificate votes.
pub const CTX_QUORUM: &[u8] = b"pqrascv-fed-quorum-v1";
/// Domain-separation context for temporal-ambiguity observer evidence.
pub const CTX_OBSERVER: &[u8] = b"pqrascv-fed-observer-v1";

// ── Canonical payload encoder ─────────────────────────────────────────────

/// Builds deterministic, length-delimited signing payloads.
///
/// Every variable-length field is prefixed with its length as an 8-byte
/// little-endian integer, so distinct field tuples can never produce the same
/// byte string.
struct PayloadWriter(Vec<u8>);

impl PayloadWriter {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    fn bytes(&mut self, b: &[u8]) {
        self.u64(b.len() as u64);
        self.0.extend_from_slice(b);
    }

    fn str(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }

    fn bool(&mut self, b: bool) {
        self.0.push(u8::from(b));
    }

    /// Encodes an `Option<u64>` as a presence byte followed by the value
    /// (zero when absent), so `Some(0)` and `None` encode distinctly.
    fn opt_u64(&mut self, v: Option<u64>) {
        self.0.push(u8::from(v.is_some()));
        self.u64(v.unwrap_or(0));
    }

    fn clock(&mut self, c: &HybridLogicalClock) {
        self.u64(c.logical_counter);
        self.u64(c.physical_timestamp);
        // The clock's own signature is part of its identity for replay binding.
        self.bytes(&c.signature);
    }

    fn digest(&mut self, dg: &TypedDigest) {
        // Bind both algorithm and value: equality of TypedDigest is defined over
        // both, so a SHA-256 and SHA3-256 digest with the same bytes are distinct.
        self.str(dg.algorithm.name());
        self.bytes(&dg.value);
    }

    fn opt_digest(&mut self, d: Option<&TypedDigest>) {
        match d {
            Some(dg) => {
                self.0.push(1);
                self.digest(dg);
            }
            None => self.0.push(0),
        }
    }

    fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

// ── Canonical payload builders ────────────────────────────────────────────

/// Canonical signing payload for a federated policy-epoch approval.
///
/// Binds the federation, the epoch being approved (and its predecessor, so an
/// approval cannot be replayed onto a different epoch chain), and the approving
/// verifier's identity.
#[must_use]
pub fn approval_payload(
    federation_id: &str,
    epoch_id: u64,
    previous_epoch: Option<u64>,
    verifier_id: &str,
) -> Vec<u8> {
    let mut w = PayloadWriter::new();
    w.str(federation_id);
    w.u64(epoch_id);
    w.opt_u64(previous_epoch);
    w.str(verifier_id);
    w.into_vec()
}

/// Canonical signing payload for a distributed-consensus vote.
///
/// Binds the attestation under evaluation, the voting verifier, and the
/// trust verdict — so a vote signed for one attestation or verdict cannot be
/// replayed for another.
#[must_use]
pub fn vote_payload(attestation_id: &str, verifier_id: &str, trusted: bool) -> Vec<u8> {
    let mut w = PayloadWriter::new();
    w.str(attestation_id);
    w.str(verifier_id);
    w.bool(trusted);
    w.into_vec()
}

/// Canonical signing payload for a Byzantine quorum-certificate vote.
///
/// Binds the quorum instance, the agreed state hash, and the voting verifier.
#[must_use]
pub fn quorum_payload(quorum_id: &str, state_hash: &TypedDigest, verifier_id: &str) -> Vec<u8> {
    let mut w = PayloadWriter::new();
    w.str(quorum_id);
    w.digest(state_hash);
    w.str(verifier_id);
    w.into_vec()
}

/// Canonical signing payload for temporal-ambiguity observer evidence.
///
/// Binds the observer, the accused verifier, both clock readings, the
/// violation type, and any associated event hash.
#[must_use]
pub fn observer_payload(
    observing_verifier_id: &str,
    violating_verifier_id: &str,
    violating_clock: &HybridLogicalClock,
    reference_clock: &HybridLogicalClock,
    violation_type: &str,
    event_hash: Option<&TypedDigest>,
) -> Vec<u8> {
    let mut w = PayloadWriter::new();
    w.str(observing_verifier_id);
    w.str(violating_verifier_id);
    w.clock(violating_clock);
    w.clock(reference_clock);
    w.str(violation_type);
    w.opt_digest(event_hash);
    w.into_vec()
}

// ── Verification ──────────────────────────────────────────────────────────

/// Verifies an ML-DSA-65 `signature` over `message` under `context` using the
/// encoded `verifying_key`.
///
/// Returns `false` — never panics — for any malformed input (wrong key length,
/// wrong signature length, undecodable key or signature) as well as for a
/// genuine signature mismatch. This is the single fail-closed primitive every
/// federation mutation path routes through.
#[must_use]
pub fn verify_ml_dsa(
    message: &[u8],
    context: &[u8],
    verifying_key: &[u8],
    signature: &[u8],
) -> bool {
    use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};

    if verifying_key.len() != ML_DSA_65_VK_LEN || signature.len() != ML_DSA_65_SIG_LEN {
        return false;
    }
    let Ok(vk_array) = <[u8; ML_DSA_65_VK_LEN]>::try_from(verifying_key) else {
        return false;
    };
    let encoded_vk = EncodedVerifyingKey::<MlDsa65>::from(vk_array);
    let vk = VerifyingKey::<MlDsa65>::decode(&encoded_vk);

    let Ok(sig_array) = <[u8; ML_DSA_65_SIG_LEN]>::try_from(signature) else {
        return false;
    };
    let encoded_sig = ml_dsa::EncodedSignature::<MlDsa65>::from(sig_array);
    let Some(sig) = Signature::<MlDsa65>::decode(&encoded_sig) else {
        return false;
    };

    vk.verify_with_context(message, context, &sig)
}

/// Signs `message` under `context` with the 32-byte ML-DSA-65 `seed`.
///
/// Provided for legitimate signers (and tests) constructing authenticated
/// federation mutations. Returns `None` if the seed is the wrong length or
/// signing fails.
#[must_use]
pub fn sign_ml_dsa(message: &[u8], context: &[u8], seed: &[u8]) -> Option<Vec<u8>> {
    use ml_dsa::{KeyGen, MlDsa65};

    let seed_array = <[u8; 32]>::try_from(seed).ok()?;
    let b32 = ml_dsa::B32::from(seed_array);
    let sk = MlDsa65::from_seed(&b32);
    let sig = sk.signing_key().sign_deterministic(message, context).ok()?;
    Some(sig.encode().to_vec())
}

/// Test-only signing helpers shared across the federation modules' adversarial
/// test suites. Crate-visible (not part of the public API) so each module can
/// mint real ML-DSA-65 keypairs and signatures without duplicating the wiring.
#[cfg(test)]
pub(crate) mod test_keys {
    use alloc::vec::Vec;

    /// Generates a fresh ML-DSA-65 keypair `(seed, verifying_key_bytes)`.
    #[must_use]
    pub(crate) fn keypair() -> ([u8; 32], Vec<u8>) {
        use getrandom::rand_core::UnwrapErr;
        use getrandom::SysRng;
        use ml_dsa::signature::Keypair;
        use ml_dsa::{KeyGen, MlDsa65};

        let mut rng = UnwrapErr(SysRng);
        let sk = MlDsa65::key_gen(&mut rng);
        let seed: [u8; 32] = (*sk.to_seed()).try_into().unwrap();
        let vk: Vec<u8> = sk.verifying_key().encode().to_vec();
        (seed, vk)
    }
}

#[cfg(test)]
mod tests {
    use super::test_keys::keypair;
    use super::*;
    use crate::digest::{DigestAlgorithm, TypedDigest};
    use alloc::vec;

    #[test]
    fn valid_signature_over_payload_verifies() {
        let (seed, vk) = keypair();
        let payload = approval_payload("fed-1", 7, Some(6), "v0");
        let sig = sign_ml_dsa(&payload, CTX_APPROVAL, &seed).unwrap();
        assert!(verify_ml_dsa(&payload, CTX_APPROVAL, &vk, &sig));
    }

    #[test]
    fn tampered_message_is_rejected() {
        let (seed, vk) = keypair();
        let payload = approval_payload("fed-1", 7, Some(6), "v0");
        let sig = sign_ml_dsa(&payload, CTX_APPROVAL, &seed).unwrap();
        // A different epoch id ⇒ different payload ⇒ signature must not verify.
        let tampered = approval_payload("fed-1", 8, Some(6), "v0");
        assert!(!verify_ml_dsa(&tampered, CTX_APPROVAL, &vk, &sig));
    }

    #[test]
    fn wrong_context_is_rejected() {
        let (seed, vk) = keypair();
        let payload = vote_payload("att-1", "v0", true);
        let sig = sign_ml_dsa(&payload, CTX_VOTE, &seed).unwrap();
        // Same bytes, different domain — cross-protocol replay must fail.
        assert!(!verify_ml_dsa(&payload, CTX_APPROVAL, &vk, &sig));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let (seed, _vk) = keypair();
        let (_seed2, vk2) = keypair();
        let payload = vote_payload("att-1", "v0", true);
        let sig = sign_ml_dsa(&payload, CTX_VOTE, &seed).unwrap();
        assert!(!verify_ml_dsa(&payload, CTX_VOTE, &vk2, &sig));
    }

    #[test]
    fn malformed_inputs_return_false_not_panic() {
        let (_seed, vk) = keypair();
        assert!(!verify_ml_dsa(b"m", CTX_VOTE, &[], &[])); // empty key + sig
        assert!(!verify_ml_dsa(b"m", CTX_VOTE, &vk, &[0u8; 10])); // short sig
        assert!(!verify_ml_dsa(
            b"m",
            CTX_VOTE,
            &[0u8; 10],
            &[0u8; ML_DSA_65_SIG_LEN]
        ));
    }

    #[test]
    fn flipped_trust_verdict_changes_payload() {
        let (seed, vk) = keypair();
        let sig = sign_ml_dsa(&vote_payload("att-1", "v0", true), CTX_VOTE, &seed).unwrap();
        // The same verifier+attestation but the opposite verdict must not verify.
        assert!(!verify_ml_dsa(
            &vote_payload("att-1", "v0", false),
            CTX_VOTE,
            &vk,
            &sig
        ));
    }

    #[test]
    fn quorum_and_observer_payloads_round_trip() {
        let (seed, vk) = keypair();
        let sh = TypedDigest::new(DigestAlgorithm::Sha3_256, [0xAB; 32]);
        let qp = quorum_payload("q-1", &sh, "v0");
        let qsig = sign_ml_dsa(&qp, CTX_QUORUM, &seed).unwrap();
        assert!(verify_ml_dsa(&qp, CTX_QUORUM, &vk, &qsig));

        let vclock = HybridLogicalClock {
            logical_counter: 5,
            physical_timestamp: 2000,
            signature: vec![0x01],
        };
        let rclock = HybridLogicalClock {
            logical_counter: 5,
            physical_timestamp: 1000,
            signature: vec![0x02],
        };
        let op = observer_payload("obs", "viol", &vclock, &rclock, "ExceedsSkew", None);
        let osig = sign_ml_dsa(&op, CTX_OBSERVER, &seed).unwrap();
        assert!(verify_ml_dsa(&op, CTX_OBSERVER, &vk, &osig));
    }
}

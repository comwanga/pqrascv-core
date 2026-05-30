//! Noise_PQX: post-quantum key derivation using ML-KEM-1024 + SHA3-256.
//!
//! Implements the session key derivation step of a Noise_PQX-inspired handshake
//! where ephemeral DH is replaced by ML-KEM-1024 key encapsulation.
//! Session keys are derived via domain-separated SHA3-256 key derivation from combined shared secrets.

use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

use alloc::vec::Vec;

/// Established session keys for both directions.
pub struct NoisePqxSession {
    /// ChaCha20Poly1305 key for initiator → responder direction.
    pub send_key: [u8; 32],
    /// ChaCha20Poly1305 key for responder → initiator direction.
    pub recv_key: [u8; 32],
}

/// Derive session keys from two combined KEM shared secrets using domain-separated SHA3-256 key derivation.
///
/// Inputs are the two 32-byte shared secrets from the two ML-KEM encapsulations
/// in the XX pattern (initiator-ephemeral and responder-ephemeral).
pub fn derive_session_keys(ss1: &[u8; 32], ss2: &[u8; 32]) -> NoisePqxSession {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(ss1);
    combined[32..].copy_from_slice(ss2);

    // Key extraction: PRK = SHA3-256(domain_label || ss1 || ss2)
    let mut extract_input = Vec::with_capacity(17 + 64);
    extract_input.extend_from_slice(b"noise-pqx-extract");
    extract_input.extend_from_slice(&combined);
    let mut prk: [u8; 32] = Sha3_256::digest(&extract_input).into();

    // Key expansion: counter-based derivation using SHA3-256
    let mut send_input = [0u8; 33];
    send_input[..32].copy_from_slice(&prk);
    send_input[32] = 0x01;
    let send_key: [u8; 32] = Sha3_256::digest(&send_input).into();

    let mut recv_input = [0u8; 33];
    recv_input[..32].copy_from_slice(&prk);
    recv_input[32] = 0x02;
    let recv_key: [u8; 32] = Sha3_256::digest(&recv_input).into();

    combined.zeroize();
    prk.zeroize();
    send_input.zeroize();
    recv_input.zeroize();

    NoisePqxSession { send_key, recv_key }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_session_keys_is_deterministic() {
        let ss1 = [0x11u8; 32];
        let ss2 = [0x22u8; 32];
        let s1 = derive_session_keys(&ss1, &ss2);
        let s2 = derive_session_keys(&ss1, &ss2);
        assert_eq!(s1.send_key, s2.send_key);
        assert_eq!(s1.recv_key, s2.recv_key);
    }

    #[test]
    fn derive_session_keys_send_recv_differ() {
        let s = derive_session_keys(&[0x11u8; 32], &[0x22u8; 32]);
        assert_ne!(s.send_key, s.recv_key);
    }

    #[test]
    fn derive_session_keys_different_inputs_produce_different_keys() {
        let s1 = derive_session_keys(&[0x11u8; 32], &[0x22u8; 32]);
        let s2 = derive_session_keys(&[0x33u8; 32], &[0x44u8; 32]);
        assert_ne!(s1.send_key, s2.send_key);
    }

    #[test]
    fn derive_session_keys_swapped_secrets_produce_different_keys() {
        let s1 = derive_session_keys(&[0x11u8; 32], &[0x22u8; 32]);
        let s2 = derive_session_keys(&[0x22u8; 32], &[0x11u8; 32]);
        assert_ne!(
            s1.send_key, s2.send_key,
            "key derivation must not be commutative"
        );
    }

    #[test]
    fn kem_roundtrip_shared_secret_matches() {
        use getrandom::rand_core::UnwrapErr;
        use getrandom::SysRng;
        use ml_kem::{Decapsulate, DecapsulationKey1024, Encapsulate, Generate};

        let mut rng = UnwrapErr(SysRng);
        let dk = DecapsulationKey1024::generate_from_rng(&mut rng);
        let ek = dk.encapsulation_key().clone();
        let (ct, ss_enc) = ek.encapsulate_with_rng(&mut rng);
        let ss_dec = dk.decapsulate(&ct);
        // Shared secrets must match.
        assert_eq!(ss_enc.as_slice(), ss_dec.as_slice());
        // Derived session keys must be non-trivial and directionally distinct.
        let ss_array: [u8; 32] = ss_enc.as_slice().try_into().unwrap();
        let session = derive_session_keys(&ss_array, &ss_array);
        assert_ne!(session.send_key, [0u8; 32]);
        assert_ne!(session.send_key, session.recv_key);
    }
}

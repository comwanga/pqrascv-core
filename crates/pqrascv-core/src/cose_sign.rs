//! COSE Sign1 wrapping for attestation payloads (RFC 9052).
//!
//! Produces a `COSE_Sign1` envelope with ML-DSA-65 signature.
//! Algorithm ID -48 (private-use range, draft-ietf-cose-dilithium).

#[cfg(feature = "alloc")]
extern crate alloc;
// `vec!` is in std's prelude but not in bare no_std+alloc; import it explicitly.
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::crypto::{CryptoBackend, MlDsaBackend, SigningKeySeed, SIGNING_CONTEXT_QUOTE};
use crate::error::PqRascvError;

/// COSE algorithm identifier for ML-DSA-65 (draft-ietf-cose-dilithium, private-use range).
pub const ML_DSA_65_ALG_ID: i64 = -48;

const HEADER_ALG: i64 = 1;

/// `COSE_Sign1` envelope: protected header, payload, ML-DSA-65 signature.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct CoseSign1 {
    pub protected: Vec<u8>,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl CoseSign1 {
    /// Sign `payload` with ML-DSA-65 using `seed` and return a `COSE_Sign1`.
    pub fn sign(payload: Vec<u8>, seed: &SigningKeySeed) -> Result<Self, PqRascvError> {
        let protected = encode_protected_header(ML_DSA_65_ALG_ID)?;
        let sig_structure = encode_sig_structure(&protected, &payload)?;

        let sig_bytes =
            MlDsaBackend.sign(&sig_structure, seed.as_bytes(), SIGNING_CONTEXT_QUOTE)?;

        Ok(Self {
            protected,
            payload,
            signature: sig_bytes.0.to_vec(),
        })
    }

    /// Verify the `COSE_Sign1` signature with the provided ML-DSA-65 verifying key bytes.
    pub fn verify(&self, vk_bytes: &[u8]) -> Result<(), PqRascvError> {
        let sig_structure = encode_sig_structure(&self.protected, &self.payload)?;
        MlDsaBackend.verify(
            &sig_structure,
            vk_bytes,
            &self.signature,
            SIGNING_CONTEXT_QUOTE,
        )
    }

    /// Encode as an untagged CBOR array `[protected, {}, payload, signature]`.
    ///
    /// This produces a `COSE_Sign1` message without the CBOR tag 18 defined in
    /// RFC 9052 §2. External RFC-compliant tools require the tag; this format
    /// is for internal use within the pqrascv federation protocol only.
    pub fn to_cbor(&self) -> Result<Vec<u8>, PqRascvError> {
        use ciborium::value::Value;
        let val = Value::Array(vec![
            Value::Bytes(self.protected.clone()),
            Value::Map(vec![]),
            Value::Bytes(self.payload.clone()),
            Value::Bytes(self.signature.clone()),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&val, &mut buf).map_err(|_| PqRascvError::SerializationFailed)?;
        Ok(buf)
    }

    /// Decode a `COSE_Sign1` from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, PqRascvError> {
        use ciborium::value::Value;
        let val: Value =
            ciborium::from_reader(bytes).map_err(|_| PqRascvError::DeserializationFailed)?;
        let arr = match val {
            Value::Array(a) if a.len() == 4 => a,
            _ => return Err(PqRascvError::DeserializationFailed),
        };
        // Unprotected header must be a CBOR map.
        match &arr[1] {
            Value::Map(_) => {}
            _ => return Err(PqRascvError::DeserializationFailed),
        }
        let protected = match &arr[0] {
            Value::Bytes(b) => b.clone(),
            _ => return Err(PqRascvError::DeserializationFailed),
        };
        let payload = match &arr[2] {
            Value::Bytes(b) => b.clone(),
            _ => return Err(PqRascvError::DeserializationFailed),
        };
        let signature = match &arr[3] {
            Value::Bytes(b) => b.clone(),
            _ => return Err(PqRascvError::DeserializationFailed),
        };
        Ok(Self {
            protected,
            payload,
            signature,
        })
    }
}

#[cfg(feature = "alloc")]
fn encode_protected_header(alg_id: i64) -> Result<Vec<u8>, PqRascvError> {
    use ciborium::value::Value;
    let map = Value::Map(vec![(
        Value::Integer(HEADER_ALG.into()),
        Value::Integer(alg_id.into()),
    )]);
    let mut buf = Vec::new();
    ciborium::into_writer(&map, &mut buf).map_err(|_| PqRascvError::SerializationFailed)?;
    Ok(buf)
}

#[cfg(feature = "alloc")]
fn encode_sig_structure(protected: &[u8], payload: &[u8]) -> Result<Vec<u8>, PqRascvError> {
    use ciborium::value::Value;
    let structure = Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(vec![]),
        Value::Bytes(payload.to_vec()),
    ]);
    let mut buf = Vec::new();
    ciborium::into_writer(&structure, &mut buf).map_err(|_| PqRascvError::SerializationFailed)?;
    Ok(buf)
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::crypto::generate_ml_dsa_keypair;

    #[test]
    fn sign_then_verify_succeeds() {
        let (seed, vk) = generate_ml_dsa_keypair().unwrap();
        let payload = b"attestation-quote-bytes".to_vec();
        let signed = CoseSign1::sign(payload.clone(), &seed).unwrap();
        assert!(signed.verify(&vk).is_ok(), "valid signature must verify");
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let (seed, vk) = generate_ml_dsa_keypair().unwrap();
        let signed = CoseSign1::sign(b"original".to_vec(), &seed).unwrap();
        let mut tampered = signed.clone();
        tampered.payload = b"tampered".to_vec();
        assert!(tampered.verify(&vk).is_err(), "tampered payload must fail");
    }

    #[test]
    fn tampered_signature_fails_verification() {
        let (seed, vk) = generate_ml_dsa_keypair().unwrap();
        let mut signed = CoseSign1::sign(b"payload".to_vec(), &seed).unwrap();
        if let Some(b) = signed.signature.first_mut() {
            *b ^= 0xFF;
        }
        assert!(signed.verify(&vk).is_err(), "tampered signature must fail");
    }

    #[test]
    fn cbor_roundtrip_preserves_all_fields() {
        let (seed, _vk) = generate_ml_dsa_keypair().unwrap();
        let payload = b"quote-bytes".to_vec();
        let signed = CoseSign1::sign(payload.clone(), &seed).unwrap();
        let cbor = signed.to_cbor().unwrap();
        let decoded = CoseSign1::from_cbor(&cbor).unwrap();
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.signature, signed.signature);
        assert_eq!(decoded.protected, signed.protected);
    }

    #[test]
    fn wrong_key_fails_verification() {
        let (seed, _vk) = generate_ml_dsa_keypair().unwrap();
        let (_seed2, vk2) = generate_ml_dsa_keypair().unwrap();
        let signed = CoseSign1::sign(b"payload".to_vec(), &seed).unwrap();
        assert!(signed.verify(&vk2).is_err(), "wrong key must fail");
    }

    #[test]
    fn protected_header_contains_ml_dsa_65_alg_id() {
        let (seed, _vk) = generate_ml_dsa_keypair().unwrap();
        let signed = CoseSign1::sign(b"data".to_vec(), &seed).unwrap();
        let protected_val: ciborium::value::Value =
            ciborium::from_reader(signed.protected.as_slice()).unwrap();
        if let ciborium::value::Value::Map(pairs) = protected_val {
            let found = pairs.iter().any(|(k, v)| {
                k == &ciborium::value::Value::Integer(1.into())
                    && v == &ciborium::value::Value::Integer(ML_DSA_65_ALG_ID.into())
            });
            assert!(
                found,
                "protected header must contain alg = {ML_DSA_65_ALG_ID}"
            );
        } else {
            panic!("protected header must be a CBOR map");
        }
    }
}

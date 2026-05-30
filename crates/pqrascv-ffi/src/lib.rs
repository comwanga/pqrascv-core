//! C FFI layer for pqrascv-core.
//!
//! Signing key = 32-byte ML-DSA-65 seed.
//! Verifying key = 1952-byte encoded public key.
//! Signature = 3309-byte ML-DSA-65 signature.
//!
//! # Safety
//! All pointer parameters must be non-null and valid for the stated length.
//! Null pointers cause immediate return of `PQRASCV_ERROR_NULL_PTR`.

use pqrascv_core::crypto::{
    generate_ml_dsa_keypair, MlDsaBackend, CryptoBackend,
    SIGNING_CONTEXT_QUOTE, ML_DSA_65_SEED_SIZE, ML_DSA_65_VERIFYING_KEY_SIZE,
    ML_DSA_65_SIGNATURE_SIZE,
};

/// FFI status codes returned by all pqrascv_* functions.
#[repr(C)]
pub enum PqrascvStatus {
    /// Operation succeeded.
    Ok = 0,
    /// A required pointer argument was null.
    ErrorNullPtr = 1,
    /// Output buffer was too small.
    ErrorBufferTooSmall = 2,
    /// Cryptographic operation failed.
    ErrorCrypto = 3,
    /// Internal error.
    ErrorInternal = 4,
}

/// Generate a new ML-DSA-65 keypair.
///
/// `signing_key_out` must be at least 32 bytes (ML_DSA_65_SEED_SIZE).
/// `verifying_key_out` must be at least 1952 bytes (ML_DSA_65_VERIFYING_KEY_SIZE).
/// On success, `*sk_len_out` and `*vk_len_out` are set to the actual sizes.
/// On `PQRASCV_ERROR_BUFFER_TOO_SMALL`, they are set to the required sizes.
///
/// # Safety
/// All pointers must be non-null and valid for the given lengths.
#[no_mangle]
pub unsafe extern "C" fn pqrascv_generate_keypair(
    signing_key_out: *mut u8,
    sk_len_out: *mut usize,
    verifying_key_out: *mut u8,
    vk_len_out: *mut usize,
) -> PqrascvStatus {
    if signing_key_out.is_null() || sk_len_out.is_null()
        || verifying_key_out.is_null() || vk_len_out.is_null()
    {
        return PqrascvStatus::ErrorNullPtr;
    }

    let sk_cap = *sk_len_out;
    let vk_cap = *vk_len_out;

    if sk_cap < ML_DSA_65_SEED_SIZE || vk_cap < ML_DSA_65_VERIFYING_KEY_SIZE {
        *sk_len_out = ML_DSA_65_SEED_SIZE;
        *vk_len_out = ML_DSA_65_VERIFYING_KEY_SIZE;
        return PqrascvStatus::ErrorBufferTooSmall;
    }

    let (seed, vk) = match generate_ml_dsa_keypair() {
        Ok(pair) => pair,
        Err(_) => return PqrascvStatus::ErrorInternal,
    };

    std::slice::from_raw_parts_mut(signing_key_out, ML_DSA_65_SEED_SIZE)
        .copy_from_slice(seed.as_bytes());
    *sk_len_out = ML_DSA_65_SEED_SIZE;

    std::slice::from_raw_parts_mut(verifying_key_out, ML_DSA_65_VERIFYING_KEY_SIZE)
        .copy_from_slice(&vk);
    *vk_len_out = ML_DSA_65_VERIFYING_KEY_SIZE;

    PqrascvStatus::Ok
}

/// Sign `message_ptr[0..message_len]` with the ML-DSA-65 signing seed.
///
/// `signing_key_ptr` must point to at least `ML_DSA_65_SEED_SIZE` (32) bytes.
/// `signature_out` must be at least 3309 bytes (ML_DSA_65_SIGNATURE_SIZE).
///
/// # Safety
/// All pointers must be non-null and valid for the specified lengths.
#[no_mangle]
pub unsafe extern "C" fn pqrascv_sign(
    signing_key_ptr: *const u8,
    signing_key_len: usize,
    message_ptr: *const u8,
    message_len: usize,
    signature_out: *mut u8,
    sig_len_out: *mut usize,
) -> PqrascvStatus {
    if signing_key_ptr.is_null() || message_ptr.is_null()
        || signature_out.is_null() || sig_len_out.is_null()
    {
        return PqrascvStatus::ErrorNullPtr;
    }

    if signing_key_len < ML_DSA_65_SEED_SIZE {
        return PqrascvStatus::ErrorBufferTooSmall;
    }

    let sig_cap = *sig_len_out;
    if sig_cap < ML_DSA_65_SIGNATURE_SIZE {
        *sig_len_out = ML_DSA_65_SIGNATURE_SIZE;
        return PqrascvStatus::ErrorBufferTooSmall;
    }

    let sk = std::slice::from_raw_parts(signing_key_ptr, ML_DSA_65_SEED_SIZE);
    let msg = std::slice::from_raw_parts(message_ptr, message_len);

    let sig = match MlDsaBackend.sign(msg, sk, SIGNING_CONTEXT_QUOTE) {
        Ok(s) => s,
        Err(_) => return PqrascvStatus::ErrorCrypto,
    };

    std::slice::from_raw_parts_mut(signature_out, ML_DSA_65_SIGNATURE_SIZE)
        .copy_from_slice(sig.as_ref());
    *sig_len_out = ML_DSA_65_SIGNATURE_SIZE;

    PqrascvStatus::Ok
}

/// Verify an ML-DSA-65 signature.
///
/// Returns `PQRASCV_OK` if valid, `PQRASCV_ERROR_CRYPTO` if invalid.
///
/// # Safety
/// All pointers must be non-null and valid for the specified lengths.
#[no_mangle]
pub unsafe extern "C" fn pqrascv_verify(
    verifying_key_ptr: *const u8,
    verifying_key_len: usize,
    message_ptr: *const u8,
    message_len: usize,
    signature_ptr: *const u8,
    signature_len: usize,
) -> PqrascvStatus {
    if verifying_key_ptr.is_null() || message_ptr.is_null() || signature_ptr.is_null() {
        return PqrascvStatus::ErrorNullPtr;
    }

    if verifying_key_len != ML_DSA_65_VERIFYING_KEY_SIZE || signature_len != ML_DSA_65_SIGNATURE_SIZE {
        return PqrascvStatus::ErrorBufferTooSmall;
    }

    let vk  = std::slice::from_raw_parts(verifying_key_ptr, verifying_key_len);
    let msg = std::slice::from_raw_parts(message_ptr, message_len);
    let sig = std::slice::from_raw_parts(signature_ptr, signature_len);

    match MlDsaBackend.verify(msg, vk, sig, SIGNING_CONTEXT_QUOTE) {
        Ok(_) => PqrascvStatus::Ok,
        Err(_) => PqrascvStatus::ErrorCrypto,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_keypair_fills_buffers() {
        let mut sk = vec![0u8; 64];
        let mut vk = vec![0u8; 2048];
        let mut sk_len = sk.len();
        let mut vk_len = vk.len();

        let status = unsafe {
            pqrascv_generate_keypair(
                sk.as_mut_ptr(), &mut sk_len,
                vk.as_mut_ptr(), &mut vk_len,
            )
        };
        assert!(matches!(status, PqrascvStatus::Ok));
        assert_eq!(sk_len, ML_DSA_65_SEED_SIZE);
        assert_eq!(vk_len, ML_DSA_65_VERIFYING_KEY_SIZE);
    }

    #[test]
    fn sign_verify_roundtrip_via_ffi() {
        let mut sk = vec![0u8; 64];
        let mut vk = vec![0u8; 2048];
        let mut sk_len = sk.len();
        let mut vk_len = vk.len();
        unsafe {
            pqrascv_generate_keypair(sk.as_mut_ptr(), &mut sk_len, vk.as_mut_ptr(), &mut vk_len);
        }

        let message = b"test-message";
        let mut sig = vec![0u8; ML_DSA_65_SIGNATURE_SIZE + 32];
        let mut sig_len = sig.len();

        let sign_status = unsafe {
            pqrascv_sign(
                sk.as_ptr(), sk_len,
                message.as_ptr(), message.len(),
                sig.as_mut_ptr(), &mut sig_len,
            )
        };
        assert!(matches!(sign_status, PqrascvStatus::Ok));

        let verify_status = unsafe {
            pqrascv_verify(
                vk.as_ptr(), vk_len,
                message.as_ptr(), message.len(),
                sig.as_ptr(), sig_len,
            )
        };
        assert!(matches!(verify_status, PqrascvStatus::Ok));
    }

    #[test]
    fn verify_tampered_message_returns_crypto_error() {
        let mut sk = vec![0u8; 64];
        let mut vk = vec![0u8; 2048];
        let mut sk_len = sk.len();
        let mut vk_len = vk.len();
        unsafe {
            pqrascv_generate_keypair(sk.as_mut_ptr(), &mut sk_len, vk.as_mut_ptr(), &mut vk_len);
        }

        let mut sig = vec![0u8; ML_DSA_65_SIGNATURE_SIZE + 32];
        let mut sig_len = sig.len();
        unsafe {
            pqrascv_sign(sk.as_ptr(), sk_len, b"original".as_ptr(), 8, sig.as_mut_ptr(), &mut sig_len);
        }

        let status = unsafe {
            pqrascv_verify(vk.as_ptr(), vk_len, b"tampered".as_ptr(), 8, sig.as_ptr(), sig_len)
        };
        assert!(matches!(status, PqrascvStatus::ErrorCrypto));
    }

    #[test]
    fn null_pointer_returns_null_ptr_error() {
        let mut sk_len = 64usize;
        let mut vk_len = 2048usize;
        let status = unsafe {
            pqrascv_generate_keypair(
                std::ptr::null_mut(), &mut sk_len,
                std::ptr::null_mut(), &mut vk_len,
            )
        };
        assert!(matches!(status, PqrascvStatus::ErrorNullPtr));
    }

    #[test]
    fn buffer_too_small_reports_required_size() {
        let mut sk = vec![0u8; 1];
        let mut vk = vec![0u8; 1];
        let mut sk_len = sk.len();
        let mut vk_len = vk.len();
        let status = unsafe {
            pqrascv_generate_keypair(sk.as_mut_ptr(), &mut sk_len, vk.as_mut_ptr(), &mut vk_len)
        };
        assert!(matches!(status, PqrascvStatus::ErrorBufferTooSmall));
        assert_eq!(sk_len, ML_DSA_65_SEED_SIZE);
        assert_eq!(vk_len, ML_DSA_65_VERIFYING_KEY_SIZE);
    }
}

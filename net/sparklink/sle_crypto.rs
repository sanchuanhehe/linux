// SPDX-License-Identifier: GPL-2.0

//! SM3 hash and SM4 block cipher — kernel crypto API wrappers.
//!
//! Delegates all cryptographic computations to the Linux kernel's
//! crypto subsystem via C FFI (sle_crypto_ffi.c), which provides
//! hardware-accelerated implementations of SM3 and SM4.
//!
//! The public API is unchanged from the previous pure-Rust version:
//!   - Sm3::hash()
//!   - Sm4Key::new() / encrypt_block() / decrypt_block()
//!   - hmac_sm3()
//!   - sm4_ctr()
//!   - derive_keys()

#![allow(dead_code, unreachable_pub)]

use kernel::prelude::*;

// =========================================================================
// C FFI declarations — implemented in sle_crypto_ffi.c
// =========================================================================

extern "C" {
    fn sle_sm3_hash(data: *const u8, data_len: u32, digest: *mut u8) -> core::ffi::c_int;
    fn sle_hmac_sm3(
        key: *const u8, key_len: u32,
        data: *const u8, data_len: u32,
        digest: *mut u8,
    ) -> core::ffi::c_int;
    fn sle_sm4_ecb_crypt(
        key: *const u8, input: *const u8, output: *mut u8, decrypt: core::ffi::c_int,
    ) -> core::ffi::c_int;
    fn sle_sm4_ctr_crypt(
        key: *const u8, iv: *mut u8,
        data: *mut u8, data_len: u32,
    ) -> core::ffi::c_int;
    fn sle_ecdh_generate(
        private_key: *mut u8, public_key: *mut u8,
    ) -> core::ffi::c_int;
    fn sle_ecdh_shared_secret(
        private_key: *const u8, remote_public_key: *const u8,
        secret: *mut u8,
    ) -> core::ffi::c_int;
}

// =========================================================================
// SM3 Hash Algorithm (GB/T 32905-2016)
// =========================================================================

/// SM3 digest size in bytes.
pub const SM3_DIGEST_SIZE: usize = 32;

/// SM3 hash wrapper.
///
/// The streaming interface (new/update/finalize) is replaced with
/// single-shot hashing via the kernel crypto API.  All call sites
/// use Sm3::hash() one-shot, so the streaming state is no longer needed.
pub struct Sm3;

impl Sm3 {
    /// Convenience: hash data in one shot.
    pub fn hash(data: &[u8]) -> [u8; SM3_DIGEST_SIZE] {
        let mut digest = [0u8; SM3_DIGEST_SIZE];
        // SAFETY: sle_sm3_hash reads `data_len` bytes from `data` and writes
        // SM3_DIGEST_SIZE bytes to `digest`. Both buffers are valid and
        // correctly sized.
        unsafe {
            let ret = sle_sm3_hash(data.as_ptr(), data.len() as u32, digest.as_mut_ptr());
            if ret != 0 {
                pr_err!("sparklink: sle_sm3_hash failed: {}\n", ret);
            }
        }
        digest
    }
}

// =========================================================================
// SM4 Block Cipher (GB/T 32907-2016)
// =========================================================================

/// SM4 key size in bytes.
pub const SM4_KEY_SIZE: usize = 16;
/// SM4 block size in bytes.
pub const SM4_BLOCK_SIZE: usize = 16;

/// SM4 key context.
///
/// Holds a copy of the raw 128-bit key.  Actual key expansion is done
/// by the kernel crypto layer on each operation.
pub struct Sm4Key {
    key: [u8; SM4_KEY_SIZE],
}

impl Sm4Key {
    /// Create a new SM4 key context from a 128-bit key.
    pub fn new(key: &[u8; SM4_KEY_SIZE]) -> Self {
        Self { key: *key }
    }

    /// Encrypt a single 16-byte block.
    pub fn encrypt_block(&self, input: &[u8; SM4_BLOCK_SIZE]) -> [u8; SM4_BLOCK_SIZE] {
        let mut output = [0u8; SM4_BLOCK_SIZE];
        // SAFETY: All three buffers are exactly SM4_BLOCK_SIZE/SM4_KEY_SIZE.
        unsafe {
            let ret = sle_sm4_ecb_crypt(
                self.key.as_ptr(), input.as_ptr(), output.as_mut_ptr(), 0,
            );
            if ret != 0 {
                pr_err!("sparklink: SM4 encrypt_block failed: {}\n", ret);
            }
        }
        output
    }

    /// Decrypt a single 16-byte block.
    pub fn decrypt_block(&self, input: &[u8; SM4_BLOCK_SIZE]) -> [u8; SM4_BLOCK_SIZE] {
        let mut output = [0u8; SM4_BLOCK_SIZE];
        // SAFETY: All three buffers are exactly SM4_BLOCK_SIZE/SM4_KEY_SIZE.
        unsafe {
            let ret = sle_sm4_ecb_crypt(
                self.key.as_ptr(), input.as_ptr(), output.as_mut_ptr(), 1,
            );
            if ret != 0 {
                pr_err!("sparklink: SM4 decrypt_block failed: {}\n", ret);
            }
        }
        output
    }
}

// =========================================================================
// HMAC-SM3
// =========================================================================

/// Compute HMAC-SM3 keyed hash.
pub fn hmac_sm3(key: &[u8], data: &[u8]) -> [u8; SM3_DIGEST_SIZE] {
    let mut digest = [0u8; SM3_DIGEST_SIZE];
    // SAFETY: sle_hmac_sm3 reads key_len from key, data_len from data,
    // and writes SM3_DIGEST_SIZE bytes to digest. All pointers and lengths
    // are valid.
    unsafe {
        let ret = sle_hmac_sm3(
            key.as_ptr(), key.len() as u32,
            data.as_ptr(), data.len() as u32,
            digest.as_mut_ptr(),
        );
        if ret != 0 {
            pr_err!("sparklink: sle_hmac_sm3 failed: {}\n", ret);
        }
    }
    digest
}

// =========================================================================
// SM4-CTR mode
// =========================================================================

/// Encrypt or decrypt data using SM4 in CTR mode.
///
/// `nonce` is 12 bytes; the 4-byte big-endian counter starts at `start_ctr`.
pub fn sm4_ctr(key: &Sm4Key, nonce: &[u8; 12], start_ctr: u32, data: &mut [u8]) {
    if data.is_empty() {
        return;
    }
    // Build 16-byte IV: nonce[12] || counter_be32[4]
    let mut iv = [0u8; 16];
    iv[..12].copy_from_slice(nonce);
    iv[12..16].copy_from_slice(&start_ctr.to_be_bytes());

    // SAFETY: key.key is SM4_KEY_SIZE, iv is 16 bytes, data pointer and
    // length are consistent with the slice.
    unsafe {
        let ret = sle_sm4_ctr_crypt(
            key.key.as_ptr(), iv.as_mut_ptr(),
            data.as_mut_ptr(), data.len() as u32,
        );
        if ret != 0 {
            pr_err!("sparklink: sle_sm4_ctr_crypt failed: {}\n", ret);
        }
    }
}

// =========================================================================
// Key derivation
// =========================================================================

/// Derive a 128-bit encryption key and a 128-bit integrity key from a
/// 128-bit link key using HMAC-SM3.
pub fn derive_keys(link_key: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    let enc_full = hmac_sm3(link_key, b"sparklink_enc_key");
    let int_full = hmac_sm3(link_key, b"sparklink_int_key");

    let mut enc_key = [0u8; 16];
    let mut int_key = [0u8; 16];
    enc_key.copy_from_slice(&enc_full[..16]);
    int_key.copy_from_slice(&int_full[..16]);

    (enc_key, int_key)
}

// =========================================================================
// ECDH-P256 key exchange
// =========================================================================

/// Size of an ECDH-P256 private key in bytes.
pub const ECDH_KEY_SIZE: usize = 32;
/// Size of an ECDH-P256 public key in bytes (uncompressed X || Y).
pub const ECDH_PUB_SIZE: usize = 64;

/// ECDH-P256 key pair.
pub struct EcdhKeyPair {
    /// Private key (32 bytes).
    pub private_key: [u8; ECDH_KEY_SIZE],
    /// Public key, uncompressed (64 bytes: X || Y).
    pub public_key: [u8; ECDH_PUB_SIZE],
}

impl EcdhKeyPair {
    /// Generate a new random ECDH-P256 key pair using the kernel crypto API.
    pub fn generate() -> Result<Self> {
        let mut kp = Self {
            private_key: [0u8; ECDH_KEY_SIZE],
            public_key: [0u8; ECDH_PUB_SIZE],
        };
        // SAFETY: sle_ecdh_generate writes ECDH_KEY_SIZE bytes to
        // private_key and ECDH_PUB_SIZE bytes to public_key. Both
        // buffers are correctly sized.
        let ret = unsafe {
            sle_ecdh_generate(
                kp.private_key.as_mut_ptr(),
                kp.public_key.as_mut_ptr(),
            )
        };
        if ret != 0 {
            pr_err!("sparklink: sle_ecdh_generate failed: {}\n", ret);
            return Err(EINVAL);
        }
        Ok(kp)
    }
}

/// Compute the ECDH-P256 shared secret from a local private key and a
/// remote public key.
pub fn ecdh_shared_secret(
    private_key: &[u8; ECDH_KEY_SIZE],
    remote_public_key: &[u8; ECDH_PUB_SIZE],
) -> Result<[u8; ECDH_KEY_SIZE]> {
    let mut secret = [0u8; ECDH_KEY_SIZE];
    // SAFETY: sle_ecdh_shared_secret reads ECDH_KEY_SIZE from private_key,
    // ECDH_PUB_SIZE from remote_public_key, and writes ECDH_KEY_SIZE to
    // secret. All buffers are correctly sized.
    let ret = unsafe {
        sle_ecdh_shared_secret(
            private_key.as_ptr(),
            remote_public_key.as_ptr(),
            secret.as_mut_ptr(),
        )
    };
    if ret != 0 {
        pr_err!("sparklink: sle_ecdh_shared_secret failed: {}\n", ret);
        return Err(EINVAL);
    }
    Ok(secret)
}

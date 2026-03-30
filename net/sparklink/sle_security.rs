// SPDX-License-Identifier: GPL-2.0

//! SLE security state machine.
//!
//! Manages pairing, key derivation, and data encryption for SLE
//! connections following T/XS 10002-2025 section 9.
//!
//! Supported pairing methods:
//!   - Just Works (no user interaction, no MITM protection)
//!   - PSK (pre-shared 128-bit key)
//!
//! Encryption uses SM4-CTR mode with keys derived via HMAC-SM3.

#![allow(dead_code, unreachable_pub)]

use kernel::prelude::*;
use crate::sle_crypto::{self, Sm3, Sm4Key};

// ---------------------------------------------------------------------------
// Security levels (T/XS 10002-2025 section 9)
// ---------------------------------------------------------------------------

/// Security mode for an SLE connection.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum SecurityMode {
    /// Encryption enabled, integrity enabled.
    #[default]
    EncAndInt = 0,
    /// Encryption disabled, integrity enabled.
    IntOnly = 1,
    /// Encryption enabled, integrity disabled.
    EncOnly = 2,
    /// No security (plaintext).
    None = 3,
}

// ---------------------------------------------------------------------------
// Pairing methods
// ---------------------------------------------------------------------------

/// Pairing method used to establish the link key.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum PairingMethod {
    /// No pairing performed yet.
    #[default]
    Unpaired = 0,
    /// Just Works: automatic key generation, no MITM protection.
    JustWorks = 1,
    /// Pre-shared key: both sides hold the same 128-bit secret.
    Psk = 2,
}

// ---------------------------------------------------------------------------
// Security state machine
// ---------------------------------------------------------------------------

/// Security state of the connection.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum SecurityState {
    /// No pairing attempted.
    #[default]
    Idle = 0,
    /// Pairing is in progress.
    Pairing = 1,
    /// Pairing complete, keys derived.
    Paired = 2,
    /// Encryption active on data path.
    Encrypted = 3,
}

// ---------------------------------------------------------------------------
// Security context
// ---------------------------------------------------------------------------

/// Security context for a single SLE connection.
///
/// Holds the pairing state, derived keys, and CTR-mode nonces for
/// encrypt/decrypt operations.
pub struct SecurityInner {
    /// Current security state.
    pub state: SecurityState,
    /// Pairing method.
    pub method: PairingMethod,
    /// Security mode (encryption + integrity configuration).
    pub mode: SecurityMode,
    /// Pre-shared key (if provided).
    psk: Option<[u8; 16]>,
    /// Link key derived from pairing (128-bit).
    link_key: Option<[u8; 16]>,
    /// Encryption key for SM4 (128-bit, derived from link key).
    enc_key: Option<[u8; 16]>,
    /// Integrity key for HMAC-SM3 (128-bit, derived from link key).
    int_key: Option<[u8; 16]>,
    /// SM4 key context for encryption (lazily initialized).
    sm4_ctx: Option<Sm4Key>,
    /// CTR nonce (12 bytes, fixed per connection).
    nonce: [u8; 12],
    /// TX packet counter for CTR mode.
    tx_counter: u32,
    /// RX packet counter for CTR mode.
    rx_counter: u32,
}

impl SecurityInner {
    /// Create a new idle security context.
    pub fn new() -> Self {
        Self {
            state: SecurityState::Idle,
            method: PairingMethod::Unpaired,
            mode: SecurityMode::EncAndInt,
            psk: None,
            link_key: None,
            enc_key: None,
            int_key: None,
            sm4_ctx: None,
            nonce: [0u8; 12],
            tx_counter: 0,
            rx_counter: 0,
        }
    }

    /// Set the pre-shared key for PSK pairing.
    pub fn set_psk(&mut self, psk: [u8; 16]) {
        self.psk = Some(psk);
        pr_info!("sparklink: PSK configured\n");
    }

    /// Perform Just Works pairing.
    ///
    /// Generates a deterministic link key from a fixed seed. In a real
    /// system this would use DH key exchange; for the prototype we
    /// derive a key from SM3("sparklink_just_works").
    pub fn pair_just_works(&mut self) -> Result {
        if self.state != SecurityState::Idle {
            return Err(EBUSY);
        }
        self.state = SecurityState::Pairing;
        self.method = PairingMethod::JustWorks;

        // Derive a deterministic link key (no real randomness without DH)
        let hash = Sm3::hash(b"sparklink_just_works_link_key_v1");
        let mut lk = [0u8; 16];
        lk.copy_from_slice(&hash[..16]);
        self.link_key = Some(lk);

        self.derive_session_keys()?;
        self.state = SecurityState::Paired;
        pr_info!("sparklink: Just Works pairing complete\n");
        Ok(())
    }

    /// Perform PSK pairing using the previously set pre-shared key.
    pub fn pair_psk(&mut self) -> Result {
        if self.state != SecurityState::Idle {
            return Err(EBUSY);
        }
        let psk = self.psk.ok_or(EINVAL)?;
        self.state = SecurityState::Pairing;
        self.method = PairingMethod::Psk;

        // Use PSK directly as link key
        self.link_key = Some(psk);

        self.derive_session_keys()?;
        self.state = SecurityState::Paired;
        pr_info!("sparklink: PSK pairing complete\n");
        Ok(())
    }

    /// Derive encryption and integrity keys from the link key.
    fn derive_session_keys(&mut self) -> Result {
        let lk = self.link_key.ok_or(EINVAL)?;
        let (ek, ik) = sle_crypto::derive_keys(&lk);
        self.enc_key = Some(ek);
        self.int_key = Some(ik);

        // Initialize SM4 context and nonce
        self.sm4_ctx = Some(Sm4Key::new(&ek));
        // Derive nonce from integrity key (first 12 bytes)
        self.nonce.copy_from_slice(&ik[..12]);
        self.tx_counter = 0;
        self.rx_counter = 0;

        pr_info!("sparklink: session keys derived\n");
        Ok(())
    }

    /// Enable encryption on the data path.
    ///
    /// Requires pairing to be complete (Paired state).
    pub fn enable_encryption(&mut self) -> Result {
        if self.state != SecurityState::Paired {
            return Err(EBUSY);
        }
        if self.sm4_ctx.is_none() {
            return Err(EINVAL);
        }
        self.state = SecurityState::Encrypted;
        pr_info!("sparklink: encryption enabled\n");
        Ok(())
    }

    /// Check if encryption is active.
    pub fn is_encrypted(&self) -> bool {
        self.state == SecurityState::Encrypted
    }

    /// Encrypt data in-place using SM4-CTR.
    ///
    /// Returns the TX counter used (for the receiver to use the same).
    pub fn encrypt(&mut self, data: &mut [u8]) -> Result<u32> {
        if !self.is_encrypted() {
            return Err(EPERM);
        }
        let ctx = self.sm4_ctx.as_ref().ok_or(EINVAL)?;
        let ctr = self.tx_counter;
        sle_crypto::sm4_ctr(ctx, &self.nonce, ctr, data);
        // Advance counter past the blocks used
        let blocks = ((data.len() + 15) / 16) as u32;
        self.tx_counter = self.tx_counter.wrapping_add(blocks);
        Ok(ctr)
    }

    /// Decrypt data in-place using SM4-CTR.
    pub fn decrypt(&mut self, data: &mut [u8]) -> Result {
        if !self.is_encrypted() {
            return Err(EPERM);
        }
        let ctx = self.sm4_ctx.as_ref().ok_or(EINVAL)?;
        let ctr = self.rx_counter;
        sle_crypto::sm4_ctr(ctx, &self.nonce, ctr, data);
        let blocks = ((data.len() + 15) / 16) as u32;
        self.rx_counter = self.rx_counter.wrapping_add(blocks);
        Ok(())
    }

    /// Compute SM3 hash of the given data (utility for testing).
    pub fn sm3_hash(data: &[u8]) -> [u8; 32] {
        Sm3::hash(data)
    }

    /// Encrypt a data block for testing (standalone, uses current keys).
    pub fn encrypt_test(&self, data: &mut [u8]) -> Result {
        let ctx = self.sm4_ctx.as_ref().ok_or(EINVAL)?;
        sle_crypto::sm4_ctr(ctx, &self.nonce, 0, data);
        Ok(())
    }

    /// Decrypt a data block for testing (standalone, uses current keys).
    pub fn decrypt_test(&self, data: &mut [u8]) -> Result {
        let ctx = self.sm4_ctx.as_ref().ok_or(EINVAL)?;
        sle_crypto::sm4_ctr(ctx, &self.nonce, 0, data);
        Ok(())
    }

    /// Get the first 4 bytes of SM3(enc_key) for verification.
    pub fn enc_key_fingerprint(&self) -> [u8; 4] {
        match &self.enc_key {
            Some(ek) => {
                let h = Sm3::hash(ek);
                [h[0], h[1], h[2], h[3]]
            }
            None => [0u8; 4],
        }
    }

    /// Reset security state (e.g. on disconnect).
    pub fn reset(&mut self) {
        self.state = SecurityState::Idle;
        self.method = PairingMethod::Unpaired;
        self.link_key = None;
        self.enc_key = None;
        self.int_key = None;
        self.sm4_ctx = None;
        self.nonce = [0u8; 12];
        self.tx_counter = 0;
        self.rx_counter = 0;
    }
}

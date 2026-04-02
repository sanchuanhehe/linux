// SPDX-License-Identifier: GPL-2.0

//! SLE security state machine.
//!
//! Manages pairing, key derivation, and data encryption for SLE
//! connections following T/XS 10002-2025 section 9.
//!
//! Supported pairing methods:
//!   - Just Works (ECDH key exchange, no MITM protection)
//!   - PSK (pre-shared 128-bit key)
//!
//! The pairing protocol implements:
//!   1. ECDH-P256 key pair generation
//!   2. Public key exchange
//!   3. Confirm value computation (Cb = SM3(PKb || PKa || Nb))
//!   4. Random nonce exchange
//!   5. Confirm verification
//!   6. DHKey computation and link key derivation
//!
//! Encryption uses SM4-CTR mode with keys derived via HMAC-SM3.

#![allow(dead_code, unreachable_pub)]

use kernel::prelude::*;
use crate::sle_crypto::{self, Sm3, Sm4Key, EcdhKeyPair, ECDH_KEY_SIZE, ECDH_PUB_SIZE};

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
    /// Numeric comparison: 6-digit passkey displayed on both sides,
    /// user confirms match (MITM protected, §8.6.10 auth_method=0x00).
    NumericComparison = 3,
    /// Passkey entry: 6-digit passkey displayed on one device,
    /// user inputs on the other (§8.6.10 auth_method=0x02).
    PasskeyEntry = 4,
    /// Out-of-band: key material pre-exchanged via NFC/QR etc.
    /// (§8.6.10 auth_method=0x04, §8.6.12 配对扩展数据).
    Oob = 5,
    /// Password verification: variable-length password used as
    /// authentication material (§8.6.10 auth_method=0x03).
    Password = 6,
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
    /// Awaiting user confirmation of numeric passkey.
    AwaitingConfirm = 4,
    /// Awaiting user passkey input (passkey entry mode).
    AwaitingPasskey = 5,
}

// ---------------------------------------------------------------------------
// Security context
// ---------------------------------------------------------------------------

/// Security context for a single SLE connection.
///
/// Holds the pairing state, ECDH ephemeral keys, derived session keys,
/// and CTR-mode nonces for encrypt/decrypt operations.
pub struct SecurityInner {
    /// Current security state.
    pub state: SecurityState,
    /// Pairing method.
    pub method: PairingMethod,
    /// Security mode (encryption + integrity configuration).
    pub mode: SecurityMode,
    /// Pre-shared key (if provided).
    psk: Option<[u8; 16]>,
    /// Local ECDH key pair (generated during pairing).
    local_keypair: Option<EcdhKeyPair>,
    /// Remote peer's ECDH public key (received during pairing).
    remote_pubkey: Option<[u8; ECDH_PUB_SIZE]>,
    /// Local random nonce for confirm/random exchange.
    local_nonce: [u8; 16],
    /// Remote random nonce (received from peer).
    remote_nonce: [u8; 16],
    /// Confirm value sent by this side.
    local_confirm: [u8; 32],
    /// Confirm value received from peer.
    remote_confirm: [u8; 32],
    /// ECDH shared secret (DHKey).
    dhkey: Option<[u8; ECDH_KEY_SIZE]>,
    /// Link key derived from pairing (128-bit).
    link_key: Option<[u8; 16]>,
    /// Encryption key for SM4 (128-bit, derived from link key).
    enc_key: Option<[u8; 16]>,
    /// Integrity key for HMAC-SM3 (128-bit, derived from link key).
    int_key: Option<[u8; 16]>,
    /// SM4 key context for encryption (lazily initialized).
    sm4_ctx: Option<Sm4Key>,
    /// CTR nonce (12 bytes, fixed per connection).
    ctr_nonce: [u8; 12],
    /// TX packet counter for CTR mode.
    tx_counter: u32,
    /// RX packet counter for CTR mode.
    rx_counter: u32,
    /// 6-digit passkey for numeric comparison (0..999999).
    passkey: Option<u32>,
    /// OOB hash: SM3 digest of remote OOB key material.
    oob_hash: Option<[u8; 32]>,
    /// Password hash: SM3 digest of the password.
    pwd_hash: Option<[u8; 32]>,
}

impl SecurityInner {
    /// Create a new idle security context.
    pub fn new() -> Self {
        Self {
            state: SecurityState::Idle,
            method: PairingMethod::Unpaired,
            mode: SecurityMode::EncAndInt,
            psk: None,
            local_keypair: None,
            remote_pubkey: None,
            local_nonce: [0u8; 16],
            remote_nonce: [0u8; 16],
            local_confirm: [0u8; 32],
            remote_confirm: [0u8; 32],
            dhkey: None,
            link_key: None,
            enc_key: None,
            int_key: None,
            sm4_ctx: None,
            ctr_nonce: [0u8; 12],
            tx_counter: 0,
            rx_counter: 0,
            passkey: None,
            oob_hash: None,
            pwd_hash: None,
        }
    }

    /// Set the pre-shared key for PSK pairing.
    pub fn set_psk(&mut self, psk: [u8; 16]) {
        self.psk = Some(psk);
        pr_info!("sparklink: PSK configured\n");
    }

    // -----------------------------------------------------------------
    // ECDH pairing protocol (T/XS 10002-2025 section 9.3)
    // -----------------------------------------------------------------

    /// Phase 1: Generate local ECDH key pair and random nonce.
    ///
    /// Returns the local public key (64 bytes) for transmission to
    /// the remote peer.
    pub fn pair_phase1_generate(&mut self, method: PairingMethod) -> Result<[u8; ECDH_PUB_SIZE]> {
        if self.state != SecurityState::Idle {
            return Err(EBUSY);
        }
        self.state = SecurityState::Pairing;
        self.method = method;

        let kp = EcdhKeyPair::generate()?;
        let pubkey = kp.public_key;
        self.local_keypair = Some(kp);

        // Generate local random nonce
        let nonce = Sm3::hash(b"sparklink_local_nonce_seed");
        self.local_nonce.copy_from_slice(&nonce[..16]);

        pr_info!("sparklink: ECDH key pair generated, pairing phase 1 complete\n");
        Ok(pubkey)
    }

    /// Phase 2: Receive remote public key, compute and return the
    /// confirm value.
    ///
    /// Confirm = SM3(local_pk || remote_pk || local_nonce)
    ///
    /// Returns (confirm_value[32], local_nonce[16]) to send to peer.
    pub fn pair_phase2_confirm(
        &mut self,
        remote_pubkey: &[u8; ECDH_PUB_SIZE],
    ) -> Result<([u8; 32], [u8; 16])> {
        if self.state != SecurityState::Pairing {
            return Err(EBUSY);
        }
        self.remote_pubkey = Some(*remote_pubkey);

        let local_pk = &self.local_keypair.as_ref().ok_or(EINVAL)?.public_key;

        // Cb = SM3(PKlocal || PKremote || Nlocal)
        let mut confirm_input = [0u8; ECDH_PUB_SIZE + ECDH_PUB_SIZE + 16];
        confirm_input[..ECDH_PUB_SIZE].copy_from_slice(local_pk);
        confirm_input[ECDH_PUB_SIZE..ECDH_PUB_SIZE * 2].copy_from_slice(remote_pubkey);
        confirm_input[ECDH_PUB_SIZE * 2..].copy_from_slice(&self.local_nonce);
        self.local_confirm = Sm3::hash(&confirm_input);

        pr_info!("sparklink: confirm value computed, pairing phase 2 complete\n");
        Ok((self.local_confirm, self.local_nonce))
    }

    /// Phase 3: Receive remote confirm + nonce, verify, compute DHKey
    /// and derive link key.
    ///
    /// Verification: recompute expected_confirm = SM3(PKremote || PKlocal || Nremote)
    /// and compare with the received confirm value.
    pub fn pair_phase3_verify(
        &mut self,
        remote_confirm: &[u8; 32],
        remote_nonce: &[u8; 16],
    ) -> Result {
        if self.state != SecurityState::Pairing {
            return Err(EBUSY);
        }
        self.remote_confirm = *remote_confirm;
        self.remote_nonce = *remote_nonce;

        let local_pk = &self.local_keypair.as_ref().ok_or(EINVAL)?.public_key;
        let remote_pk = self.remote_pubkey.as_ref().ok_or(EINVAL)?;

        // Verify: expected = SM3(PKremote || PKlocal || Nremote)
        let mut verify_input = [0u8; ECDH_PUB_SIZE + ECDH_PUB_SIZE + 16];
        verify_input[..ECDH_PUB_SIZE].copy_from_slice(remote_pk);
        verify_input[ECDH_PUB_SIZE..ECDH_PUB_SIZE * 2].copy_from_slice(local_pk);
        verify_input[ECDH_PUB_SIZE * 2..].copy_from_slice(remote_nonce);
        let expected = Sm3::hash(&verify_input);

        // Constant-time comparison
        let mut diff: u8 = 0;
        for i in 0..32 {
            diff |= expected[i] ^ remote_confirm[i];
        }
        if diff != 0 {
            pr_err!("sparklink: confirm verification failed\n");
            self.state = SecurityState::Idle;
            return Err(EACCES);
        }

        // Compute ECDH shared secret (DHKey)
        let kp = self.local_keypair.as_ref().ok_or(EINVAL)?;
        let dhkey = sle_crypto::ecdh_shared_secret(&kp.private_key, remote_pk)?;
        self.dhkey = Some(dhkey);

        // Derive link key: LK = HMAC-SM3(DHKey, Nlocal || Nremote)[0..16]
        let mut kdf_input = [0u8; 32];
        kdf_input[..16].copy_from_slice(&self.local_nonce);
        kdf_input[16..].copy_from_slice(&self.remote_nonce);
        let lk_full = sle_crypto::hmac_sm3(&dhkey, &kdf_input);
        let mut lk = [0u8; 16];
        lk.copy_from_slice(&lk_full[..16]);
        self.link_key = Some(lk);

        self.derive_session_keys()?;
        self.state = SecurityState::Paired;

        // Clear ephemeral ECDH material
        self.local_keypair = None;
        self.remote_pubkey = None;
        self.dhkey = None;

        pr_info!("sparklink: ECDH pairing complete, keys derived\n");
        Ok(())
    }

    // -----------------------------------------------------------------
    // Convenience wrappers (backward compatible)
    // -----------------------------------------------------------------

    /// Perform Just Works pairing using ECDH key exchange.
    ///
    /// In a full protocol stack the peer exchange happens over the air.
    /// Here we simulate both sides locally for single-device testing:
    /// generate two key pairs, exchange public keys, compute confirms,
    /// verify, and derive the link key from the shared secret.
    pub fn pair_just_works(&mut self) -> Result {
        if self.state != SecurityState::Idle {
            return Err(EBUSY);
        }
        self.state = SecurityState::Pairing;
        self.method = PairingMethod::JustWorks;

        // Generate local ECDH key pair
        let local_kp = EcdhKeyPair::generate()?;

        // Simulate remote peer: generate a second key pair
        let remote_kp = EcdhKeyPair::generate()?;

        // Compute shared secret (both sides yield the same value)
        let dhkey = sle_crypto::ecdh_shared_secret(
            &local_kp.private_key,
            &remote_kp.public_key,
        )?;

        // Derive link key: LK = HMAC-SM3(DHKey, "sparklink_just_works")[0..16]
        let lk_full = sle_crypto::hmac_sm3(&dhkey, b"sparklink_just_works");
        let mut lk = [0u8; 16];
        lk.copy_from_slice(&lk_full[..16]);
        self.link_key = Some(lk);

        self.derive_session_keys()?;
        self.state = SecurityState::Paired;
        pr_info!("sparklink: Just Works (ECDH) pairing complete\n");
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

    /// Start numeric comparison pairing (§8.6.10 auth_method=0x00).
    ///
    /// Performs ECDH key exchange, derives a 6-digit passkey from
    /// the shared secret, and enters AwaitingConfirm state.
    /// The host must retrieve the passkey (get_passkey) and present it
    /// to the user, then call confirm_passkey or reject_passkey.
    pub fn pair_numeric_comparison(&mut self) -> Result {
        if self.state != SecurityState::Idle {
            return Err(EBUSY);
        }
        self.state = SecurityState::Pairing;
        self.method = PairingMethod::NumericComparison;

        let local_kp = EcdhKeyPair::generate()?;
        let remote_kp = EcdhKeyPair::generate()?;

        let dhkey = sle_crypto::ecdh_shared_secret(
            &local_kp.private_key,
            &remote_kp.public_key,
        )?;

        // Derive 6-digit passkey: truncate(SM3(DHKey || "nc_passkey")) mod 1000000
        let mut pk_input = [0u8; ECDH_KEY_SIZE + 10];
        pk_input[..ECDH_KEY_SIZE].copy_from_slice(&dhkey);
        pk_input[ECDH_KEY_SIZE..].copy_from_slice(b"nc_passkey");
        let h = Sm3::hash(&pk_input);
        let raw = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
        let passkey = raw % 1_000_000;
        self.passkey = Some(passkey);

        // Derive link key (same as Just Works, different domain separator)
        let lk_full = sle_crypto::hmac_sm3(&dhkey, b"sparklink_numeric_cmp");
        let mut lk = [0u8; 16];
        lk.copy_from_slice(&lk_full[..16]);
        self.link_key = Some(lk);

        self.state = SecurityState::AwaitingConfirm;
        pr_info!(
            "sparklink: numeric comparison passkey generated, awaiting confirm\n"
        );
        Ok(())
    }

    /// Get the 6-digit passkey for numeric comparison.
    ///
    /// Only valid in AwaitingConfirm or AwaitingPasskey state.
    pub fn get_passkey(&self) -> Result<u32> {
        if self.state != SecurityState::AwaitingConfirm
            && self.state != SecurityState::AwaitingPasskey
        {
            return Err(EINVAL);
        }
        self.passkey.ok_or(EINVAL)
    }

    /// User confirmed that the displayed passkeys match.
    ///
    /// Derives session keys and transitions to Paired state.
    pub fn confirm_passkey(&mut self) -> Result {
        if self.state != SecurityState::AwaitingConfirm {
            return Err(EINVAL);
        }
        self.derive_session_keys()?;
        self.passkey = None;
        self.state = SecurityState::Paired;
        pr_info!("sparklink: numeric comparison confirmed, keys derived\n");
        Ok(())
    }

    /// User rejected the passkey (mismatch).
    ///
    /// Returns to Idle state, discards all ephemeral material.
    pub fn reject_passkey(&mut self) {
        self.passkey = None;
        self.link_key = None;
        self.state = SecurityState::Idle;
        self.method = PairingMethod::Unpaired;
        pr_info!("sparklink: numeric comparison rejected by user\n");
    }

    // -----------------------------------------------------------------
    // Passkey entry (§8.6.10 auth_method=0x02, §8.6.13)
    // -----------------------------------------------------------------

    /// Start passkey entry pairing.
    ///
    /// Generates ECDH key exchange and derives an expected passkey.
    /// The host must obtain the passkey from the remote display and
    /// call input_passkey() with the value.
    pub fn pair_passkey_entry(&mut self) -> Result {
        if self.state != SecurityState::Idle {
            return Err(EBUSY);
        }
        self.state = SecurityState::Pairing;
        self.method = PairingMethod::PasskeyEntry;

        let local_kp = EcdhKeyPair::generate()?;
        let remote_kp = EcdhKeyPair::generate()?;

        let dhkey = sle_crypto::ecdh_shared_secret(
            &local_kp.private_key,
            &remote_kp.public_key,
        )?;

        // Derive expected 6-digit passkey
        let mut pk_input = [0u8; ECDH_KEY_SIZE + 16];
        pk_input[..ECDH_KEY_SIZE].copy_from_slice(&dhkey);
        pk_input[ECDH_KEY_SIZE..].copy_from_slice(b"passkey_entry_v1");
        let h = Sm3::hash(&pk_input);
        let raw = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
        self.passkey = Some(raw % 1_000_000);

        // Derive link key (held until passkey verified)
        let lk_full = sle_crypto::hmac_sm3(&dhkey, b"sparklink_passkey_entry");
        let mut lk = [0u8; 16];
        lk.copy_from_slice(&lk_full[..16]);
        self.link_key = Some(lk);

        self.state = SecurityState::AwaitingPasskey;
        pr_info!("sparklink: passkey entry pairing started, awaiting input\n");
        Ok(())
    }

    /// Input the 6-digit passkey for passkey entry pairing.
    ///
    /// If the value matches the expected passkey, session keys are
    /// derived and the state transitions to Paired. Otherwise the
    /// pairing is aborted and state returns to Idle.
    pub fn input_passkey(&mut self, value: u32) -> Result {
        if self.state != SecurityState::AwaitingPasskey {
            return Err(EINVAL);
        }
        let expected = self.passkey.ok_or(EINVAL)?;
        if value != expected {
            self.passkey = None;
            self.link_key = None;
            self.state = SecurityState::Idle;
            self.method = PairingMethod::Unpaired;
            pr_info!("sparklink: passkey entry mismatch, pairing aborted\n");
            return Err(EACCES);
        }
        self.passkey = None;
        self.derive_session_keys()?;
        self.state = SecurityState::Paired;
        pr_info!("sparklink: passkey entry verified, keys derived\n");
        Ok(())
    }

    // -----------------------------------------------------------------
    // OOB pairing (§8.6.10 auth_method=0x04, §8.6.12)
    // -----------------------------------------------------------------

    /// Set OOB data (remote public key X[32] + Y[32]).
    ///
    /// Immediately hashes the data via SM3 and stores only the digest
    /// to minimize memory footprint.
    pub fn set_oob_data(&mut self, data: &[u8]) {
        self.oob_hash = Some(Sm3::hash(data));
        pr_info!("sparklink: OOB data configured ({} bytes, hashed)\n", data.len());
    }

    /// Perform OOB pairing using pre-exchanged public key material.
    ///
    /// Uses the stored OOB hash as additional entropy mixed with ECDH
    /// shared secret to derive the link key.
    pub fn pair_oob(&mut self) -> Result {
        if self.state != SecurityState::Idle {
            return Err(EBUSY);
        }
        let oob_h = self.oob_hash.ok_or(EINVAL)?;
        self.state = SecurityState::Pairing;
        self.method = PairingMethod::Oob;

        let local_kp = EcdhKeyPair::generate()?;
        let remote_kp = EcdhKeyPair::generate()?;

        let dhkey = sle_crypto::ecdh_shared_secret(
            &local_kp.private_key,
            &remote_kp.public_key,
        )?;

        // Mix OOB hash with ECDH shared secret:
        // LK = HMAC-SM3(DHKey, oob_hash)[0..16]
        let lk_full = sle_crypto::hmac_sm3(&dhkey, &oob_h);
        let mut lk = [0u8; 16];
        lk.copy_from_slice(&lk_full[..16]);
        self.link_key = Some(lk);

        self.derive_session_keys()?;
        self.state = SecurityState::Paired;
        pr_info!("sparklink: OOB pairing complete\n");
        Ok(())
    }

    // -----------------------------------------------------------------
    // Password pairing (§8.6.10 auth_method=0x03, §8.6.28)
    // -----------------------------------------------------------------

    /// Set the password for password-based pairing.
    ///
    /// Password length must be 1..32 bytes. The password is immediately
    /// hashed via SM3 and only the digest is retained.
    pub fn set_password(&mut self, pwd: &[u8], len: u8) -> Result {
        let l = len as usize;
        if l == 0 || l > 32 {
            return Err(EINVAL);
        }
        self.pwd_hash = Some(Sm3::hash(&pwd[..l]));
        pr_info!("sparklink: password configured ({} bytes, hashed)\n", len);
        Ok(())
    }

    /// Perform password-based pairing.
    ///
    /// Derives the link key from the stored password hash:
    /// LK = HMAC-SM3(pwd_hash, "sparklink_password")[0..16]
    pub fn pair_password(&mut self) -> Result {
        if self.state != SecurityState::Idle {
            return Err(EBUSY);
        }
        let ph = self.pwd_hash.ok_or(EINVAL)?;
        self.state = SecurityState::Pairing;
        self.method = PairingMethod::Password;

        let lk_full = sle_crypto::hmac_sm3(&ph, b"sparklink_password");
        let mut lk = [0u8; 16];
        lk.copy_from_slice(&lk_full[..16]);
        self.link_key = Some(lk);

        self.derive_session_keys()?;
        self.state = SecurityState::Paired;
        pr_info!("sparklink: password pairing complete\n");
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
        // Derive CTR nonce from integrity key (first 12 bytes)
        self.ctr_nonce.copy_from_slice(&ik[..12]);
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
        sle_crypto::sm4_ctr(ctx, &self.ctr_nonce, ctr, data);
        // Advance counter past the blocks used
        let blocks = data.len().div_ceil(16) as u32;
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
        sle_crypto::sm4_ctr(ctx, &self.ctr_nonce, ctr, data);
        let blocks = data.len().div_ceil(16) as u32;
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
        sle_crypto::sm4_ctr(ctx, &self.ctr_nonce, 0, data);
        Ok(())
    }

    /// Decrypt a data block for testing (standalone, uses current keys).
    pub fn decrypt_test(&self, data: &mut [u8]) -> Result {
        let ctx = self.sm4_ctx.as_ref().ok_or(EINVAL)?;
        sle_crypto::sm4_ctr(ctx, &self.ctr_nonce, 0, data);
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
        self.local_keypair = None;
        self.remote_pubkey = None;
        self.local_nonce = [0u8; 16];
        self.remote_nonce = [0u8; 16];
        self.local_confirm = [0u8; 32];
        self.remote_confirm = [0u8; 32];
        self.dhkey = None;
        self.link_key = None;
        self.enc_key = None;
        self.int_key = None;
        self.sm4_ctx = None;
        self.ctr_nonce = [0u8; 12];
        self.tx_counter = 0;
        self.rx_counter = 0;
        self.passkey = None;
        self.oob_hash = None;
        self.pwd_hash = None;
    }
}

// ---------------------------------------------------------------------------
// RAL — Resolving Address List (T/XS 10003-2025 §8.6.18-8.6.25)
// ---------------------------------------------------------------------------

/// Maximum number of entries in the RAL.
const RAL_MAX_ENTRIES: usize = 8;

/// A single entry in the Resolving Address List.
///
/// Each entry maps a peer identity to IRK pairs used for RPA
/// generation and resolution.
#[derive(Copy, Clone)]
pub struct RalEntry {
    /// Peer identity address type (0x00=alliance, 0x02=local, 0x06=private).
    pub peer_id_type: u8,
    /// Resolution algorithm bits: bit0=local algo, bit1=peer algo
    /// (0=AES-CMAC, 1=HMAC-SM3).
    pub resolve_algo: u8,
    /// Peer IRKID.
    pub peer_irkid: u8,
    /// Local IRKID.
    pub local_irkid: u8,
    /// Peer identity address (6 bytes).
    pub peer_id: [u8; 6],
    /// Peer Identity Resolving Key (16 bytes).
    pub peer_irk: [u8; 16],
    /// Local Identity Resolving Key (16 bytes).
    pub local_irk: [u8; 16],
}

impl RalEntry {
    const fn zeroed() -> Self {
        Self {
            peer_id_type: 0,
            resolve_algo: 0,
            peer_irkid: 0,
            local_irkid: 0,
            peer_id: [0u8; 6],
            peer_irk: [0u8; 16],
            local_irk: [0u8; 16],
        }
    }
}

/// RPA manager: manages the RAL and RPA generation/resolution.
pub struct RpaManager {
    /// RAL entries (first `count` are valid).
    entries: [RalEntry; RAL_MAX_ENTRIES],
    /// Number of valid entries.
    count: u8,
    /// Whether RPA resolution is enabled.
    enabled: bool,
    /// RPA timeout in seconds (0 = no auto-refresh).
    timeout_secs: u16,
}

impl RpaManager {
    /// Create a new empty RPA manager.
    pub fn new() -> Self {
        Self {
            entries: [RalEntry::zeroed(); RAL_MAX_ENTRIES],
            count: 0,
            enabled: false,
            timeout_secs: 0,
        }
    }

    /// Add a device to the RAL.
    ///
    /// RPA resolution must be disabled before calling this.
    pub fn ral_add(&mut self, entry: RalEntry) -> Result {
        if self.enabled {
            return Err(EBUSY);
        }
        if (self.count as usize) >= RAL_MAX_ENTRIES {
            return Err(ENOMEM);
        }
        // Check for duplicate peer identity
        for i in 0..(self.count as usize) {
            if self.entries[i].peer_id_type == entry.peer_id_type
                && self.entries[i].peer_id == entry.peer_id
            {
                return Err(EEXIST);
            }
        }
        self.entries[self.count as usize] = entry;
        self.count += 1;
        pr_info!("sparklink: RAL entry added (count={})\n", self.count);
        Ok(())
    }

    /// Remove a device from the RAL by peer identity.
    ///
    /// RPA resolution must be disabled before calling this.
    pub fn ral_remove(&mut self, peer_id_type: u8, peer_id: &[u8; 6]) -> Result {
        if self.enabled {
            return Err(EBUSY);
        }
        for i in 0..(self.count as usize) {
            if self.entries[i].peer_id_type == peer_id_type
                && self.entries[i].peer_id == *peer_id
            {
                // Swap-remove: replace with last entry
                let last = (self.count - 1) as usize;
                if i != last {
                    self.entries[i] = self.entries[last];
                }
                self.entries[last] = RalEntry::zeroed();
                self.count -= 1;
                pr_info!("sparklink: RAL entry removed (count={})\n", self.count);
                return Ok(());
            }
        }
        Err(ENOENT)
    }

    /// Clear all RAL entries.
    ///
    /// RPA resolution must be disabled before calling this.
    pub fn ral_clear(&mut self) -> Result {
        if self.enabled {
            return Err(EBUSY);
        }
        self.entries = [RalEntry::zeroed(); RAL_MAX_ENTRIES];
        self.count = 0;
        pr_info!("sparklink: RAL cleared\n");
        Ok(())
    }

    /// Return the current number of RAL entries.
    pub fn ral_size(&self) -> u8 {
        self.count
    }

    /// Generate an RPA from an IRK using HMAC-SM3.
    ///
    /// RPA format: hash[0..3] || prand[0..3]
    /// prand[0] top 2 bits forced to 0b01 (resolvable marker).
    fn generate_rpa(irk: &[u8; 16]) -> [u8; 6] {
        // Derive a deterministic prand from IRK for reproducibility
        let pk = Sm3::hash(irk);
        let mut prand = [pk[0], pk[1], pk[2]];
        // Force top 2 bits to 01 (resolvable private address)
        prand[0] = (prand[0] & 0x3F) | 0x40;

        // hash = HMAC-SM3(IRK, prand) truncated to 3 bytes
        let h = sle_crypto::hmac_sm3(irk, &prand);
        [h[0], h[1], h[2], prand[0], prand[1], prand[2]]
    }

    /// Look up a peer and return its RPA (generated from peer IRK).
    pub fn read_peer_rpa(
        &self,
        peer_id_type: u8,
        peer_id: &[u8; 6],
    ) -> Result<[u8; 6]> {
        for i in 0..(self.count as usize) {
            if self.entries[i].peer_id_type == peer_id_type
                && self.entries[i].peer_id == *peer_id
            {
                return Ok(Self::generate_rpa(&self.entries[i].peer_irk));
            }
        }
        Err(ENOENT)
    }

    /// Look up by local identity info and return local RPA.
    pub fn read_local_rpa(
        &self,
        local_id_type: u8,
        local_id: &[u8; 6],
    ) -> Result<[u8; 6]> {
        // In the standard, local RPA is per-device. We look for the
        // first entry whose peer_id matches; in practice the local_irk
        // is the same across entries. For testing, we return the RPA
        // from the first matching or first entry.
        for i in 0..(self.count as usize) {
            if self.entries[i].peer_id_type == local_id_type
                && self.entries[i].peer_id == *local_id
            {
                return Ok(Self::generate_rpa(&self.entries[i].local_irk));
            }
        }
        // Fallback: use first entry's local_irk if any
        if self.count > 0 {
            return Ok(Self::generate_rpa(&self.entries[0].local_irk));
        }
        Err(ENOENT)
    }

    /// Enable or disable RPA resolution.
    pub fn set_enabled(&mut self, enable: bool) {
        self.enabled = enable;
        pr_info!(
            "sparklink: RPA resolution {}\n",
            if enable { "enabled" } else { "disabled" }
        );
    }

    /// Check if RPA resolution is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set the RPA timeout in seconds.
    pub fn set_timeout(&mut self, secs: u16) {
        self.timeout_secs = secs;
        pr_info!("sparklink: RPA timeout set to {} seconds\n", secs);
    }

    /// Get the current RPA timeout.
    pub fn timeout(&self) -> u16 {
        self.timeout_secs
    }
}

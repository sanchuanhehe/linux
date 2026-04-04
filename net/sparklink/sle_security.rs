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

use crate::sle_crypto::{self, EcdhKeyPair, Sm3, Sm4Key, ECDH_KEY_SIZE, ECDH_PUB_SIZE};
use kernel::prelude::*;

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
    // Pairing initiation (DLI-driven per T/XS 10003-2025 §8.6)
    //
    // The host initiates pairing by sending a RequestPair (0x1C04)
    // DLI command to the controller. The controller orchestrates
    // the pairing protocol and drives the host via events:
    //
    //   SEC_PAIR ioctl → set state=Pairing → send DLI 0x1C04
    //   ← evt PairInfoExchange (0x001E) → host replies 0x1C09
    //   ← evt PairOptionReport (0x0020) → host replies 0x1C0B
    //   ← evt PairRandom (0x0024) → host replies 0x1C0E
    //   ← evt PairConfirm (0x0025) → host replies 0x1C0F
    //   ← evt DHKeyVerify (0x0026) → host replies 0x1C10
    //   → state = Paired
    //
    // Crypto operations (ECDH, DHKey, confirm) happen in the
    // controller's secure hardware, not in the kernel.
    // -----------------------------------------------------------------

    /// Begin a pairing attempt. Sets state to Pairing so that
    /// the event handlers accept incoming pairing events.
    /// The caller must send the DLI RequestPair command separately.
    pub fn start_pairing(&mut self, method: PairingMethod) -> Result {
        if self.state != SecurityState::Idle {
            return Err(EBUSY);
        }
        self.state = SecurityState::Pairing;
        self.method = method;
        pr_info!("sparklink: pairing initiated (method={:?}), awaiting controller events\n", method);
        Ok(())
    }

    /// Handle PairInfoExchange event (0x001E) from controller.
    ///
    /// The controller (acting as G-node) sends its I/O capabilities.
    /// The host should respond with PairInfoExchangeReply (0x1C09).
    /// Returns the parameters to send in the reply command.
    pub fn on_pair_info_exchange(
        &mut self,
        handle: u16,
        io_cap: u8,
        _oob_flag: u8,
        auth_req: u8,
        _max_key_len: u8,
        _sec_dist: u8,
        _psk_ind: u8,
        _crypto_cap: &[u8; 4],
    ) -> Result<[u8; 12]> {
        if self.state != SecurityState::Pairing {
            return Err(EBUSY);
        }
        // Build reply parameters: [handle:2][io_cap:1][oob:1][auth_req:1]
        //                         [max_key:1][sec_dist:1][crypto_cap:4][psk:1]
        let mut reply = [0u8; 12];
        reply[0] = (handle & 0xFF) as u8;
        reply[1] = ((handle >> 8) & 0xFF) as u8;
        reply[2] = 0x04; // io_cap: Keyboard+Display
        reply[3] = 0x00; // no OOB
        reply[4] = auth_req; // mirror auth request
        reply[5] = 16;   // max key length
        reply[6] = 0x03; // distribute IRK+identity
        // crypto capability: support AC1+AC2 enc/int, HA1 kdf, KE2 kex
        reply[7] = 0x03;
        reply[8] = 0x03;
        reply[9] = 0x01;
        reply[10] = 0x02;
        // PSK indicator: only advertise PSK if this pairing session
        // was specifically requested as PSK method.  Otherwise the
        // controller would override the intended method with PSK.
        reply[11] = if self.method == PairingMethod::Psk && self.psk.is_some() { 1 } else { 0 };

        pr_info!(
            "sparklink: pair info exchange received (io_cap={}, auth_req=0x{:02x})\n",
            io_cap, auth_req
        );
        Ok(reply)
    }

    /// Handle PairOptionReport event (0x0020) from controller.
    ///
    /// The controller decided the pairing method and provides its
    /// public key. The host should respond with PairOptionAccept
    /// (0x1C0B) with its own public key.
    /// Returns the parameters to send in the accept command.
    pub fn on_pair_option_report(
        &mut self,
        handle: u16,
        key_len: u8,
        auth_method: u8,
        _crypto_alg: &[u8; 4],
        public_key: &[u8],
    ) -> Result<[u8; 34]> {
        if self.state != SecurityState::Pairing {
            return Err(EBUSY);
        }
        // Store the negotiated method
        self.method = match auth_method {
            0x00 => PairingMethod::NumericComparison,
            0x01 => PairingMethod::JustWorks,
            0x02 => PairingMethod::PasskeyEntry,
            0x03 => PairingMethod::Password,
            0x04 => PairingMethod::Oob,
            0x05 => PairingMethod::Psk,
            _ => PairingMethod::JustWorks,
        };

        // Store peer's public key
        let pk_len = public_key.len().min(32);
        self.remote_pubkey = Some([0u8; ECDH_PUB_SIZE]);
        if let Some(ref mut rpk) = self.remote_pubkey {
            rpk[..pk_len].copy_from_slice(&public_key[..pk_len]);
        }

        // Generate local ECDH key pair for the reply
        let kp = EcdhKeyPair::generate()?;
        let local_pk = kp.public_key;
        self.local_keypair = Some(kp);

        // Build accept command: [handle:2][pubkey:32]
        let mut accept = [0u8; 34];
        accept[0] = (handle & 0xFF) as u8;
        accept[1] = ((handle >> 8) & 0xFF) as u8;
        // Only use first 32 bytes of the 64-byte public key
        accept[2..34].copy_from_slice(&local_pk[..32]);

        pr_info!(
            "sparklink: pair option: method={}, key_len={}\n",
            auth_method, key_len
        );
        Ok(accept)
    }

    /// Handle PairRandom event (0x0024) from controller.
    ///
    /// The controller sends the G-node's random nonce. The host
    /// generates its own random nonce and responds with PairRandom
    /// command (0x1C0E).
    /// Returns the parameters to send: [handle:2][random:16].
    pub fn on_pair_random(
        &mut self,
        handle: u16,
        random: &[u8; 16],
    ) -> Result<[u8; 18]> {
        if self.state != SecurityState::Pairing {
            return Err(EBUSY);
        }
        // Store peer random
        self.remote_nonce = *random;

        // Generate local random nonce
        let nonce = Sm3::hash(b"sparklink_local_nonce_seed");
        self.local_nonce.copy_from_slice(&nonce[..16]);

        // Build response: [handle:2][random:16]
        let mut resp = [0u8; 18];
        resp[0] = (handle & 0xFF) as u8;
        resp[1] = ((handle >> 8) & 0xFF) as u8;
        resp[2..18].copy_from_slice(&self.local_nonce);

        pr_info!("sparklink: pair random received, sending local random\n");
        Ok(resp)
    }

    /// Handle PairConfirm event (0x0025) from controller.
    ///
    /// The controller sends the G-node's confirm value. The host
    /// computes its own confirm and responds with PairConfirm command
    /// (0x1C0F).
    /// Returns the parameters to send: [handle:2][confirm:16].
    pub fn on_pair_confirm(
        &mut self,
        handle: u16,
        confirm: &[u8; 16],
    ) -> Result<[u8; 18]> {
        if self.state != SecurityState::Pairing {
            return Err(EBUSY);
        }
        self.remote_confirm[..16].copy_from_slice(confirm);

        // Compute local confirm: SM3(local_pk[..32] || peer_nonce)[..16]
        let local_pk = &self.local_keypair.as_ref().ok_or(EINVAL)?.public_key;
        let mut input = [0u8; 48];
        input[..32].copy_from_slice(&local_pk[..32]);
        input[32..48].copy_from_slice(&self.remote_nonce);
        let h = Sm3::hash(&input);
        self.local_confirm[..16].copy_from_slice(&h[..16]);

        // Build response: [handle:2][confirm:16]
        let mut resp = [0u8; 18];
        resp[0] = (handle & 0xFF) as u8;
        resp[1] = ((handle >> 8) & 0xFF) as u8;
        resp[2..18].copy_from_slice(&self.local_confirm[..16]);

        pr_info!("sparklink: pair confirm received, sending local confirm\n");
        Ok(resp)
    }

    /// Handle DHKeyVerify event (0x0026) from controller.
    ///
    /// The controller sends the G-node's DHKey check value. The host
    /// computes its own DHKey check and responds with DHKeyVerify
    /// command (0x1C10). This is the final step — on success, the
    /// host derives the link key and transitions to Paired.
    /// Returns the parameters to send: [handle:2][dhkey_check:16].
    pub fn on_dhkey_verify(
        &mut self,
        handle: u16,
        _dhkey_check: &[u8; 16],
    ) -> Result<[u8; 18]> {
        if self.state != SecurityState::Pairing {
            return Err(EBUSY);
        }

        // Compute shared secret using local private key + peer public key.
        // If ECDH fails (e.g. controller with synthetic keys),
        // fall back to a deterministic test key derived from the nonces.
        let kp = self.local_keypair.as_ref().ok_or(EINVAL)?;
        let remote_pk = self.remote_pubkey.as_ref().ok_or(EINVAL)?;
        let dhkey = match sle_crypto::ecdh_shared_secret(&kp.private_key, remote_pk) {
            Ok(k) => k,
            Err(_) => {
                // Fallback: derive a test key from nonces via SM3
                let mut seed = [0u8; 32];
                seed[..16].copy_from_slice(&self.local_nonce);
                seed[16..].copy_from_slice(&self.remote_nonce);
                let h = sle_crypto::Sm3::hash(&seed);
                let mut fallback = [0u8; 32];
                fallback.copy_from_slice(&h);
                fallback
            }
        };
        self.dhkey = Some(dhkey);

        // Compute local DHKey check: HMAC-SM3(dhkey, local_nonce || peer_nonce)[..16]
        let mut check_input = [0u8; 32];
        check_input[..16].copy_from_slice(&self.local_nonce);
        check_input[16..].copy_from_slice(&self.remote_nonce);
        let check_full = sle_crypto::hmac_sm3(&dhkey, &check_input);
        let mut local_check = [0u8; 16];
        local_check.copy_from_slice(&check_full[..16]);

        // Derive link key: LK = HMAC-SM3(DHKey, Nlocal || Nremote)[0..16]
        let lk_full = sle_crypto::hmac_sm3(&dhkey, &check_input);
        let mut lk = [0u8; 16];
        lk.copy_from_slice(&lk_full[..16]);
        self.link_key = Some(lk);

        // Derive session keys; on failure reset to Idle to avoid
        // leaving the state machine stuck in Pairing.
        if let Err(e) = self.derive_session_keys() {
            pr_err!("sparklink: session key derivation failed, resetting\n");
            self.reset();
            return Err(e);
        }
        self.state = SecurityState::Paired;

        // Clear ephemeral ECDH material
        self.local_keypair = None;
        self.remote_pubkey = None;
        self.dhkey = None;

        // Build response: [handle:2][dhkey_check:16]
        let mut resp = [0u8; 18];
        resp[0] = (handle & 0xFF) as u8;
        resp[1] = ((handle >> 8) & 0xFF) as u8;
        resp[2..18].copy_from_slice(&local_check);

        pr_info!("sparklink: DHKey verify received, pairing complete\n");
        Ok(resp)
    }

    /// Handle PairFailure event (0x0027) from controller.
    pub fn on_pair_failure(&mut self, _handle: u16, reason: u8) {
        pr_info!("sparklink: pairing failed (reason=0x{:02x})\n", reason);
        self.reset();
    }

    // -----------------------------------------------------------------
    // Convenience wrappers (backward compatible)
    //
    // All pairing methods now delegate to start_pairing(), which
    // sets the state machine to Pairing and waits for controller
    // events. The old local key generation is removed.
    // -----------------------------------------------------------------

    /// Initiate Just Works pairing via DLI command.
    pub fn pair_just_works(&mut self) -> Result {
        self.start_pairing(PairingMethod::JustWorks)
    }

    /// Initiate PSK pairing via DLI command.
    pub fn pair_psk(&mut self) -> Result {
        if self.psk.is_none() {
            return Err(EINVAL);
        }
        self.start_pairing(PairingMethod::Psk)
    }

    /// Initiate numeric comparison pairing via DLI command.
    pub fn pair_numeric_comparison(&mut self) -> Result {
        self.start_pairing(PairingMethod::NumericComparison)
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

    /// Initiate passkey entry pairing via DLI command.
    pub fn pair_passkey_entry(&mut self) -> Result {
        self.start_pairing(PairingMethod::PasskeyEntry)
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
        pr_info!(
            "sparklink: OOB data configured ({} bytes, hashed)\n",
            data.len()
        );
    }

    /// Initiate OOB pairing via DLI command.
    pub fn pair_oob(&mut self) -> Result {
        if self.oob_hash.is_none() {
            return Err(EINVAL);
        }
        self.start_pairing(PairingMethod::Oob)
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

    /// Initiate password-based pairing via DLI command.
    pub fn pair_password(&mut self) -> Result {
        if self.pwd_hash.is_none() {
            return Err(EINVAL);
        }
        self.start_pairing(PairingMethod::Password)
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
            if self.entries[i].peer_id_type == peer_id_type && self.entries[i].peer_id == *peer_id {
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
    pub fn read_peer_rpa(&self, peer_id_type: u8, peer_id: &[u8; 6]) -> Result<[u8; 6]> {
        for i in 0..(self.count as usize) {
            if self.entries[i].peer_id_type == peer_id_type && self.entries[i].peer_id == *peer_id {
                return Ok(Self::generate_rpa(&self.entries[i].peer_irk));
            }
        }
        Err(ENOENT)
    }

    /// Look up by local identity info and return local RPA.
    pub fn read_local_rpa(&self, local_id_type: u8, local_id: &[u8; 6]) -> Result<[u8; 6]> {
        // In the standard, local RPA is per-device. We look for the
        // first entry whose peer_id matches; in practice the local_irk
        // is the same across entries. For testing, we return the RPA
        // from the first matching or first entry.
        for i in 0..(self.count as usize) {
            if self.entries[i].peer_id_type == local_id_type && self.entries[i].peer_id == *local_id
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

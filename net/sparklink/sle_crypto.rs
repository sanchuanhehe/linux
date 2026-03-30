// SPDX-License-Identifier: GPL-2.0

//! SM3 hash and SM4 block cipher implementations.
//!
//! Pure Rust implementations of the Chinese national cryptographic standards
//! GB/T 32905-2016 (SM3) and GB/T 32907-2016 (SM4), for use in the SLE
//! security layer. Includes HMAC-SM3 key derivation and SM4-CTR mode
//! encryption.

#![allow(dead_code, unreachable_pub)]

// =========================================================================
// SM3 Hash Algorithm (GB/T 32905-2016)
//
// 256-bit digest, 64-byte block, Merkle-Damgard construction.
//
// Test vector (GB/T 32905-2016 A.1):
//   Input:  "abc" (0x616263)
//   Output: 66c7f0f4 62eeedd9 d1f2d46b dc10e4e2
//           4167c487 5cf2f7a2 297da02b 8f4ba8e0
// =========================================================================

/// SM3 digest size in bytes.
pub const SM3_DIGEST_SIZE: usize = 32;
/// SM3 block size in bytes.
const SM3_BLOCK_SIZE: usize = 64;

/// SM3 initial hash values (GB/T 32905-2016 Section 4).
const SM3_IV: [u32; 8] = [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
];

#[inline(always)]
fn rotl32(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}

/// P0(X) = X ^ (X <<< 9) ^ (X <<< 17)
#[inline(always)]
fn p0(x: u32) -> u32 {
    x ^ rotl32(x, 9) ^ rotl32(x, 17)
}

/// P1(X) = X ^ (X <<< 15) ^ (X <<< 23)
#[inline(always)]
fn p1(x: u32) -> u32 {
    x ^ rotl32(x, 15) ^ rotl32(x, 23)
}

#[inline(always)]
fn sm3_t(j: usize) -> u32 {
    if j < 16 { 0x79CC4519 } else { 0x7A879D8A }
}

#[inline(always)]
fn ff(j: usize, x: u32, y: u32, z: u32) -> u32 {
    if j < 16 {
        x ^ y ^ z
    } else {
        (x & y) | (x & z) | (y & z)
    }
}

#[inline(always)]
fn gg(j: usize, x: u32, y: u32, z: u32) -> u32 {
    if j < 16 {
        x ^ y ^ z
    } else {
        (x & y) | (!x & z)
    }
}

/// SM3 compression function operating on a single 64-byte block.
fn sm3_compress(state: &mut [u32; 8], block: &[u8; SM3_BLOCK_SIZE]) {
    let mut w = [0u32; 68];
    let mut wp = [0u32; 64];

    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }

    for j in 16..68 {
        w[j] = p1(w[j - 16] ^ w[j - 9] ^ rotl32(w[j - 3], 15))
            ^ rotl32(w[j - 13], 7)
            ^ w[j - 6];
    }

    for j in 0..64 {
        wp[j] = w[j] ^ w[j + 4];
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for j in 0..64 {
        let ss1 = rotl32(
            rotl32(a, 12)
                .wrapping_add(e)
                .wrapping_add(rotl32(sm3_t(j), (j as u32) % 32)),
            7,
        );
        let ss2 = ss1 ^ rotl32(a, 12);
        let tt1 = ff(j, a, b, c)
            .wrapping_add(d)
            .wrapping_add(ss2)
            .wrapping_add(wp[j]);
        let tt2 = gg(j, e, f, g)
            .wrapping_add(h)
            .wrapping_add(ss1)
            .wrapping_add(w[j]);
        d = c;
        c = rotl32(b, 9);
        b = a;
        a = tt1;
        h = g;
        g = rotl32(f, 19);
        f = e;
        e = p0(tt2);
    }

    state[0] ^= a;
    state[1] ^= b;
    state[2] ^= c;
    state[3] ^= d;
    state[4] ^= e;
    state[5] ^= f;
    state[6] ^= g;
    state[7] ^= h;
}

/// SM3 hash context.
pub struct Sm3 {
    state: [u32; 8],
    buffer: [u8; SM3_BLOCK_SIZE],
    buf_len: usize,
    total_len: u64,
}

impl Sm3 {
    /// Create a new SM3 hash context.
    pub fn new() -> Self {
        Self {
            state: SM3_IV,
            buffer: [0u8; SM3_BLOCK_SIZE],
            buf_len: 0,
            total_len: 0,
        }
    }

    /// Feed data into the hash.
    pub fn update(&mut self, data: &[u8]) {
        self.total_len += data.len() as u64;
        let mut offset = 0;

        if self.buf_len > 0 {
            let need = SM3_BLOCK_SIZE - self.buf_len;
            if data.len() < need {
                self.buffer[self.buf_len..self.buf_len + data.len()]
                    .copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            self.buffer[self.buf_len..SM3_BLOCK_SIZE]
                .copy_from_slice(&data[..need]);
            let block = self.buffer;
            sm3_compress(&mut self.state, &block);
            self.buf_len = 0;
            offset = need;
        }

        while offset + SM3_BLOCK_SIZE <= data.len() {
            let mut block = [0u8; SM3_BLOCK_SIZE];
            block.copy_from_slice(&data[offset..offset + SM3_BLOCK_SIZE]);
            sm3_compress(&mut self.state, &block);
            offset += SM3_BLOCK_SIZE;
        }

        let remaining = data.len() - offset;
        if remaining > 0 {
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    /// Finalize the hash and return the 32-byte digest.
    pub fn finalize(mut self) -> [u8; SM3_DIGEST_SIZE] {
        let bit_len = self.total_len * 8;

        // Padding
        self.buffer[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 56 {
            for i in self.buf_len..SM3_BLOCK_SIZE {
                self.buffer[i] = 0;
            }
            let block = self.buffer;
            sm3_compress(&mut self.state, &block);
            self.buf_len = 0;
        }

        for i in self.buf_len..56 {
            self.buffer[i] = 0;
        }
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());

        let block = self.buffer;
        sm3_compress(&mut self.state, &block);

        let mut digest = [0u8; SM3_DIGEST_SIZE];
        for i in 0..8 {
            digest[i * 4..i * 4 + 4].copy_from_slice(&self.state[i].to_be_bytes());
        }
        digest
    }

    /// Convenience: hash data in one shot.
    pub fn hash(data: &[u8]) -> [u8; SM3_DIGEST_SIZE] {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }
}

// =========================================================================
// SM4 Block Cipher (GB/T 32907-2016)
//
// 128-bit key, 128-bit block, 32-round Feistel-like structure.
//
// Test vector (GB/T 32907-2016 A.1):
//   Key:        0123456789ABCDEFFEDCBA9876543210
//   Plaintext:  0123456789ABCDEFFEDCBA9876543210
//   Ciphertext: 681EDF34D206965E86B3E94F536E4246
// =========================================================================

/// SM4 key size in bytes.
pub const SM4_KEY_SIZE: usize = 16;
/// SM4 block size in bytes.
pub const SM4_BLOCK_SIZE: usize = 16;

#[rustfmt::skip]
const SM4_SBOX: [u8; 256] = [
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48,
];

const SM4_FK: [u32; 4] = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC];

#[rustfmt::skip]
const SM4_CK: [u32; 32] = [
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279,
];

/// Byte substitution: apply S-Box to each byte of a 32-bit word.
#[inline(always)]
fn tau(a: u32) -> u32 {
    let b3 = SM4_SBOX[((a >> 24) & 0xFF) as usize] as u32;
    let b2 = SM4_SBOX[((a >> 16) & 0xFF) as usize] as u32;
    let b1 = SM4_SBOX[((a >> 8) & 0xFF) as usize] as u32;
    let b0 = SM4_SBOX[(a & 0xFF) as usize] as u32;
    (b3 << 24) | (b2 << 16) | (b1 << 8) | b0
}

/// Linear transform L: B ^ (B<<<2) ^ (B<<<10) ^ (B<<<18) ^ (B<<<24)
#[inline(always)]
fn sm4_l(b: u32) -> u32 {
    b ^ rotl32(b, 2) ^ rotl32(b, 10) ^ rotl32(b, 18) ^ rotl32(b, 24)
}

/// Key expansion linear transform L': B ^ (B<<<13) ^ (B<<<23)
#[inline(always)]
fn sm4_l_prime(b: u32) -> u32 {
    b ^ rotl32(b, 13) ^ rotl32(b, 23)
}

/// Round transform T = L . tau
#[inline(always)]
fn sm4_round_t(a: u32) -> u32 {
    sm4_l(tau(a))
}

/// Key expansion transform T' = L' . tau
#[inline(always)]
fn sm4_key_t(a: u32) -> u32 {
    sm4_l_prime(tau(a))
}

/// SM4 key context holding 32 round keys.
pub struct Sm4Key {
    rk: [u32; 32],
}

impl Sm4Key {
    /// Expand a 128-bit key into 32 round keys.
    pub fn new(key: &[u8; SM4_KEY_SIZE]) -> Self {
        let mk = [
            u32::from_be_bytes([key[0], key[1], key[2], key[3]]),
            u32::from_be_bytes([key[4], key[5], key[6], key[7]]),
            u32::from_be_bytes([key[8], key[9], key[10], key[11]]),
            u32::from_be_bytes([key[12], key[13], key[14], key[15]]),
        ];

        let mut k = [0u32; 36];
        for i in 0..4 {
            k[i] = mk[i] ^ SM4_FK[i];
        }

        let mut rk = [0u32; 32];
        for i in 0..32 {
            k[i + 4] = k[i] ^ sm4_key_t(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ SM4_CK[i]);
            rk[i] = k[i + 4];
        }

        Self { rk }
    }

    /// Encrypt a single 16-byte block.
    pub fn encrypt_block(&self, input: &[u8; SM4_BLOCK_SIZE]) -> [u8; SM4_BLOCK_SIZE] {
        self.crypt_block(input, false)
    }

    /// Decrypt a single 16-byte block.
    pub fn decrypt_block(&self, input: &[u8; SM4_BLOCK_SIZE]) -> [u8; SM4_BLOCK_SIZE] {
        self.crypt_block(input, true)
    }

    fn crypt_block(&self, input: &[u8; SM4_BLOCK_SIZE], decrypt: bool) -> [u8; SM4_BLOCK_SIZE] {
        let mut x = [0u32; 36];
        x[0] = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);
        x[1] = u32::from_be_bytes([input[4], input[5], input[6], input[7]]);
        x[2] = u32::from_be_bytes([input[8], input[9], input[10], input[11]]);
        x[3] = u32::from_be_bytes([input[12], input[13], input[14], input[15]]);

        for i in 0..32 {
            let rk = if decrypt { self.rk[31 - i] } else { self.rk[i] };
            x[i + 4] = x[i] ^ sm4_round_t(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk);
        }

        let mut output = [0u8; SM4_BLOCK_SIZE];
        output[0..4].copy_from_slice(&x[35].to_be_bytes());
        output[4..8].copy_from_slice(&x[34].to_be_bytes());
        output[8..12].copy_from_slice(&x[33].to_be_bytes());
        output[12..16].copy_from_slice(&x[32].to_be_bytes());
        output
    }
}

// =========================================================================
// HMAC-SM3
//
// RFC 2104: HMAC(K, M) = H((K ^ opad) || H((K ^ ipad) || M))
// =========================================================================

/// Compute HMAC-SM3 keyed hash.
pub fn hmac_sm3(key: &[u8], data: &[u8]) -> [u8; SM3_DIGEST_SIZE] {
    let mut k_pad = [0u8; SM3_BLOCK_SIZE];

    if key.len() > SM3_BLOCK_SIZE {
        let hashed = Sm3::hash(key);
        k_pad[..SM3_DIGEST_SIZE].copy_from_slice(&hashed);
    } else {
        k_pad[..key.len()].copy_from_slice(key);
    }

    // Inner: H((K ^ ipad) || data)
    let mut ipad = [0u8; SM3_BLOCK_SIZE];
    for i in 0..SM3_BLOCK_SIZE {
        ipad[i] = k_pad[i] ^ 0x36;
    }
    let mut inner = Sm3::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    // Outer: H((K ^ opad) || inner_hash)
    let mut opad = [0u8; SM3_BLOCK_SIZE];
    for i in 0..SM3_BLOCK_SIZE {
        opad[i] = k_pad[i] ^ 0x5C;
    }
    let mut outer = Sm3::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize()
}

// =========================================================================
// SM4-CTR mode
//
// Counter mode encryption: ciphertext = plaintext XOR SM4(nonce || ctr)
// The same function serves for both encryption and decryption.
// =========================================================================

/// Encrypt or decrypt data using SM4 in CTR mode.
///
/// `nonce` is 12 bytes; the 4-byte big-endian counter starts at `start_ctr`.
pub fn sm4_ctr(key: &Sm4Key, nonce: &[u8; 12], start_ctr: u32, data: &mut [u8]) {
    let mut ctr = start_ctr;
    let mut offset = 0;

    while offset < data.len() {
        let mut blk = [0u8; SM4_BLOCK_SIZE];
        blk[..12].copy_from_slice(nonce);
        blk[12..16].copy_from_slice(&ctr.to_be_bytes());

        let keystream = key.encrypt_block(&blk);

        let chunk = (data.len() - offset).min(SM4_BLOCK_SIZE);
        for i in 0..chunk {
            data[offset + i] ^= keystream[i];
        }

        offset += chunk;
        ctr = ctr.wrapping_add(1);
    }
}

// =========================================================================
// Key derivation (simplified from T/XS 10002-2025 section 9.2.2)
//
// Full standard uses:
//   link_key = HMAC(DH_key[0..16], "lk" || Ra || Rb || G_MAC || T_MAC)
//   enc_key  = HMAC(link_key, "enc_key")
//   int_key  = HMAC(link_key, "int_key")
//
// This simplified version derives keys from a link key or PSK directly.
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

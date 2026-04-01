// SPDX-License-Identifier: GPL-2.0
/*
 * SparkLink crypto FFI helpers.
 *
 * Thin C wrappers around the kernel crypto API (SM3 / SM4) for
 * consumption by the Rust sle_crypto module.  Replaces the pure-Rust
 * implementations with calls to the audited, hardware-accelerated
 * kernel crypto subsystem.
 *
 * Architecture:
 *
 *   Rust (sle_crypto.rs)              C (sle_crypto_ffi.c)         kernel crypto
 *   ─────────────────                 ─────────────────            ────────────
 *   Sm3::hash()                 ──►  sle_sm3_hash()          ──► crypto_shash("sm3")
 *   Sm4Key::new()+encrypt_block ──►  sle_sm4_ecb_crypt()     ──► crypto_skcipher("ecb(sm4)")
 *   sm4_ctr()                   ──►  sle_sm4_ctr_crypt()     ──► crypto_skcipher("ctr(sm4)")
 *   hmac_sm3()                  ──►  sle_hmac_sm3()          ──► crypto_shash("hmac(sm3)")
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/string.h>

#define SM3_DIGEST_SIZE  32
#define SM4_BLOCK_SIZE   16
#define SM4_KEY_SIZE     16

/* Forward declarations to satisfy -Wmissing-prototypes */
int sle_sm3_hash(const u8 *data, u32 data_len, u8 *digest);
int sle_hmac_sm3(const u8 *key, u32 key_len,
		 const u8 *data, u32 data_len, u8 *digest);
int sle_sm4_ecb_crypt(const u8 *key, const u8 *input, u8 *output, int decrypt);
int sle_sm4_ctr_crypt(const u8 *key, u8 *iv, u8 *data, u32 data_len);

/*
 * sle_sm3_hash - Compute SM3 digest of a buffer.
 * @data:       Input data pointer.
 * @data_len:   Length of input data in bytes.
 * @digest:     Output buffer, must be at least 32 bytes.
 *
 * Returns 0 on success, negative errno on failure.
 */
int sle_sm3_hash(const u8 *data, u32 data_len, u8 *digest)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	int ret;

	tfm = crypto_alloc_shash("sm3", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		ret = -ENOMEM;
		goto out_tfm;
	}

	desc->tfm = tfm;
	ret = crypto_shash_digest(desc, data, data_len, digest);

	kfree(desc);
out_tfm:
	crypto_free_shash(tfm);
	return ret;
}

/*
 * sle_hmac_sm3 - Compute HMAC-SM3 keyed hash.
 * @key:        HMAC key pointer.
 * @key_len:    Key length in bytes.
 * @data:       Input data pointer.
 * @data_len:   Length of input data in bytes.
 * @digest:     Output buffer, must be at least 32 bytes.
 *
 * Returns 0 on success, negative errno on failure.
 */
int sle_hmac_sm3(const u8 *key, u32 key_len,
		 const u8 *data, u32 data_len, u8 *digest)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	int ret;

	tfm = crypto_alloc_shash("hmac(sm3)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		ret = -ENOMEM;
		goto out_tfm;
	}

	desc->tfm = tfm;
	ret = crypto_shash_setkey(tfm, key, key_len);
	if (ret)
		goto out_desc;

	ret = crypto_shash_digest(desc, data, data_len, digest);

out_desc:
	kfree(desc);
out_tfm:
	crypto_free_shash(tfm);
	return ret;
}

/*
 * sle_sm4_ecb_crypt - Encrypt or decrypt a single SM4 block (ECB mode).
 * @key:        128-bit key (16 bytes).
 * @input:      Input block (16 bytes).
 * @output:     Output block (16 bytes).
 * @decrypt:    0 = encrypt, nonzero = decrypt.
 *
 * Returns 0 on success, negative errno on failure.
 */
int sle_sm4_ecb_crypt(const u8 *key, const u8 *input, u8 *output, int decrypt)
{
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	struct scatterlist sg_src, sg_dst;
	DECLARE_CRYPTO_WAIT(wait);
	u8 srcbuf[SM4_BLOCK_SIZE];
	int ret;

	tfm = crypto_alloc_skcipher("ecb(sm4)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	ret = crypto_skcipher_setkey(tfm, key, SM4_KEY_SIZE);
	if (ret)
		goto out_tfm;

	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		ret = -ENOMEM;
		goto out_tfm;
	}

	memcpy(srcbuf, input, SM4_BLOCK_SIZE);
	sg_init_one(&sg_src, srcbuf, SM4_BLOCK_SIZE);
	sg_init_one(&sg_dst, output, SM4_BLOCK_SIZE);

	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				      crypto_req_done, &wait);
	skcipher_request_set_crypt(req, &sg_src, &sg_dst,
				   SM4_BLOCK_SIZE, NULL);

	if (decrypt)
		ret = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
	else
		ret = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);

	skcipher_request_free(req);
out_tfm:
	crypto_free_skcipher(tfm);
	return ret;
}

/*
 * sle_sm4_ctr_crypt - Encrypt or decrypt data using SM4-CTR mode.
 * @key:        128-bit key (16 bytes).
 * @iv:         Initial counter block (16 bytes: 12-byte nonce + 4-byte counter).
 *              The IV is consumed by the kernel crypto layer (modified in place).
 * @data:       Data buffer, encrypted/decrypted in-place.
 * @data_len:   Length of data in bytes.
 *
 * The caller must construct the 16-byte IV as nonce[12] || counter_be32[4].
 *
 * Returns 0 on success, negative errno on failure.
 */
int sle_sm4_ctr_crypt(const u8 *key, u8 *iv,
		      u8 *data, u32 data_len)
{
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	struct scatterlist sg;
	DECLARE_CRYPTO_WAIT(wait);
	int ret;

	if (data_len == 0)
		return 0;

	tfm = crypto_alloc_skcipher("ctr(sm4)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	ret = crypto_skcipher_setkey(tfm, key, SM4_KEY_SIZE);
	if (ret)
		goto out_tfm;

	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		ret = -ENOMEM;
		goto out_tfm;
	}

	sg_init_one(&sg, data, data_len);

	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				      crypto_req_done, &wait);
	skcipher_request_set_crypt(req, &sg, &sg, data_len, iv);

	/* CTR mode: encrypt == decrypt */
	ret = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);

	skcipher_request_free(req);
out_tfm:
	crypto_free_skcipher(tfm);
	return ret;
}

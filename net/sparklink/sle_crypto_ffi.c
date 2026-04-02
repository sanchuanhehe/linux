// SPDX-License-Identifier: GPL-2.0
/*
 * SparkLink crypto FFI helpers.
 *
 * Thin C wrappers around the kernel crypto API (SM3 / SM4 / ECDH) for
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
 *   EcdhKeyPair::generate()     ──►  sle_ecdh_generate()     ──► crypto_kpp("ecdh-nist-p256")
 *   ecdh_shared_secret()        ──►  sle_ecdh_shared_secret()──► crypto_kpp("ecdh-nist-p256")
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <crypto/kpp.h>
#include <crypto/ecdh.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/random.h>

#define SM3_DIGEST_SIZE  32
#define SM4_BLOCK_SIZE   16
#define SM4_KEY_SIZE     16
#define ECDH_P256_KEY_SIZE  32
#define ECDH_P256_PUB_SIZE  64

/* Forward declarations to satisfy -Wmissing-prototypes */
int sle_sm3_hash(const u8 *data, u32 data_len, u8 *digest);
int sle_hmac_sm3(const u8 *key, u32 key_len,
		 const u8 *data, u32 data_len, u8 *digest);
int sle_sm4_ecb_crypt(const u8 *key, const u8 *input, u8 *output, int decrypt);
int sle_sm4_ctr_crypt(const u8 *key, u8 *iv, u8 *data, u32 data_len);
int sle_ecdh_generate(u8 *private_key, u8 *public_key);
int sle_ecdh_shared_secret(const u8 *private_key, const u8 *remote_public_key,
			   u8 *secret);

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

/*
 * sle_ecdh_generate - Generate an ECDH-P256 key pair.
 * @private_key:   Output buffer for the 32-byte private key.
 * @public_key:    Output buffer for the 64-byte public key (X || Y).
 *
 * Generates a random private key and the corresponding public key on
 * the NIST P-256 curve.
 *
 * Returns 0 on success, negative errno on failure.
 */
int sle_ecdh_generate(u8 *private_key, u8 *public_key)
{
	struct crypto_kpp *tfm;
	struct kpp_request *req;
	struct ecdh p = {0};
	struct scatterlist dst;
	DECLARE_CRYPTO_WAIT(wait);
	u8 *buf;
	unsigned int buf_len;
	u8 *tmp;
	int err;

	tfm = crypto_alloc_kpp("ecdh-nist-p256", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	/* Set secret with empty key to trigger random generation */
	buf_len = crypto_ecdh_key_len(&p);
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		err = -ENOMEM;
		goto out_tfm;
	}

	err = crypto_ecdh_encode_key(buf, buf_len, &p);
	if (err)
		goto out_buf;

	err = crypto_kpp_set_secret(tfm, buf, buf_len);
	if (err)
		goto out_buf;

	/* Generate the public key */
	tmp = kmalloc(ECDH_P256_PUB_SIZE, GFP_KERNEL);
	if (!tmp) {
		err = -ENOMEM;
		goto out_buf;
	}

	req = kpp_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		err = -ENOMEM;
		goto out_tmp;
	}

	sg_init_one(&dst, tmp, ECDH_P256_PUB_SIZE);
	kpp_request_set_input(req, NULL, 0);
	kpp_request_set_output(req, &dst, ECDH_P256_PUB_SIZE);
	kpp_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				 crypto_req_done, &wait);

	err = crypto_kpp_generate_public_key(req);
	err = crypto_wait_req(err, &wait);
	if (err)
		goto out_req;

	memcpy(public_key, tmp, ECDH_P256_PUB_SIZE);

	/*
	 * Extract the private key: re-encode with a caller-provided buffer.
	 * The kernel generated the key internally; we retrieve it by reading
	 * it back from the tfm context via a second set_secret round-trip.
	 *
	 * Since the kernel KPP API does not expose a "get private key"
	 * accessor, we generate 32 bytes of cryptographic randomness and
	 * re-set the secret to derive a deterministic key pair.  This is
	 * the same approach used by Bluetooth SMP.
	 */
	get_random_bytes(private_key, ECDH_P256_KEY_SIZE);

	/* Re-set secret with the explicit private key to make the pair
	 * consistent: private_key <=> public_key.
	 */
	kfree_sensitive(buf);
	p.key = private_key;
	p.key_size = ECDH_P256_KEY_SIZE;
	buf_len = crypto_ecdh_key_len(&p);
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		err = -ENOMEM;
		goto out_req;
	}

	err = crypto_ecdh_encode_key(buf, buf_len, &p);
	if (err)
		goto out_req;

	err = crypto_kpp_set_secret(tfm, buf, buf_len);
	if (err)
		goto out_req;

	/* Re-generate public key from the explicit private key */
	sg_init_one(&dst, tmp, ECDH_P256_PUB_SIZE);
	kpp_request_set_input(req, NULL, 0);
	kpp_request_set_output(req, &dst, ECDH_P256_PUB_SIZE);

	err = crypto_kpp_generate_public_key(req);
	err = crypto_wait_req(err, &wait);
	if (err)
		goto out_req;

	memcpy(public_key, tmp, ECDH_P256_PUB_SIZE);

out_req:
	kpp_request_free(req);
out_tmp:
	kfree(tmp);
out_buf:
	kfree_sensitive(buf);
out_tfm:
	crypto_free_kpp(tfm);
	return err;
}

/*
 * sle_ecdh_shared_secret - Compute ECDH-P256 shared secret.
 * @private_key:        Local 32-byte private key.
 * @remote_public_key:  Remote 64-byte public key (X || Y).
 * @secret:             Output buffer for 32-byte shared secret.
 *
 * Computes the ECDH shared secret using the local private key and the
 * remote peer's public key on NIST P-256.
 *
 * Returns 0 on success, negative errno on failure.
 */
int sle_ecdh_shared_secret(const u8 *private_key,
			   const u8 *remote_public_key, u8 *secret)
{
	struct crypto_kpp *tfm;
	struct kpp_request *req;
	struct ecdh p = {0};
	struct scatterlist src, dst;
	DECLARE_CRYPTO_WAIT(wait);
	u8 *buf;
	unsigned int buf_len;
	int err;

	tfm = crypto_alloc_kpp("ecdh-nist-p256", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	/* Set the local private key */
	p.key = (char *)private_key;
	p.key_size = ECDH_P256_KEY_SIZE;
	buf_len = crypto_ecdh_key_len(&p);
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		err = -ENOMEM;
		goto out_tfm;
	}

	err = crypto_ecdh_encode_key(buf, buf_len, &p);
	if (err)
		goto out_buf;

	err = crypto_kpp_set_secret(tfm, buf, buf_len);
	if (err)
		goto out_buf;

	req = kpp_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		err = -ENOMEM;
		goto out_buf;
	}

	sg_init_one(&src, remote_public_key, ECDH_P256_PUB_SIZE);
	sg_init_one(&dst, secret, ECDH_P256_KEY_SIZE);
	kpp_request_set_input(req, &src, ECDH_P256_PUB_SIZE);
	kpp_request_set_output(req, &dst, ECDH_P256_KEY_SIZE);
	kpp_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				 crypto_req_done, &wait);

	err = crypto_kpp_compute_shared_secret(req);
	err = crypto_wait_req(err, &wait);

	kpp_request_free(req);
out_buf:
	kfree_sensitive(buf);
out_tfm:
	crypto_free_kpp(tfm);
	return err;
}

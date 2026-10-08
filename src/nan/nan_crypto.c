/*
 * Wi-Fi Aware - NAN Data link cryptography functions
 * Copyright (C) 2025 Intel Corporation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include "utils/common.h"
#include "common/ieee802_11_common.h"
#include "crypto/sha256.h"
#include "crypto/sha384.h"
#include "crypto/crypto.h"
#include "crypto/aes_wrap.h"
#include "common/sae.h"
#include "nan_i.h"

#define NAN_KCK_MAX_LEN 24
#define NAN_KEK_MAX_LEN 32
#define NAN_TK_MAX_LEN  32

#define NAN_PTK_LABEL       "NAN Pairwise key expansion"
#define NAN_PMKID_LABEL     "NAN PMK Name"

/* NAN ciphers use only SHA-256 and SHA-384, and SHA-384 has a bigger digest */
#define MAX_MAC_LEN SHA384_MAC_LEN


static size_t nan_crypto_cipher_kck_len(enum nan_cipher_suite_id cipher)
{
	switch (cipher) {
	case NAN_CS_SK_CCM_128:
	case NAN_CS_PK_PASN_128:
		return 16;
	case NAN_CS_SK_GCM_256:
	case NAN_CS_PK_PASN_256:
		return 24;
	default:
		return 0;
	}
}


static size_t nan_crypto_cipher_kek_len(enum nan_cipher_suite_id cipher)
{
	switch (cipher) {
	case NAN_CS_SK_CCM_128:
	case NAN_CS_PK_PASN_128:
		return 16;
	case NAN_CS_SK_GCM_256:
	case NAN_CS_PK_PASN_256:
		return 32;
	default:
		return 0;
	}
}


static size_t nan_cipher_key_len(enum nan_cipher_suite_id cipher)
{
	switch (cipher) {
	case NAN_CS_SK_CCM_128:
	case NAN_CS_PK_PASN_128:
		return 16;
	case NAN_CS_SK_GCM_256:
	case NAN_CS_PK_PASN_256:
		return 32;
	default:
		return 0;
	}
}


static int nan_crypto_sha256(const u8 *plaintext, size_t psize, u8 *output)
{
	const u8 *addrs[1];
	size_t lens[1];

	addrs[0] = plaintext;
	lens[0] = psize;

	return sha256_vector(1, addrs, lens, output);
}


static int nan_crypto_sha384(const u8 *plaintext, size_t psize, u8 *output)
{
	const u8 *addrs[1];
	size_t lens[1];

	addrs[0] = plaintext;
	lens[0] = psize;

	return sha384_vector(1, addrs,  lens, output);
}


/**
 * nan_crypto_pmk_to_ptk - Calculate PTK from PMK, addresses, and nonces
 * @pmk: Pairwise master key
 * @iaddr: Initiator address
 * @raddr: Remote address
 * @inonce: Initiator nonce
 * @rnonce: Remote nonce
 * @ptk: Buffer for Pairwise Transient Key
 * @cipher: Negotiated pairwise cipher
 * returns: 0 on success, negative value of failure
 */
int nan_crypto_pmk_to_ptk(const u8 *pmk, const u8 *iaddr, const u8 *raddr,
			  const u8 *inonce, const u8 *rnonce,
			  struct nan_ptk *ptk,
			  enum nan_cipher_suite_id cipher)
{
	u8 data[2 * ETH_ALEN + 2 * WPA_NONCE_LEN];
	u8 tmp[NAN_KCK_MAX_LEN + NAN_KEK_MAX_LEN + NAN_TK_MAX_LEN];
	size_t ptk_len;
	int ret;

	if (!NAN_CS_IS_VALID_NDP(cipher))
		return -1;

	if (!ptk)
		return -1;

	os_memcpy(data, iaddr, ETH_ALEN);
	os_memcpy(data + ETH_ALEN, raddr, ETH_ALEN);
	os_memcpy(data + 2 * ETH_ALEN, inonce, WPA_NONCE_LEN);
	os_memcpy(data + 2 * ETH_ALEN + WPA_NONCE_LEN, rnonce,
		  WPA_NONCE_LEN);

	ptk->kck_len = nan_crypto_cipher_kck_len(cipher);
	ptk->kek_len = nan_crypto_cipher_kek_len(cipher);
	ptk->tk_len = nan_cipher_key_len(cipher);
	ptk_len = ptk->kck_len + ptk->kek_len + ptk->tk_len;

	if (NAN_CS_IS_128(cipher))
		ret = sha256_prf(pmk, PMK_LEN, NAN_PTK_LABEL, data,
				 sizeof(data), tmp, ptk_len);
	else
		ret = sha384_prf(pmk, PMK_LEN, NAN_PTK_LABEL, data,
				 sizeof(data), tmp, ptk_len);
	if (ret)
		goto out;

	wpa_hexdump_key(MSG_DEBUG, "NAN: PMK", pmk, PMK_LEN);
	wpa_hexdump_key(MSG_DEBUG, "NAN: iaddr", iaddr, ETH_ALEN);
	wpa_hexdump_key(MSG_DEBUG, "NAN: raddr", raddr, ETH_ALEN);
	wpa_hexdump_key(MSG_DEBUG, "NAN: inonce", inonce, WPA_NONCE_LEN);
	wpa_hexdump_key(MSG_DEBUG, "NAN: rnonce", rnonce, WPA_NONCE_LEN);
	wpa_hexdump_key(MSG_DEBUG, "NAN: PTK", tmp, ptk_len);

	os_memcpy(ptk->kck, tmp, ptk->kck_len);
	wpa_hexdump_key(MSG_DEBUG, "NAN: KCK", ptk->kck, ptk->kck_len);

	os_memcpy(ptk->kek, tmp + ptk->kck_len, ptk->kek_len);
	wpa_hexdump_key(MSG_DEBUG, "NAN: KEK", ptk->kek, ptk->kek_len);

	os_memcpy(ptk->tk, tmp + ptk->kck_len + ptk->kek_len, ptk->tk_len);
	wpa_hexdump_key(MSG_DEBUG, "NAN: TK", ptk->tk, ptk->tk_len);

out:
	forced_memzero(data, sizeof(data));
	forced_memzero(tmp, sizeof(tmp));
	return ret;
}


/*
 * nan_crypto_calc_pmkid - Calculate a NAN PMKID
 * @pmk: Pairwise Master Key
 * @iaddr: Initiator address
 * @raddr: Remote address
 * @serv_id: ID of the service providing the PMK
 * @cipher: Negotiated pairwise cipher
 * @pmkid: Buffer to hold the pmkid
 * Returns: 0 on success, negative value of failure
 */
int nan_crypto_calc_pmkid(const u8 *pmk, const u8 *iaddr, const u8 *raddr,
			  const u8 *serv_id,
			  enum nan_cipher_suite_id cipher, u8 *pmkid)
{
	u8 data[sizeof(NAN_PMKID_LABEL) - 1 + 2 * ETH_ALEN +
		NAN_SERVICE_ID_LEN];
	u8 digest[MAX_MAC_LEN];
	int ret;

	os_memset(data, 0, sizeof(data));
	os_memset(digest, 0, sizeof(digest));

	if (!NAN_CS_IS_VALID_NDP(cipher))
		return -1;

	if (!serv_id || is_zero_ether_addr(serv_id))
		return -1;

	os_memcpy(data, NAN_PMKID_LABEL, sizeof(NAN_PMKID_LABEL) - 1);
	os_memcpy(data + sizeof(NAN_PMKID_LABEL) - 1, iaddr, ETH_ALEN);
	os_memcpy(data + sizeof(NAN_PMKID_LABEL) - 1 + ETH_ALEN, raddr,
		  ETH_ALEN);
	os_memcpy(data + sizeof(NAN_PMKID_LABEL) - 1 + 2 * ETH_ALEN, serv_id,
		  NAN_SERVICE_ID_LEN);

	wpa_hexdump_key(MSG_DEBUG, "NAN: PMKID data", data, sizeof(data));

	if (NAN_CS_IS_128(cipher))
		ret = hmac_sha256(pmk, PMK_LEN, data, sizeof(data), digest);
	else
		ret = hmac_sha384(pmk, PMK_LEN, data, sizeof(data), digest);
	if (ret)
		goto out;

	os_memcpy(pmkid, digest, PMKID_LEN);
	wpa_hexdump_key(MSG_DEBUG, "NAN: PMKID", pmkid, PMKID_LEN);

out:
	forced_memzero(digest, sizeof(digest));
	return ret;
}


/**
 * nan_crypto_calc_auth_token - Calculate authentication token
 * @buf: Buffer on which to calculate the authentication token
 * @len: Length of &buf in octets
 * @cipher: Negotiated NAN cipher
 * @token: Buffer to hold the token (NAN_AUTH_TOKEN_LEN octets)
 * Returns: 0 on success, and a negative error value on failure.
 */
int nan_crypto_calc_auth_token(enum nan_cipher_suite_id cipher,
			       const u8 *buf, size_t len, u8 *token)
{
	u8 hash[MAX_MAC_LEN];
	int ret;

	if (!NAN_CS_IS_VALID_NDP(cipher))
		return -1;

	if (NAN_CS_IS_128(cipher))
		ret = nan_crypto_sha256(buf, len, hash);
	else
		ret = nan_crypto_sha384(buf, len, hash);
	if (ret)
		return ret;

	os_memcpy(token, hash, NAN_AUTH_TOKEN_LEN);
	wpa_hexdump_key(MSG_DEBUG, "NAN: AUTH_TOKEN_DATA", buf, len);
	wpa_hexdump_key(MSG_DEBUG, "NAN: AUTH TOKEN", token,
			NAN_AUTH_TOKEN_LEN);

	forced_memzero(hash, sizeof(hash));

	return ret;
}


/*
 * nan_crypto_key_mic - Calculate MIC over the given buffer
 * @buf: Buffer on which to calculate the MIC
 * @len: Length of &buf
 * @kck: Key Confirmation Key
 * @kck_len: Length of &kck
 * @cipher: Cipher suite identifier.
 * @mic: On successful return, would hold the MIC.
 * Return: 0 on success, and a negative error value on failure.
 */
int nan_crypto_key_mic(const u8 *buf, size_t len, const u8 *kck,
		       size_t kck_len, u8 cipher, u8 *mic)
{
	u8 digest[MAX_MAC_LEN];
	u8 mic_len;
	int ret;

	os_memset(digest, 0, sizeof(digest));

	if (!NAN_CS_IS_VALID_NDP(cipher))
		return -1;

	wpa_hexdump_key(MSG_DEBUG, "NAN: MIC data", buf, len);
	wpa_hexdump_key(MSG_DEBUG, "NAN: KCK", kck, kck_len);

	if (NAN_CS_IS_128(cipher)) {
		mic_len = NAN_KEY_MIC_LEN;
		ret = hmac_sha256(kck, kck_len, buf, len, digest);
	} else {
		mic_len = NAN_KEY_MIC_24_LEN;
		ret = hmac_sha384(kck, kck_len, buf, len, digest);
	}
	if (ret)
		return ret;

	os_memcpy(mic, digest, mic_len);
	forced_memzero(digest, sizeof(digest));

	wpa_hexdump_key(MSG_DEBUG, "NAN: MIC", mic, mic_len);
	return 0;
}


int nan_crypto_derive_nd_pmk(const char *pwd, const u8 *service_id,
			     enum nan_cipher_suite_id csid,
			     const u8 *peer_nmi, u8 *nd_pmk)
{
	u8 salt[1 + 1 + NAN_SERVICE_ID_LEN + ETH_ALEN];

	salt[0] = 0;
	salt[1] = (u8) csid;
	os_memcpy(salt + 2, service_id, NAN_SERVICE_ID_LEN);
	os_memcpy(salt + 2 + NAN_SERVICE_ID_LEN, peer_nmi, ETH_ALEN);

	switch (csid) {
	case NAN_CS_SK_CCM_128:
	case NAN_CS_PK_PASN_128:
		return pbkdf2_sha256(pwd, salt, sizeof(salt), 4096, nd_pmk, 32);
	case NAN_CS_SK_GCM_256:
	case NAN_CS_PK_PASN_256:
		return pbkdf2_sha384(pwd, salt, sizeof(salt), 4096, nd_pmk, 32);
	default:
		return -1;
	}
}


/**
 * nan_crypto_derive_nira_tag - Derive NIRA tag
 * @nik: NAN Identity Key
 * @nik_len: Length of &nik in bytes
 * @nmi_addr: NAN Management Interface address (6 bytes)
 * @nira_nonce: NIRA nonce (8 bytes)
 * Returns: wpabuf containing the derived tag (8 bytes) or %NULL on failure
 *
 * Derives a NIRA tag for cipher version 0 using HMAC-SHA-256:
 * Tag = Truncate-64(HMAC-SHA-256(NIK, "NIR" || NMI Address || Nonce))
 * The caller is responsible for freeing the returned wpabuf using
 * wpabuf_free().
 */
struct wpabuf * nan_crypto_derive_nira_tag(const u8 *nik, size_t nik_len,
					   const u8 *nmi_addr,
					   const u8 *nira_nonce)
{
	u8 data[NAN_NIRA_STR_LEN + ETH_ALEN + NAN_NIRA_NONCE_LEN];
	u8 tag[SHA256_MAC_LEN];
	struct wpabuf *tag_buf;

	if (!nik || nik_len != NAN_NIK_LEN) {
		wpa_printf(MSG_INFO,
			   "NAN: Invalid NIK for tag derivation (len=%zu)",
			   nik ? nik_len : 0);
		return NULL;
	}

	if (!nmi_addr || !nira_nonce) {
		wpa_printf(MSG_INFO,
			   "NAN: Invalid parameters for tag derivation");
		return NULL;
	}

	/* Tag = Truncate-64(HMAC-SHA-256(NIK, “NIR”, NMI || Nonce)) */

	/* Construct data: "NIR" || NMI Address || Nonce */
	os_memcpy(data, NAN_NIRA_STR, NAN_NIRA_STR_LEN);
	os_memcpy(&data[NAN_NIRA_STR_LEN], nmi_addr, ETH_ALEN);
	os_memcpy(&data[NAN_NIRA_STR_LEN + ETH_ALEN], nira_nonce,
		  NAN_NIRA_NONCE_LEN);

	/* Compute HMAC-SHA-256(NIK, data) */
	if (hmac_sha256(nik, NAN_NIK_LEN, data, sizeof(data), tag) < 0) {
		wpa_printf(MSG_INFO, "NAN: Failed to compute HMAC for tag");
		return NULL;
	}

	tag_buf = wpabuf_alloc_copy(tag, NAN_NIRA_TAG_LEN);
	if (!tag_buf)
		wpa_printf(MSG_INFO, "NAN: Failed to allocate tag buffer");
	else
		wpa_hexdump(MSG_DEBUG, "NAN: Derived NIRA tag",
			    wpabuf_head(tag_buf), wpabuf_len(tag_buf));

	forced_memzero(tag, sizeof(tag));
	return tag_buf;
}


/**
 * nan_crypto_derive_from_kdk - Derive a key from KDK using KDF-HASH-NNN
 * @kdk: Key Derivation Key
 * @kdk_len: Length of KDK in bytes
 * @cipher: Cipher suite identifier (NAN_CS_PK_PASN_128 or NAN_CS_PK_PASN_256)
 * @label: Label string for the key derivation
 * @initiator_nmi: Pairing Initiator NMI address (6 bytes)
 * @responder_nmi: Pairing Responder NMI address (6 bytes)
 * @key: Buffer for the derived key
 * @key_len: number of bytes to derive
 * Returns: 0 on success, -1 on failure
 *
 * Generic function to derive a key from KDK using:
 * KEY = KDF-HASH-NNN(KDK, label, Initiator NMI || Responder NMI)
 */
static int nan_crypto_derive_from_kdk(const u8 *kdk, size_t kdk_len,
				      enum nan_cipher_suite_id cipher,
				      const char *label,
				      const u8 *initiator_nmi,
				      const u8 *responder_nmi,
				      u8 *key, size_t key_len)
{
	u8 data[ETH_ALEN * 2];
	int ret = 0;

	if (!kdk || !kdk_len || !label || !initiator_nmi || !responder_nmi ||
	    !key || !key_len) {
		wpa_printf(MSG_INFO,
			   "NAN: Invalid parameters for NPK/KEK derivation");
		return -1;
	}

	/* Concatenate: Pairing Initiator NMI || Pairing Responder NMI */
	os_memcpy(data, initiator_nmi, ETH_ALEN);
	os_memcpy(data + ETH_ALEN, responder_nmi, ETH_ALEN);

	if (cipher == NAN_CS_PK_PASN_128) {
		ret = sha256_prf(kdk, kdk_len, label, data, sizeof(data), key,
				 key_len);
	} else if (cipher == NAN_CS_PK_PASN_256) {
		ret = sha384_prf(kdk, kdk_len, label, data, sizeof(data), key,
				 key_len);
	} else {
		wpa_printf(MSG_INFO,
			   "NAN: Unsupported cipher suite for key derivation: %d",
			   cipher);
		return -1;
	}

	if (ret) {
		wpa_printf(MSG_INFO,
			   "NAN: NPK/KEK derivation failed (ret=%d)", ret);
		return ret;
	}

	wpa_hexdump_key(MSG_DEBUG, "NAN: KDK", kdk, kdk_len);
	wpa_printf(MSG_DEBUG, "NAN: Label: %s", label);
	wpa_printf(MSG_DEBUG, "NAN: Initiator NMI " MACSTR,
		   MAC2STR(initiator_nmi));
	wpa_printf(MSG_DEBUG, "NAN: Responder NMI " MACSTR,
		   MAC2STR(responder_nmi));
	wpa_hexdump_key(MSG_DEBUG, "NAN: Derived key", key, key_len);

	return 0;
}


/**
 * nan_crypto_derive_npk - Derive NPK from NM-KDK for opportunistic pairing
 * @kdk: NM-KDK (NAN Master Key Derivation Key)
 * @kdk_len: Length of KDK in bytes
 * @cipher: Cipher suite identifier (NAN_CS_PK_PASN_128 or NAN_CS_PK_PASN_256)
 * @initiator_nmi: Pairing Initiator NMI address (6 bytes)
 * @responder_nmi: Pairing Responder NMI address (6 bytes)
 * @buf: Buffer for the derived NPK
 * @buf_len: Length of the buffer  (must be 32 bytes)
 * Returns: 0 on success, -1 on failure
 *
 * NPK = KDF-HASH-256(NM-KDK, "NAN Opportunistic NPK Derivation",
 *                    Pairing Initiator NMI || Pairing Responder NMI)
 *
 * Note: It is unclear whether KDF-HASH-256 means that SHA-256 must be used as
 * the hash algorithm, or the hash algorithm is determined by the cipher suite.
 * Usually, NCS-PK-PASN-128 cipher comes with SHA-256 and NCS-PK-PASN-256 with
 * SHA-384 as defined in Wi-Fi Aware Specification v4.0, section 7.1.2. But for
 * opportunistic pairing, section 7.6.4.3 specifies KDF-HASH-256 only for NPK
 * derivation. Does this mean that SHA-256 must be used? In IEEE 802.11-2024,
 * 12.13.8, where KDF-HASH-NNN is defined, NNN is the number of bits to derive,
 * not the hash function. Therefore, we follow the latter interpretation and use
 * the hash function corresponding to the cipher suite.
 */
int nan_crypto_derive_npk(const u8 *kdk, size_t kdk_len,
			  enum nan_cipher_suite_id cipher,
			  const u8 *initiator_nmi, const u8 *responder_nmi,
			  u8 *buf, size_t buf_len)
{
	const char *label = "NAN Opportunistic NPK Derivation";

	wpa_printf(MSG_DEBUG, "NAN: Deriving NPK from NM-KDK");

	if (buf_len < NAN_NPK_LEN) {
		wpa_printf(MSG_INFO, "NAN: NPK buffer too small: %zu bytes",
			   buf_len);
		return -1;
	}

	return nan_crypto_derive_from_kdk(kdk, kdk_len, cipher, label,
					  initiator_nmi, responder_nmi,
					  buf, buf_len);
}


/**
 * nan_crypto_derive_kek - Derive KEK from NM-KDK
 * @kdk: NM-KDK (NAN Master Key Derivation Key)
 * @kdk_len: Length of KDK in bytes
 * @cipher: Cipher suite identifier (NAN_CS_PK_PASN_128 or NAN_CS_PK_PASN_256)
 * @initiator_nmi: Pairing Initiator NMI address (6 bytes)
 * @responder_nmi: Pairing Responder NMI address (6 bytes)
 * @ptk: Buffer for the derived KEK
 * Returns: 0 on success, -1 on failure
 *
 * NM-KEK = KDF-HASH-MMM(NM-KDK, "NAN Management KEK Derivation",
 *                       Pairing Initiator NMI || Pairing Responder NMI)
 */
int nan_crypto_derive_kek(const u8 *kdk, size_t kdk_len,
			  enum nan_cipher_suite_id cipher,
			  const u8 *initiator_nmi, const u8 *responder_nmi,
			  struct wpa_ptk *ptk)
{
	const char *label = "NAN Management KEK Derivation";

	wpa_printf(MSG_DEBUG, "NAN: Deriving KEK from NM-KDK");

	if (cipher != NAN_CS_PK_PASN_128 &&
	    cipher != NAN_CS_PK_PASN_256) {
		wpa_printf(MSG_INFO,
			   "NAN: Unsupported cipher suite for KEK derivation: %d",
			   cipher);
		return -1;
	}

	ptk->kek_len = nan_crypto_cipher_kek_len(cipher);

	return nan_crypto_derive_from_kdk(kdk, kdk_len, cipher, label,
					  initiator_nmi, responder_nmi,
					  ptk->kek, ptk->kek_len);
}


/**
 * nan_crypto_derive_nd_pmk_from_kdk - Derive ND-PMK from NM-KDK
 * @kdk: NM-KDK (NAN Master Key Derivation Key)
 * @kdk_len: Length of KDK in bytes
 * @cipher: Cipher suite identifier (NAN_CS_PK_PASN_128 or NAN_CS_PK_PASN_256)
 * @initiator_nmi: Pairing Initiator NMI address (6 bytes)
 * @responder_nmi: Pairing Responder NMI address (6 bytes)
 * @nd_pmk: Buffer for the derived ND-PMK (must be 32 bytes)
 * Returns: 0 on success, -1 on failure
 *
 * ND-PMK = KDF-HASH-256(NM-KDK, "NDP PMK Derivation",
 *                       Pairing Initiator NMI || Pairing Responder NMI)
 */
int nan_crypto_derive_nd_pmk_from_kdk(const u8 *kdk, size_t kdk_len,
				      enum nan_cipher_suite_id cipher,
				      const u8 *initiator_nmi,
				      const u8 *responder_nmi, u8 *nd_pmk)
{
	const char *label = "NDP PMK Derivation";

	wpa_printf(MSG_DEBUG, "NAN: Deriving ND-PMK from NM-KDK");

	/* ND-PMK always uses SHA-256, resulting in 32 bytes */
	return nan_crypto_derive_from_kdk(kdk, kdk_len, cipher, label,
					  initiator_nmi, responder_nmi, nd_pmk,
					  PMK_LEN);
}


/**
 * nan_crypto_encrypt_key - Encrypt key data using AES Key Wrap (RFC 3394)
 * @key_data: Key data to be encrypted
 * @kek: Key Encryption Key (KEK)
 * @kek_len: Length of KEK in octets
 * Returns: Encrypted key data in a newly allocated wpabuf, or NULL on failure.
 *
 * This function encrypts the provided key data using AES Key Wrap algorithm
 * as defined in RFC 3394. The input data is padded to 8-byte alignment before
 * encryption. The padding scheme uses 0xdd as the first padding byte followed
 * by zeros.
 *
 * The caller is responsible for freeing the returned wpabuf.
 */
struct wpabuf * nan_crypto_encrypt_key_data(const struct wpabuf *key_data,
					    const u8 *kek, size_t kek_len)
{
	size_t key_data_len;
	size_t pad;
	size_t padded_len;
	u8 *padded_key_data;
	struct wpabuf *encrypted_key_data;

	if (!key_data || !kek || !kek_len) {
		wpa_printf(MSG_INFO,
			   "NAN: Pairing: Invalid parameters for key data encryption");
		return NULL;
	}

	key_data_len = wpabuf_len(key_data);
	if (!key_data_len) {
		wpa_printf(MSG_INFO,
			   "NAN: Pairing: Key data is empty for encryption");
		return NULL;
	}

	wpa_hexdump_key(MSG_DEBUG, "NAN: Plain key data", wpabuf_head(key_data),
			key_data_len);

	/* Calculate padding to align to 8 bytes (AES block size) */
	pad = key_data_len % 8;
	if (pad)
		pad = 8 - pad;

	padded_len = key_data_len + pad;
	padded_key_data = os_zalloc(padded_len);
	if (!padded_key_data)
		return NULL;

	/* Copy key data and apply padding (0xdd followed by zeros) */
	os_memcpy(padded_key_data, wpabuf_head(key_data), key_data_len);
	if (pad)
		padded_key_data[key_data_len] = 0xdd;

	/* Allocate buffer for encrypted data (input length + 8 bytes for IV) */
	encrypted_key_data = wpabuf_alloc(padded_len + 8);
	if (!encrypted_key_data)
		goto fail;

	/* Encrypt the padded data using AES Key Wrap */
	if (aes_wrap(kek, kek_len, padded_len / 8, padded_key_data,
		     wpabuf_put(encrypted_key_data, padded_len + 8))) {
		wpa_printf(MSG_INFO, "NAN: Pairing: AES wrap failed");
		wpabuf_free(encrypted_key_data);
		encrypted_key_data = NULL;
	} else {
		wpa_hexdump(MSG_DEBUG, "NAN: Encrypted key data",
			    wpabuf_head(encrypted_key_data),
			    wpabuf_len(encrypted_key_data));
	}

fail:
	bin_clear_free(padded_key_data, padded_len);
	return encrypted_key_data;
}


/**
 * nan_crypto_decrypt_key_data - Decrypt NAN key data using AES-UNWRAP
 * @kek: Key Encryption Key
 * @kek_len: KEK length in bytes
 * @encrypted_data: Encrypted key data to decrypt
 * @encrypted_len: Length of encrypted data in bytes
 * Returns: wpabuf containing decrypted data or %NULL on failure
 *
 * This function decrypts NAN key data that was encrypted using AES-WRAP.
 * The encrypted data must be at least 16 bytes and a multiple of 8 bytes
 * (AES-WRAP requirement). The caller is responsible for freeing the returned
 * wpabuf using wpabuf_free().
 */
struct wpabuf * nan_crypto_decrypt_key_data(const u8 *kek, size_t kek_len,
					    const u8 *encrypted_data,
					    size_t encrypted_len)
{
	struct wpabuf *decrypted;
	size_t plain_len;
	u8 *buf;

	if (!encrypted_data || !encrypted_len) {
		wpa_printf(MSG_INFO, "NAN: Invalid encrypted key data");
		return NULL;
	}

	wpa_hexdump_key(MSG_DEBUG, "NAN: Encrypted key data",
			encrypted_data, encrypted_len);

	if (!kek || !kek_len) {
		wpa_printf(MSG_INFO,
			   "NAN: No KEK available for key data decryption");
		return NULL;
	}

	wpa_hexdump_key(MSG_DEBUG, "NAN: KEK for decryption", kek, kek_len);

	/* AES-WRAP adds 8 bytes overhead */
	if (encrypted_len < 16 || encrypted_len % 8 != 0) {
		wpa_printf(MSG_INFO,
			   "NAN: Invalid encrypted key data length %zu",
			   encrypted_len);
		return NULL;
	}

	plain_len = encrypted_len - 8;
	decrypted = wpabuf_alloc(plain_len);
	if (!decrypted) {
		wpa_printf(MSG_INFO,
			   "NAN: Failed to allocate decryption buffer");
		return NULL;
	}

	buf = wpabuf_put(decrypted, plain_len);
	if (aes_unwrap(kek, kek_len, plain_len / 8, encrypted_data, buf)) {
		wpa_printf(MSG_INFO,
			   "NAN: AES unwrap failed - could not decrypt key data");
		wpabuf_free(decrypted);
		return NULL;
	}

	wpa_hexdump_key(MSG_DEBUG, "NAN: Decrypted key data",
			wpabuf_head(decrypted), wpabuf_len(decrypted));

	return decrypted;
}


/**
 * nan_crypto_clear_pmkid_list - Clear and free all entries in a PMKID list
 * @pmkid_list: List of PMKIDs to clear
 *
 * This function removes and frees all PMKID entries from the provided list.
 */
void nan_crypto_clear_pmkid_list(struct dl_list *pmkid_list)
{
	struct nan_de_pmkid *p, *n;

	dl_list_for_each_safe(p, n, pmkid_list, struct nan_de_pmkid, list) {
		dl_list_del(&p->list);
		os_free(p);
	}
}


/**
 * nan_crypto_pmkid_list - Generate PMKIDs for multiple cipher suites
 * @pmkid_list: List to which the generated PMKIDs are appended
 * @raddr: Responder MAC address
 * @srv_id: Service ID (6 bytes)
 * @cipher_suites: Array of cipher suite identifiers (int_array)
 * @pmk: PMK for which the PMKIDs are generated
 * Returns: 0 on success, -1 on failure
 *
 * This function generates a PMKID for each NDP cipher suite in the provided
 * array and adds them to the pmkid_list. Cipher suites that are not used for
 * an ND-TKSA, e.g., the NCS-GTK-* suites, have no ND-PMK and are skipped.
 */
int nan_crypto_pmkid_list(struct dl_list *pmkid_list, const u8 *raddr,
			  const u8 *srv_id, const int *cipher_suites,
			  const u8 *pmk)
{
	size_t cs_num = int_array_len(cipher_suites);
	size_t i;

	if (!cs_num || !pmk)
		return 0;

	for (i = 0; i < cs_num; i++) {
		struct nan_de_pmkid *p;
		int ret;
		static const u8 iaddr[ETH_ALEN] = {
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff
		};
		enum nan_cipher_suite_id csid =
			(enum nan_cipher_suite_id) cipher_suites[i];

		if (!NAN_CS_IS_VALID_NDP(csid))
			continue;

		p = os_zalloc(sizeof(*p));
		if (!p)
			return -1;

		ret = nan_crypto_calc_pmkid(pmk, iaddr, raddr, srv_id, csid,
					    p->pmkid);
		if (ret < 0) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Failed to derive PMKID for cipher suite %d",
				   cipher_suites[i]);
			os_free(p);
			nan_crypto_clear_pmkid_list(pmkid_list);
			return ret;
		}

		dl_list_add(pmkid_list, &p->list);
	}

	return 0;
}


/*
 * Based on the SipHash reference C implementation by Jean-Philippe
 * Aumasson and Daniel J. Bernstein:
 * https://github.com/veorq/SipHash
 *
 * The reference implementation is dedicated to the public domain under
 * the CC0 Public Domain Dedication. This version is adapted to hostap.git
 * interfaces and computes the 64-bit SipHash-2-4 output.
 */

/* SipHash round function */
#define SIPROUND do { \
	v0 += v1; v1 = ROTL64(v1, 13); v1 ^= v0; v0 = ROTL64(v0, 32); \
	v2 += v3; v3 = ROTL64(v3, 16); v3 ^= v2; \
	v0 += v3; v3 = ROTL64(v3, 21); v3 ^= v0; \
	v2 += v1; v1 = ROTL64(v1, 17); v1 ^= v2; v2 = ROTL64(v2, 32); \
} while (0)

/* Rotate left for 64-bit values */
#define ROTL64(x, b) ((u64) (((x) << (b)) | ((x) >> (64 - (b)))))

#define SIPHASH_TAG_LEN 8

/**
 * siphash_2_4 - SipHash-2-4 pseudorandom function
 * @key: 128-bit (16-byte) secret key
 * @data: Input data to be hashed
 * @data_len: Length of the input data in bytes
 * @tag: Buffer for the output tag (8 bytes)
 * Returns: 0 on success, -1 on failure
 *
 * This function computes the SipHash-2-4 tag for the given data using
 * the provided key. SipHash-2-4 uses 2 compression rounds (c=2) and
 * 4 finalization rounds (d=4).
 */
int siphash_2_4(const u8 *key, const u8 *data, size_t data_len, u8 *tag)
{
	u64 v0, v1, v2, v3;
	u64 k0, k1;
	u64 m;
	size_t i;
	const u8 *end;
	int left;
	u64 b;

	if (!key || !tag || (data_len > 0 && !data))
		return -1;

	/* Load 128-bit key as two 64-bit little-endian values */
	k0 = WPA_GET_LE64(key);
	k1 = WPA_GET_LE64(key + 8);

	/* Initialize state with key and constants */
	v0 = k0 ^ 0x736f6d6570736575ULL;
	v1 = k1 ^ 0x646f72616e646f6dULL;
	v2 = k0 ^ 0x6c7967656e657261ULL;
	v3 = k1 ^ 0x7465646279746573ULL;

	/* Process full 8-byte blocks */
	end = data + (data_len - (data_len % 8));
	for (i = 0; i < data_len / 8; i++) {
		m = WPA_GET_LE64(data + i * 8);
		v3 ^= m;

		/* Compression rounds (c=2) */
		SIPROUND;
		SIPROUND;

		v0 ^= m;
	}

	/* Process remaining bytes and add length */
	left = data_len & 7;
	b = ((u64) data_len) << 56;

	switch (left) {
	case 7:
		b |= ((u64) end[6]) << 48;
		__attribute__((__fallthrough__));
	case 6:
		b |= ((u64) end[5]) << 40;
		__attribute__((__fallthrough__));
	case 5:
		b |= ((u64) end[4]) << 32;
		__attribute__((__fallthrough__));
	case 4:
		b |= ((u64) end[3]) << 24;
		__attribute__((__fallthrough__));
	case 3:
		b |= ((u64) end[2]) << 16;
		__attribute__((__fallthrough__));
	case 2:
		b |= ((u64) end[1]) << 8;
		__attribute__((__fallthrough__));
	case 1:
		b |= ((u64) end[0]);
		break;
	case 0:
		break;
	}

	v3 ^= b;

	/* Compression rounds (c=2) */
	SIPROUND;
	SIPROUND;

	v0 ^= b;

	/* Finalization */
	v2 ^= 0xff;

	/* Finalization rounds (d=4) */
	SIPROUND;
	SIPROUND;
	SIPROUND;
	SIPROUND;

	/* Compute output tag */
	b = v0 ^ v1 ^ v2 ^ v3;
	WPA_PUT_LE64(tag, b);

	return 0;
}


struct wpabuf * nan_crypto_derive_irsa_tag(const u8 *nik, size_t nik_len,
					  const u8 *nmi_addr,
					  const u8 *irsa_nonce)
{
	u8 data[NAN_NIRA_STR_LEN + ETH_ALEN + NAN_NIRA_NONCE_LEN];
	u8 tag[SIPHASH_TAG_LEN];
	struct wpabuf *tag_buf;

	if (!nik || nik_len != NAN_NIK_LEN) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Invalid NIK for tag derivation (len=%zu)",
			   nik ? nik_len : 0);
		return NULL;
	}

	if (!nmi_addr || !irsa_nonce) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Invalid parameters for tag derivation");
		return NULL;
	}

	os_memcpy(data, NAN_NIRA_STR, NAN_NIRA_STR_LEN);
	os_memcpy(&data[NAN_NIRA_STR_LEN], nmi_addr, ETH_ALEN);
	os_memcpy(&data[NAN_NIRA_STR_LEN + ETH_ALEN], irsa_nonce,
		  NAN_NIRA_NONCE_LEN);

	if (siphash_2_4(nik, data, sizeof(data), tag) < 0) {
		wpa_printf(MSG_DEBUG, "NAN: Failed to compute HMAC for tag");
		return NULL;
	}

	tag_buf = wpabuf_alloc_copy(tag, NAN_NIRA_TAG_LEN);
	if (!tag_buf)
		wpa_printf(MSG_DEBUG, "NAN: Failed to allocate tag buffer");
	else
		wpa_hexdump(MSG_DEBUG, "NAN: Derived NIRA tag",
			    wpabuf_head(tag_buf), wpabuf_len(tag_buf));

	forced_memzero(tag, sizeof(tag));
	return tag_buf;
}


/*
 * DER prefix of an RFC 5480 SubjectPublicKeyInfo for a P-256 public key in
 * compressed point format:
 *   SEQUENCE {
 *     SEQUENCE {
 *       OID id-ecPublicKey (1.2.840.10045.2.1),
 *       OID secp256r1 (1.2.840.10045.3.1.7)
 *     },
 *     BIT STRING (34 octets, 0 unused bits)
 *   }
 *
 * The 33-octet compressed IPK (Wi-Fi Aware spec R5, Table 36) follows as the
 * BIT STRING value.
 */
static const u8 nan_ipk_spki_prefix[NAN_IPK_SPKI_PREFIX_LEN] = {
	0x30, 0x39,
	0x30, 0x13,
	0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
	0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
	0x03, 0x22, 0x00,
};


static struct crypto_ec_key * nan_crypto_load_ipk(const u8 *ipk)
{
	u8 spki[NAN_IPK_SPKI_PREFIX_LEN + NAN_IPK_LEN];

	os_memcpy(spki, nan_ipk_spki_prefix, NAN_IPK_SPKI_PREFIX_LEN);
	os_memcpy(spki + NAN_IPK_SPKI_PREFIX_LEN, ipk, NAN_IPK_LEN);

	return crypto_ec_key_parse_pub(spki, sizeof(spki));
}


/**
 * nan_crypto_verify_pkr_signature - Verify a PKR signature
 * @ipk: Compressed P-256 Individual Public Key
 * @data: Record after the Length field up to the Record Signature
 * @data_len: Length of @data
 * @sig: DER-encoded ECDSA Record Signature
 * @sig_len: Length of @sig
 *
 * The record data covers the fields after Length and excludes Record
 * Signature, as specified by Wi-Fi Aware spec R5, Table 34.
 *
 * Returns: 0 if the signature is valid, -1 otherwise
 */
int nan_crypto_verify_pkr_signature(const u8 *ipk,
				    const u8 *data, size_t data_len,
				    const u8 *sig, size_t sig_len)
{
	struct crypto_ec_key *key = NULL;
	u8 digest[SHA256_MAC_LEN];
	int ret = -1;

	if (!ipk || !data || !data_len || !sig || !sig_len) {
		wpa_printf(MSG_DEBUG,
			   "NAN: PKR signature verify: invalid parameters");
		return -1;
	}

	if (nan_crypto_sha256(data, data_len, digest) < 0) {
		wpa_printf(MSG_DEBUG,
			   "NAN: PKR signature verify: SHA-256 failed");
		goto out;
	}

	key = nan_crypto_load_ipk(ipk);
	if (!key) {
		wpa_printf(MSG_DEBUG,
			   "NAN: PKR signature verify: failed to load IPK");
		goto out;
	}

	ret = crypto_ec_key_verify_signature(key, digest, sizeof(digest), sig,
					     sig_len) == 1 ? 0 : -1;
	if (ret)
		wpa_printf(MSG_DEBUG,
			   "NAN: PKR signature verify: invalid");

out:
	crypto_ec_key_deinit(key);
	return ret;
}


/**
 * nan_crypto_sign_pkr - Generate a PKR signature
 * @isk: P-256 Individual Secret Key (NAN_ISK_LEN octets)
 * @data: Record after the Length field up to the Record Signature
 * @data_len: Length of @data
 * Returns: DER-encoded ECDSA signature or %NULL on failure
 */
struct wpabuf * nan_crypto_sign_pkr(const u8 *isk, const u8 *data,
				    size_t data_len)
{
	struct crypto_ec_key *key;
	struct wpabuf *sig = NULL;
	u8 digest[SHA256_MAC_LEN];

	if (!isk || !data || !data_len)
		return NULL;

	key = crypto_ec_key_set_priv(19, isk, NAN_ISK_LEN);
	if (!key) {
		wpa_printf(MSG_DEBUG, "NAN: PKR signature: failed to load ISK");
		return NULL;
	}

	if (nan_crypto_sha256(data, data_len, digest) == 0)
		sig = crypto_ec_key_sign(key, digest, sizeof(digest));
	if (!sig)
		wpa_printf(MSG_DEBUG, "NAN: PKR signature: signing failed");

	crypto_ec_key_deinit(key);
	return sig;
}


/**
 * nan_crypto_derive_pkbst_password - Derive the SAE password for PKBST
 * @ipk_pub: Publisher (Pairing Responder) IPK
 * @ipk_sub: Subscriber (Pairing Initiator) IPK for mutual PKBST, or %NULL
 * @initiator_nmi: Pairing Initiator NMI
 * @responder_nmi: Pairing Responder NMI
 * @password: Buffer for the NAN_PKBST_PASSWORD_LEN octet password
 * Returns: 0 on success, -1 on failure
 *
 * Wi-Fi Aware spec R5 draft v0.0.16, Table 36:
 * HKDF-Expand(HKDF-Extract(0, IPKp || [IPKs]),
 *	       "SAE Password Derivation" || Initiator NMI || Responder NMI, 32)
 */
int nan_crypto_derive_pkbst_password(const u8 *ipk_pub, const u8 *ipk_sub,
				     const u8 *initiator_nmi,
				     const u8 *responder_nmi, u8 *password)
{
	int ret;
	size_t len[2];
	const u8 *addr[2];
	u8 salt[SHA256_MAC_LEN], prk[SHA256_MAC_LEN];
	static const char label[] = "SAE Password Derivation";
	u8 info[sizeof(label) - 1 + 2 * ETH_ALEN];

	if (!ipk_pub || !initiator_nmi || !responder_nmi || !password)
		return -1;

	addr[0] = ipk_pub;
	len[0] = NAN_IPK_LEN;
	addr[1] = ipk_sub;
	len[1] = NAN_IPK_LEN;
	os_memset(salt, 0, sizeof(salt));
	if (hmac_sha256_vector(salt, sizeof(salt), ipk_sub ? 2 : 1, addr, len,
			       prk) < 0)
		return -1;

	os_memcpy(info, label, sizeof(label) - 1);
	os_memcpy(&info[sizeof(label) - 1], initiator_nmi, ETH_ALEN);
	os_memcpy(&info[sizeof(label) - 1 + ETH_ALEN], responder_nmi,
		  ETH_ALEN);

	/* With no label, hmac_sha256_kdf() is HKDF-Expand (RFC 5869) */
	ret = hmac_sha256_kdf(prk, sizeof(prk), NULL, info, sizeof(info),
			      password, NAN_PKBST_PASSWORD_LEN);
	forced_memzero(prk, sizeof(prk));
	return ret;
}


/**
 * nan_crypto_build_fkce_input - Build the PKBST identity signature input
 * @sae: SAE data after both commits have been processed
 * @ipk: IPK of the signer
 * @initiator_nmi: Pairing Initiator NMI
 * @responder_nmi: Pairing Responder NMI
 * @responder: Whether the local device is the Pairing Responder
 * Returns: Allocated buffer or %NULL on failure
 *
 * Wi-Fi Aware spec R5 draft v0.0.16, Table 36: eleResp || eleInit || scaResp ||
 * scaInit || IPK || Responder NMI || Initiator NMI. Both sides build the same
 * input for a given signer.
 */
struct wpabuf * nan_crypto_build_fkce_input(const struct sae_data *sae,
					    const u8 *ipk,
					    const u8 *initiator_nmi,
					    const u8 *responder_nmi,
					    bool responder)
{
	const struct sae_temporary_data *tmp = sae ? sae->tmp : NULL;
	const struct crypto_ec_point *ele_resp, *ele_init;
	const struct crypto_bignum *sca_resp, *sca_init;
	struct wpabuf *buf;
	size_t plen;
	u8 *pos;

	if (!tmp || !tmp->ec || !ipk || !initiator_nmi || !responder_nmi)
		return NULL;

	plen = tmp->prime_len;
	ele_resp = responder ? tmp->own_commit_element_ecc :
		tmp->peer_commit_element_ecc;
	ele_init = responder ? tmp->peer_commit_element_ecc :
		tmp->own_commit_element_ecc;
	sca_resp = responder ? tmp->own_commit_scalar :
		sae->peer_commit_scalar;
	sca_init = responder ? sae->peer_commit_scalar :
		tmp->own_commit_scalar;

	buf = wpabuf_alloc(6 * plen + NAN_IPK_LEN + 2 * ETH_ALEN);
	if (!buf)
		return NULL;

	pos = wpabuf_put(buf, 2 * plen);
	if (crypto_ec_point_to_bin(tmp->ec, ele_resp, pos, pos + plen) < 0)
		goto fail;
	pos = wpabuf_put(buf, 2 * plen);
	if (crypto_ec_point_to_bin(tmp->ec, ele_init, pos, pos + plen) < 0 ||
	    crypto_bignum_to_bin(sca_resp, wpabuf_put(buf, plen), plen,
				 plen) < 0 ||
	    crypto_bignum_to_bin(sca_init, wpabuf_put(buf, plen), plen,
				 plen) < 0)
		goto fail;
	wpabuf_put_data(buf, ipk, NAN_IPK_LEN);
	wpabuf_put_data(buf, responder_nmi, ETH_ALEN);
	wpabuf_put_data(buf, initiator_nmi, ETH_ALEN);
	return buf;

fail:
	wpabuf_free(buf);
	return NULL;
}


/**
 * nan_crypto_compute_fkce - Compute the PKBST FKCE KeyAuth
 * @isk: Individual Secret Key of the signer
 * @input: Output of nan_crypto_build_fkce_input()
 * Returns: DER-encoded ECDSA signature or %NULL on failure
 */
struct wpabuf * nan_crypto_compute_fkce(const u8 *isk,
					const struct wpabuf *input)
{
	if (!input)
		return NULL;
	return nan_crypto_sign_pkr(isk, wpabuf_head(input), wpabuf_len(input));
}


/**
 * nan_crypto_verify_fkce - Verify a received PKBST FKCE KeyAuth
 * @ipk: IPK of the signer
 * @input: Output of nan_crypto_build_fkce_input()
 * @key_auth: Received KeyAuth field
 * @key_auth_len: Length of @key_auth
 * Returns: 0 if the signature is valid, -1 otherwise
 */
int nan_crypto_verify_fkce(const u8 *ipk, const struct wpabuf *input,
			   const u8 *key_auth, size_t key_auth_len)
{
	if (!input || !key_auth || key_auth_len == 0) {
		wpa_printf(MSG_DEBUG, "NAN: Invalid FKCE KeyAuth");
		return -1;
	}

	return nan_crypto_verify_pkr_signature(ipk, wpabuf_head(input),
					       wpabuf_len(input),
					       key_auth, key_auth_len);
}


/**
 * nan_crypto_derive_pik - Derive the Pairwise Identity Key (PIK)
 * @nm_kdk: NM-KDK of the pairing
 * @nm_kdk_len: Length of @nm_kdk
 * @initiator_nmi: Pairing Initiator NMI
 * @responder_nmi: Pairing Responder NMI
 * @pik: Buffer for the NAN_PIK_LEN octet PIK
 * Returns: 0 on success, -1 on failure
 *
 * Wi-Fi Aware spec R5, section 7.6.4.2:
 * PIK = Truncate-128(KDF-HASH-256(NM-KDK, "Pairwise PIK Derivation",
 *                    Initiator NMI || Responder NMI)).
 * The KDF output is 256 bits and that is then truncated to 128 bits, which
 * differs from requesting a 128-bit output from the KDF.
 */
int nan_crypto_derive_pik(const u8 *nm_kdk, size_t nm_kdk_len,
			  const u8 *initiator_nmi, const u8 *responder_nmi,
			  u8 *pik)
{
	u8 out[SHA256_MAC_LEN];
	int ret;

	if (!pik)
		return -1;
	ret = nan_crypto_derive_from_kdk(nm_kdk, nm_kdk_len,
					 NAN_CS_PK_PASN_128,
					 "Pairwise PIK Derivation",
					 initiator_nmi, responder_nmi,
					 out, sizeof(out));
	if (ret == 0)
		os_memcpy(pik, out, NAN_PIK_LEN);
	forced_memzero(out, sizeof(out));
	return ret ? -1 : 0;
}

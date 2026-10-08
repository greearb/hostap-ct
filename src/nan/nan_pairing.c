/*
 * Wi-Fi Aware - NAN pairing module
 * Copyright (C) 2025 Intel Corporation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include "common.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "common/nan_de.h"
#include "crypto/crypto.h"
#include "pasn/pasn_common.h"
#include "nan/nan_i.h"


/* IRSA with the PNTag of the NPKID (Wi-Fi Aware spec R5, section 7.6.5.1) */
static void nan_pairing_add_pntag_irsa(struct wpabuf *buf, const u8 *npkid,
				       size_t start)
{
	const size_t len = 1 + NAN_NIRA_NONCE_LEN + 2 + NAN_NIRA_TAG_LEN;

	if (wpabuf_tailroom(buf) < NAN_ATTR_HDR_LEN + len ||
	    wpabuf_len(buf) - start + NAN_ATTR_HDR_LEN + len > 255)
		return;

	wpabuf_put_u8(buf, NAN_ATTR_IRSA);
	wpabuf_put_le16(buf, len);
	wpabuf_put_u8(buf, NAN_IRSA_CIPHER_VER_SIPHASH_2_4);
	wpabuf_put_data(buf, npkid, NAN_NIRA_NONCE_LEN);
	wpabuf_put_u8(buf, NAN_TAG_TYPE_PN);
	wpabuf_put_u8(buf, 1);
	wpabuf_put_data(buf, &npkid[NAN_NIRA_NONCE_LEN], NAN_NIRA_TAG_LEN);
}


static void nan_pairing_prepare_pasn_elems(struct nan_data *nan_data,
					   struct nan_peer *peer,
					   struct wpabuf *extra_ies,
					   int publish_id, int auth_mode);
static int nan_pairing_pasn_initialize(struct nan_data *nan_data,
				       struct nan_peer *peer, u8 auth_mode,
				       int cipher, const char *password,
				       enum nan_pairing_role self_role);
static int nan_pairing_prepare_data_element(void *ctx, const u8 *peer_addr);
static int nan_pairing_parse_data_element(void *ctx, const u8 *data,
					  size_t len);


/* PKBST identity confirmation applies to pairing setup using SAE */
static bool nan_pairing_pkbst_setup(struct nan_peer *peer)
{
	return peer->bootstrap.pkbst_mode != NAN_PKBST_MODE_NONE &&
		!(peer->pairing.flags & NAN_PAIRING_FLAG_NPK_VERIFICATION) &&
		peer->pairing.pasn && peer->pairing.pasn->sae.tmp;
}


/**
 * nan_pairing_is_pkr_usable - Check whether a PKR may be used
 * @pkr: NAN Pairing Key Record
 * Returns: true if the record is valid and has not expired
 */
bool nan_pairing_is_pkr_usable(const struct nan_pkr *pkr)
{
	struct os_reltime now;

	if (!pkr || !pkr->valid ||
	    (pkr->op_ctrl & NAN_PKR_OP_CTRL_REVOKED) ||
	    !pkr->valid_duration)
		return false;

	if (!os_reltime_initialized(&pkr->created_at) ||
	    os_get_reltime(&now) < 0)
		return false;

	return !os_reltime_expired(&now, &pkr->created_at,
				   (os_time_t) pkr->valid_duration * 60);
}


/**
 * nan_pkr_encode - Encode and sign a Public Key Record
 * @buf: Buffer to append the record to
 * @pkr: Record to encode
 * @isk: Individual Secret Key associated with @pkr->ipk
 * Returns: 0 on success, -1 on failure
 *
 * Wi-Fi Aware spec R5, Table 34: Length | Version | Record Control | Cipher
 * Version | IPK | IIK | Valid Duration | [Number of GIKs | List of GIKs] |
 * Record Signature, big-endian. The signature covers the fields after Length
 * and is mandatory, so a record is never emitted without it. The ISK is
 * passed separately so that record structures never hold secret keys.
 */
int nan_pkr_encode(struct wpabuf *buf, const struct nan_pkr *pkr, const u8 *isk)
{
	struct wpabuf *data, *sig = NULL;
	size_t len;
	int ret = -1;

	if (!buf || !pkr || !pkr->valid || !isk ||
	    pkr->num_giks > NAN_MAX_GIKS)
		return -1;

	data = wpabuf_alloc(1 + 3 + 1 + NAN_IPK_LEN + NAN_IIK_LEN + 4 + 2 +
			    pkr->num_giks * NAN_GIK_LEN);
	if (!data)
		return -1;
	wpabuf_put_u8(data, NAN_PKR_VERSION);
	wpabuf_put_u8(data, pkr->num_giks ? NAN_PKR_CONF_GIKS : 0);
	wpabuf_put_be16(data, pkr->op_ctrl);
	wpabuf_put_u8(data, NAN_PKR_CIPHER_VERSION_0);
	wpabuf_put_data(data, pkr->ipk, NAN_IPK_LEN);
	wpabuf_put_data(data, pkr->iik, NAN_IIK_LEN);
	wpabuf_put_be32(data, pkr->valid_duration);
	if (pkr->num_giks) {
		wpabuf_put_be16(data, pkr->num_giks);
		wpabuf_put_data(data, pkr->giks, pkr->num_giks * NAN_GIK_LEN);
	}

	sig = nan_crypto_sign_pkr(isk, wpabuf_head(data), wpabuf_len(data));
	if (!sig)
		goto out;

	len = wpabuf_len(data) + wpabuf_len(sig);
	if (len > 0xffff || wpabuf_tailroom(buf) < 2 + len) {
		wpa_printf(MSG_DEBUG, "NAN: No room for PKR (len=%zu)", len);
		goto out;
	}

	wpabuf_put_be16(buf, len);
	wpabuf_put_buf(buf, data);
	wpabuf_put_buf(buf, sig);
	ret = 0;
out:
	wpabuf_free(sig);
	wpabuf_free(data);
	return ret;
}


/**
 * nan_pkr_parse - Parse and verify a received Public Key Record
 * @data: Record, starting with its Length field
 * @len: Number of octets available at @data
 * @pkr: Buffer for the parsed record; modified only on success
 * Returns: Number of octets consumed on success, -1 on failure
 *
 * Wi-Fi Aware spec R5, Table 34 and Table 35. The optional fields are present
 * as indicated by the Record Configuration bits. The Record Signature is
 * mandatory and is verified with the IPK carried in the record.
 */
int nan_pkr_parse(const u8 *data, size_t len, struct nan_pkr *pkr)
{
	struct nan_pkr tmp;
	const u8 *pos, *end, *signed_start;
	u8 conf;
	u16 num_giks, ds_len;
	size_t rec_len, skip;

	if (!data || !pkr || len < 2)
		return -1;
	rec_len = WPA_GET_BE16(data);
	if (rec_len > len - 2) {
		wpa_printf(MSG_DEBUG, "NAN: Truncated PKR (%zu > %zu)",
			   rec_len, len - 2);
		return -1;
	}

	os_memset(&tmp, 0, sizeof(tmp));
	pos = data + 2;
	signed_start = pos;
	end = pos + rec_len;

	if (end - pos < 1 + 3 + 1 + NAN_IPK_LEN + NAN_IIK_LEN + 4) {
		wpa_printf(MSG_DEBUG, "NAN: PKR too short (%zu)", rec_len);
		return -1;
	}
	if (pos[0] != NAN_PKR_VERSION || pos[4] != NAN_PKR_CIPHER_VERSION_0) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Unsupported PKR version %u / cipher version %u",
			   pos[0], pos[4]);
		return -1;
	}
	pos++;
	conf = *pos++;
	tmp.op_ctrl = WPA_GET_BE16(pos);
	pos += 2 + 1;
	os_memcpy(tmp.ipk, pos, NAN_IPK_LEN);
	pos += NAN_IPK_LEN;
	os_memcpy(tmp.iik, pos, NAN_IIK_LEN);
	pos += NAN_IIK_LEN;
	tmp.valid_duration = WPA_GET_BE32(pos);
	pos += 4;

	/* Valid After/Before are skipped; validity is taken from Valid
	 * Duration, which starts when the record is received.
	 */
	skip = 0;
	if (conf & NAN_PKR_CONF_VALID_AFTER)
		skip += 8;
	if (conf & NAN_PKR_CONF_VALID_BEFORE)
		skip += 8;
	if ((size_t) (end - pos) < skip)
		goto truncated;
	pos += skip;

	if (conf & NAN_PKR_CONF_GIKS) {
		if (end - pos < 2)
			goto truncated;
		num_giks = WPA_GET_BE16(pos);
		pos += 2;
		if (end - pos < num_giks * NAN_GIK_LEN)
			goto truncated;
		/*
		 * The number of GIKs is not limited by the spec. Retain up to
		 * NAN_MAX_GIKS and skip the rest; the signature still covers
		 * the whole list.
		 */
		tmp.num_giks = num_giks > NAN_MAX_GIKS ? NAN_MAX_GIKS :
			num_giks;
		if (num_giks > NAN_MAX_GIKS)
			wpa_printf(MSG_DEBUG,
				   "NAN: PKR has %u GIKs; retaining first %u",
				   num_giks, NAN_MAX_GIKS);
		os_memcpy(tmp.giks, pos, tmp.num_giks * NAN_GIK_LEN);
		pos += num_giks * NAN_GIK_LEN;
	}

	if (conf & NAN_PKR_CONF_DS_INFO) {
		if (end - pos < 2)
			goto truncated;
		ds_len = WPA_GET_BE16(pos);
		pos += 2;
		if (end - pos < ds_len)
			goto truncated;
		pos += ds_len;
	}

	/* The remainder is the mandatory Record Signature */
	if (pos == end)
		goto truncated;

	if (nan_crypto_verify_pkr_signature(tmp.ipk,
					    signed_start, pos - signed_start,
					    pos, end - pos) < 0) {
		wpa_printf(MSG_DEBUG, "NAN: PKR Record Signature invalid");
		return -1;
	}

	tmp.valid = true;
	os_get_reltime(&tmp.created_at);
	*pkr = tmp;
	return 2 + rec_len;

truncated:
	wpa_printf(MSG_DEBUG, "NAN: Truncated PKR or missing Record Signature");
	return -1;
}


/**
 * nan_pkra_encode - Encode the body of a Public Key Record attribute
 * @buf: Buffer to append Number of PKRs and List of PKRs to
 * @pkrs: Records to encode
 * @isks: Individual Secret Key for each entry in @pkrs
 * @num_pkrs: Number of records (1-255)
 * Returns: 0 on success, -1 on failure; @buf is not modified on failure
 *
 * Wi-Fi Aware spec R5, Table 155. The attribute header is added by the caller.
 */
int nan_pkra_encode(struct wpabuf *buf, const struct nan_pkr *pkrs[],
		    const u8 *isks[], unsigned int num_pkrs)
{
	size_t start;
	unsigned int i;

	if (!buf || !pkrs || !isks || !num_pkrs || num_pkrs > 255 ||
	    !wpabuf_tailroom(buf))
		return -1;

	start = wpabuf_len(buf);
	wpabuf_put_u8(buf, num_pkrs);
	for (i = 0; i < num_pkrs; i++) {
		if (nan_pkr_encode(buf, pkrs[i], isks[i]) < 0) {
			buf->used = start;
			return -1;
		}
	}

	return 0;
}


/**
 * nan_pkra_parse - Parse the body of a Public Key Record attribute
 * @data: Attribute body, starting with Number of PKRs
 * @len: Length of @data
 * @cb: Called for each record that parses and verifies successfully;
 *	a negative return value stops parsing
 * @ctx: Context for @cb
 * Returns: Number of records passed to @cb, or -1 on malformed input
 *
 * Wi-Fi Aware spec R5, Table 155. Records are parsed in place. A record that
 * fails verification is skipped, but a record whose Length exceeds the
 * attribute ends parsing, since the following records cannot be located.
 */
int nan_pkra_parse(const u8 *data, size_t len,
		   int (*cb)(void *ctx, const struct nan_pkr *pkr),
		   void *ctx)
{
	struct nan_pkr pkr;
	const u8 *pos, *end;
	unsigned int i, num_pkrs;
	int count = 0, res;
	size_t rec_len;

	if (!data || !cb || len < 1)
		return -1;

	num_pkrs = data[0];
	pos = data + 1;
	end = data + len;
	for (i = 0; i < num_pkrs; i++) {
		if (end - pos < 2 ||
		    end - pos - 2 < WPA_GET_BE16(pos)) {
			wpa_printf(MSG_DEBUG, "NAN: PKRA %u truncated", i);
			return -1;
		}
		rec_len = 2 + WPA_GET_BE16(pos);
		res = nan_pkr_parse(pos, rec_len, &pkr);
		pos += rec_len;
		if (res < 0) {
			wpa_printf(MSG_DEBUG, "NAN: Skip invalid PKRA %u", i);
			continue;
		}
		count++;
		if (cb(ctx, &pkr) < 0)
			break;
	}

	return count;
}


/**
 * nan_nira_get_tag_nonce - Generate NIRA nonce and compute NIRA tag
 * @nan: Pointer to NAN configuration structure
 * @nonce: Buffer to store the generated NIRA nonce (output)
 * @tag: Buffer to store the computed NIRA tag (output)
 * Returns: 0 on success, -1 on failure
 *
 * This function generates a random NIRA (NAN Identity Resolution Attribute)
 * nonce and derives the corresponding NIRA tag using the NIK (NAN Identity
 * Key), NMI address, and the generated nonce.
 *
 * The caller must ensure that nonce buffer is at least NAN_NIRA_NONCE_LEN bytes
 * and tag buffer is at least NAN_NIRA_TAG_LEN bytes.
 */
int nan_nira_get_tag_nonce(const struct nan_config *nan, u8 *nonce, u8 *tag)
{
	struct wpabuf *tag_buf;

	if (os_get_random(nonce, NAN_NIRA_NONCE_LEN) < 0) {
		wpa_printf(MSG_INFO, "NAN: Failed to generate NIRA nonce");
		return -1;
	}

	tag_buf = nan_crypto_derive_nira_tag(nan->nik, NAN_NIK_LEN,
					     nan->nmi_addr, nonce);
	if (!tag_buf)
		return -1;

	os_memcpy(tag, wpabuf_head(tag_buf), NAN_NIRA_TAG_LEN);
	wpabuf_free(tag_buf);

	wpa_hexdump_key(MSG_DEBUG, "NAN: NIK", nan->nik, NAN_NIK_LEN);
	wpa_hexdump(MSG_DEBUG, "NAN: NIRA-NONCE", nonce, NAN_NIRA_NONCE_LEN);
	wpa_hexdump(MSG_DEBUG, "NAN: NIRA-TAG", tag, NAN_NIRA_TAG_LEN);
	return 0;
}


/**
 * nan_pairing_add_attrs - Add NAN pairing attributes to a buffer
 * @nan: Pointer to NAN data structure containing configuration
 * @buf: Pointer to wpabuf where attributes will be added
 * Returns: 0 on success, -1 otherwise
 *
 * This function adds NAN attributes that indicate pairing capabilities
 * to the provided buffer.
 */
int nan_pairing_add_attrs(struct nan_data *nan, struct wpabuf *buf)
{
	if (!nan || !buf)
		return -1;

	nan_add_dev_capa_ext_attr(nan, buf);

	if (nan->cfg->pairing_cfg.pairing_verification) {
		if (nan_add_nira(buf, nan->nira_tag, nan->nira_nonce)) {
			wpa_printf(MSG_INFO, "NAN: Failed to add NIRA");
			return -1;
		}
	}

	return 0;
}


void nan_pairing_deinit_peer(struct nan_data *nan_data, struct nan_peer *peer,
			     bool remove_nm_tk)
{
	wpabuf_free(peer->pairing.pending_auth1);
	peer->pairing.pending_auth1 = NULL;
	wpabuf_free(peer->pairing.peer_key_auth);
	peer->pairing.peer_key_auth = NULL;

	os_free(peer->pairing.psi_locale);
	peer->pairing.psi_locale = NULL;
	os_free(peer->pairing.psi_vendor_name);
	peer->pairing.psi_vendor_name = NULL;
	os_free(peer->pairing.psi_model_name);
	peer->pairing.psi_model_name = NULL;
	os_free(peer->pairing.psi_pairing_name);
	peer->pairing.psi_pairing_name = NULL;

	/* Remove the NM-TK from the driver only when the pairing did not
	 * complete successfully. On the success path the key must remain
	 * installed so that subsequent NAN Management frames are protected.
	 * Callers that tear down a failed or aborted session pass true;
	 * callers that clean up after a successful NIK exchange pass false.
	 */
	if (remove_nm_tk && peer->pairing.nm_tk_installed && nan_data &&
	    nan_data->cfg->install_nm_tk)
		nan_data->cfg->install_nm_tk(nan_data->cfg->cb_ctx,
					     peer->nmi_addr, 0, NULL, 0);
	if (remove_nm_tk)
		peer->pairing.nm_tk_installed = false;

	if (!peer->pairing.pasn)
		return;

	wpa_pasn_reset(peer->pairing.pasn);
	pasn_data_deinit(peer->pairing.pasn);
	peer->pairing.pasn = NULL;
	peer->pairing.self_pairing_role = NAN_PAIRING_ROLE_IDLE;
}


int nan_pairing_abort(struct nan_data *nan_data, const u8 *peer_addr)
{
	struct nan_peer *peer;
	int cipher;
	struct wpabuf *extra_ies;
	int ret = -1;

	peer = nan_get_peer(nan_data, peer_addr);
	if (!peer) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing abort: Peer " MACSTR " not found",
			   MAC2STR(peer_addr));
		return -1;
	}

	if (!peer->pairing.pasn && !peer->pairing.pending_auth1) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing abort: No PASN in progress with peer "
			   MACSTR, MAC2STR(peer_addr));
		return -1;
	}

	wpa_printf(MSG_DEBUG, "NAN: Aborting pairing with peer " MACSTR,
		   MAC2STR(peer_addr));

	if (!peer->pairing.pending_auth1) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing abort: No pending Auth1 frame for peer "
			   MACSTR, MAC2STR(peer_addr));
		ret = 0;
		goto done;
	}

	/* The auth mode and cipher are not important when rejecting.
	 * Just make sure to use a supported cipher so
	 * nan_pairing_pasn_initialize() won't fail.
	 */
	cipher = (nan_data->cfg->pairing_cfg.cipher_suites &
		  NAN_PAIRING_PASN_128) ? WPA_CIPHER_CCMP : WPA_CIPHER_GCMP_256;

	if (nan_pairing_pasn_initialize(nan_data, peer, NAN_PASN_AUTH_MODE_PASN,
					cipher, "",
					NAN_PAIRING_ROLE_RESPONDER)) {
		wpa_printf(MSG_DEBUG, "NAN: Pairing: Initialize failed");
		goto done;
	}

	extra_ies = wpabuf_alloc(NAN_ELEMENT_MAX_SIZE);
	if (!extra_ies) {
		wpa_printf(MSG_INFO,
			   "NAN: Pairing: Failed to allocate buffer for extra elements");
		goto done;
	}

	nan_pairing_prepare_pasn_elems(nan_data, peer, extra_ies,
				       peer->pairing.handle,
				       NAN_PASN_AUTH_MODE_PASN);
	pasn_set_extra_ies(peer->pairing.pasn, wpabuf_head_u8(extra_ies),
			   wpabuf_len(extra_ies));
	wpabuf_free(extra_ies);

	nan_configure_peer_schedule(nan_data, peer, &nan_data->sched, false);

	ret = handle_auth_pasn_resp(peer->pairing.pasn, nan_data->cfg->nmi_addr,
				    peer_addr, NULL,
				    WLAN_STATUS_UNSPECIFIED_FAILURE);
	if (ret < 0) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing abort: Failed to send response");
		nan_clear_peer_schedule(nan_data, peer);
	}

done:
	nan_pairing_deinit_peer(nan_data, peer, true);
	return ret;
}


static bool nan_pairing_is_supported(struct nan_data *nan_data,
				     struct nan_peer *peer, u8 auth_mode)
{
	if (auth_mode == NAN_PASN_AUTH_MODE_PASN ||
	    auth_mode == NAN_PASN_AUTH_MODE_SAE) {
		if (!nan_data->cfg->pairing_cfg.pairing_setup) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: Device doesn't support pairing setup");
			return false;
		}

		if (!peer->pairing.pairing_cfg.pairing_setup) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: Peer doesn't support pairing setup");
			return false;
		}
	} else if (auth_mode == NAN_PASN_AUTH_MODE_PMK) {
		if (!nan_data->cfg->pairing_cfg.pairing_verification) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: Device doesn't support pairing verification");
			return false;
		}

		if (!peer->pairing.pairing_cfg.pairing_verification) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: Peer doesn't support pairing verification");
			return false;
		}

		if (!nan_data->cfg->get_npk_akmp) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: get_npk_akmp callback not set");
			return false;
		}
	}

	return true;
}


static int nan_pairing_set_password(struct pasn_data *pasn,
				    const u8 *password, size_t password_len)
{
#ifdef CONFIG_SAE
	struct sae_pt *pt;

	pt = sae_derive_pt(pasn->pasn_groups, (const u8 *) NAN_PASN_SSID,
			   os_strlen(NAN_PASN_SSID), password, password_len,
			   NULL, 0);
	if (pasn_set_pt(pasn, pt) < 0) {
		wpa_printf(MSG_INFO, "NAN: Pairing: Failed to set SAE pt");
		sae_deinit_pt(pt);
		return -1;
	}

	return 0;
#else  /* CONFIG_SAE */
	return -1;
#endif /* CONFIG_SAE */
}


/*
 * Wi-Fi Aware spec R5, section 7.6.8 and Table 35: with PKBST, the SAE password
 * is derived from the publisher's (Pairing Responder's) IPK and, in mutual
 * PKBST, also the subscriber's (Pairing Initiator's) IPK.
 *
 * Returns 1 if the password was derived, 0 if PKBST is not used with the peer,
 * or -1 if PKBST was negotiated but the records needed for it are not
 * available. There is no fallback to a configured password in that case.
 */
static int nan_pairing_pkbst_password(struct nan_data *nan,
				      struct nan_peer *peer,
				      enum nan_pairing_role self_role,
				      u8 *password)
{
	bool responder = self_role == NAN_PAIRING_ROLE_RESPONDER;
	bool mutual = peer->bootstrap.pkbst_mode == NAN_PKBST_MODE_MUTUAL;
	const struct nan_pkr *pub, *sub;
	const u8 *init_nmi, *resp_nmi;

	if (peer->bootstrap.pkbst_mode == NAN_PKBST_MODE_NONE)
		return 0;

	pub = responder ? &nan->self_pkr : &peer->peer_pkr;
	sub = responder ? &peer->peer_pkr : &nan->self_pkr;
	if (!nan_pairing_is_pkr_usable(pub) ||
	    (mutual && !nan_pairing_is_pkr_usable(sub))) {
		wpa_printf(MSG_INFO,
			   "NAN: Pairing: PKBST records not available");
		return -1;
	}

	init_nmi = responder ? peer->nmi_addr : nan->cfg->nmi_addr;
	resp_nmi = responder ? nan->cfg->nmi_addr : peer->nmi_addr;
	if (nan_crypto_derive_pkbst_password(pub->ipk,
					     mutual ? sub->ipk : NULL,
					     init_nmi, resp_nmi,
					     password) < 0)
		return -1;

	wpa_printf(MSG_DEBUG, "NAN: Pairing: Using %s PKBST password",
		   mutual ? "mutual" : "one-way");
	return 1;
}


static struct wpabuf * nan_pairing_generate_rsnxe(int akmp, bool non_cluster)
{
	/*
	 * RSNXE capabilities field layout:
	 *   bits 0-3  : Field length (n - 1), where n = number of capability
	 *               octets following the field-length nibble.
	 *   bit  5    : SAE-H2E (WLAN_RSNX_CAPAB_SAE_H2E = 5)
	 *   bit  18   : KEK in PASN (WLAN_RSNX_CAPAB_KEK_IN_PASN = 18)
	 *
	 * For clustered pairing: 2-byte capabilities field (n=2, field_len=1)
	 *   -> IE total = 2 (header) + 2 (capab) = 4 bytes
	 *
	 * For non-cluster pairing: bit 18 requires 3-byte capabilities field
	 *   (n=3, field_len=2) -> IE total = 2 (header) + 3 (capab) = 5 bytes
	 */
	u32 capab;
	size_t capab_len;
	struct wpabuf *buf;

	if (non_cluster) {
		/* KEK_IN_PASN is bit 18 and needs 3 capability bytes
		 * (bits 0-23).
		 * Field length nibble = n - 1 = 3 - 1 = 2.
		 */
		capab_len = 3;
		capab = 2; /* field_length = 2 (n-1 for n=3 bytes) */
	} else {
		capab_len = 2;
		capab = 1; /* field_length = 1 (n-1 for n=2 bytes) */
	}

	if (wpa_key_mgmt_sae(akmp))
		capab |= BIT(WLAN_RSNX_CAPAB_SAE_H2E);

	if (non_cluster)
		capab |= BIT(WLAN_RSNX_CAPAB_KEK_IN_PASN);

	/* Element header (2 octets) + capabilities field (capab_len octets) */
	buf = wpabuf_alloc(2 + capab_len);
	if (!buf)
		return NULL;

	wpa_printf(MSG_DEBUG, "NAN: Pairing: RSNXE capab=0x%06x", capab);

	wpabuf_put_u8(buf, WLAN_EID_RSNX);
	wpabuf_put_u8(buf, capab_len);
	/* Write capabilities little-endian, capab_len bytes */
	wpabuf_put_u8(buf, capab & 0xff);
	wpabuf_put_u8(buf, (capab >> 8) & 0xff);
	if (capab_len == 3)
		wpabuf_put_u8(buf, (capab >> 16) & 0xff);
	return buf;
}


static int nan_pairing_send_cb(void *ctx, const u8 *data, size_t data_len,
			       int noack, unsigned int freq, unsigned int wait)
{
	struct nan_data *nan_data = (struct nan_data *) ctx;

	return nan_data->cfg->send_pasn(nan_data->cfg->cb_ctx, data, data_len,
					freq);
}


/*
 * Wi-Fi Aware spec R5, section 7.6.5.1: with NPK/PIK caching, the PMKID of the
 * pairing verification is Nonce || PNTag, where the PNTag is derived from the
 * PIK cached with the peer and the local NMI address, as in the IRSA of the
 * same frame (Table 25).
 */
static int nan_pairing_pik_npkid(struct nan_data *nan,
				 const struct nan_pik_cache_entry *pik,
				 u8 *npkid)
{
	struct wpabuf *tag;

	if (os_get_random(npkid, NAN_NIRA_NONCE_LEN) < 0)
		return -1;
	tag = nan_crypto_derive_irsa_tag(pik->pik, NAN_PIK_LEN,
					 nan->cfg->nmi_addr, npkid);
	if (!tag)
		return -1;
	os_memcpy(&npkid[NAN_NIRA_NONCE_LEN], wpabuf_head(tag),
		  NAN_NIRA_TAG_LEN);
	wpabuf_free(tag);
	return 0;
}


/**
 * nan_pasn_verification_init - Initialize PASN data for pairing verification
 * @nan_data: Pointer to NAN data structure containing configuration
 * @peer: Pointer to the NAN peer structure
 * Returns: 0 on success, -1 on failure
 *
 * This function gets the NPK and AKMP for the given peer and sets it as the
 * PASN PMK and AKMP. It also generates the NIRA nonce and tag to be used as the
 * custom PMKID for the PASN verification process.
 */
static int nan_pasn_verification_init(struct nan_data *nan_data,
				      struct nan_peer *peer)
{
	struct nan_pairing_peer_data *pairing_data;
	const struct nan_pik_cache_entry *pik;
	const struct wpabuf *npk = NULL;
	const u8 *npk_data;
	size_t npk_len;
	int akmp;
	u8 npkid[NAN_NIRA_NONCE_LEN + NAN_NIRA_TAG_LEN];

	pairing_data = &peer->pairing;
	pik = nan_pik_cache_get(nan_data->pik_cache, peer->nmi_addr);

	if (!pairing_data->nonce_tag_valid && !pik) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: No identity available for verification");
		return -1;
	}

	if (pik) {
		npk_data = pik->npk;
		npk_len = pik->npk_len;
		akmp = pik->akmp;
	} else {
		npk = nan_data->cfg->get_npk_akmp(nan_data->cfg->cb_ctx,
						  peer->nmi_addr,
						  pairing_data->nonce,
						  pairing_data->tag, &akmp);
		if (!npk) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: Failed to get NPK AKMP for verification");
			return -1;
		}
		npk_data = wpabuf_head_u8(npk);
		npk_len = wpabuf_len(npk);
	}

	pasn_set_akmp(pairing_data->pasn, akmp);

	if (pairing_data->self_pairing_role == NAN_PAIRING_ROLE_INITIATOR)
		pasn_initiator_pmksa_cache_add(nan_data->initiator_pmksa,
					       nan_data->cfg->nmi_addr,
					       peer->nmi_addr,
					       npk_data, npk_len, NULL, akmp);
	else
		pasn_responder_pmksa_cache_add(nan_data->responder_pmksa,
					       nan_data->cfg->nmi_addr,
					       peer->nmi_addr,
					       npk_data, npk_len, NULL, akmp);

	/*
	 * According to Wi-Fi Aware Specification v4.0, section 7.6.5, pairing
	 * verification uses NPKID constructed from NIRA nonce and tag. The same
	 * nonce and tag should be used in the NIRA added to PASN first and
	 * second frames. With NPK/PIK caching the NAN Tag is a PNTag derived
	 * from the cached PIK and the IRSA carries it instead (Wi-Fi Aware spec
	 * R5, section 7.6.5.1).
	 */
	if (pik) {
		if (nan_pairing_pik_npkid(nan_data, pik, npkid) < 0)
			return -1;
	} else if (nan_nira_get_tag_nonce(nan_data->cfg, npkid,
					  &npkid[NAN_NIRA_NONCE_LEN]) < 0) {
		wpa_printf(MSG_DEBUG, "NAN: Failed to get NIRA tag and nonce");
		return -1;
	}

	pasn_set_custom_pmkid(pairing_data->pasn, npkid);

	os_memcpy(peer->pairing.npkid, npkid, PMKID_LEN);
	peer->pairing.npkid_valid = true;
	wpa_printf(MSG_DEBUG, "NAN: Pairing: Stored NPKID for " MACSTR,
		   MAC2STR(peer->nmi_addr));

	return 0;
}


static int nan_validate_custom_pmkid(void *ctx, const u8 *addr, const u8 *pmkid)
{
	struct nan_data *nan = ctx;
	const struct nan_pik_cache_entry *pik;
	struct wpabuf *tag;
	int ret;

	/*
	 * With NPK/PIK caching the NAN Tag in the PMKID is a PNTag derived
	 * from the PIK cached with the peer and the peer's NMI address, so it
	 * is verified here. Otherwise, the custom PMKID is constructed from a
	 * NIRA nonce and tag, which are matched to a known NIK during NIRA
	 * validation, and any PMKID is accepted.
	 */
	pik = nan_pik_cache_get(nan->pik_cache, addr);
	if (!pik)
		return 0;

	tag = nan_crypto_derive_irsa_tag(pik->pik, NAN_PIK_LEN, addr, pmkid);
	if (!tag)
		return -1;
	ret = os_memcmp_const(wpabuf_head(tag), &pmkid[NAN_NIRA_NONCE_LEN],
			      NAN_NIRA_TAG_LEN) == 0 ? 0 : -1;
	wpabuf_free(tag);
	wpa_printf(MSG_DEBUG, "NAN: Pairing: PNTag in PMKID %s",
		   ret ? "did not match the cached PIK" : "verified");
	return ret;
}


/* Verify the peer's FKCE KeyAuth, signed with the ISK of its record */
static int nan_pairing_verify_fkce(struct nan_data *nan, struct nan_peer *peer,
				   const struct wpabuf *key_auth)
{
	bool responder =
		peer->pairing.self_pairing_role == NAN_PAIRING_ROLE_RESPONDER;
	struct wpabuf *input;
	int ret = -1;

	if (!key_auth) {
		wpa_printf(MSG_INFO, "NAN: Pairing: PKBST FKCE missing");
		return -1;
	}

	input = nan_crypto_build_fkce_input(&peer->pairing.pasn->sae,
					    peer->peer_pkr.ipk,
					    responder ? peer->nmi_addr :
					    nan->cfg->nmi_addr,
					    responder ? nan->cfg->nmi_addr :
					    peer->nmi_addr,
					    responder);
	if (input) {
		ret = nan_crypto_verify_fkce(peer->peer_pkr.ipk, input,
					     wpabuf_head(key_auth),
					     wpabuf_len(key_auth));
		wpabuf_free(input);
	}
	wpa_printf(MSG_DEBUG, "NAN: Pairing: PKBST FKCE %s",
		   ret ? "invalid" : "verified");
	return ret;
}


/* PASN callback: verify the responder's identity before auth 3 is sent */
static int nan_pairing_verify_auth2(void *ctx, const u8 *peer_addr)
{
	struct nan_data *nan = ctx;
	struct nan_peer *peer = nan_get_peer(nan, peer_addr);
	int ret;

	if (!peer || !peer->pairing.pasn)
		return -1;
	if (!nan_pairing_pkbst_setup(peer))
		return 0;

	ret = nan_pairing_verify_fkce(nan, peer, peer->pairing.peer_key_auth);
	wpabuf_free(peer->pairing.peer_key_auth);
	peer->pairing.peer_key_auth = NULL;
	return ret;
}


static int nan_pairing_pasn_initialize(struct nan_data *nan_data,
				       struct nan_peer *peer, u8 auth_mode,
				       int cipher, const char *password,
				       enum nan_pairing_role self_role)
{
	struct wpabuf *rsnxe = NULL;
	struct pasn_data *pasn;
	struct nan_pairing_peer_data *pairing;

	pairing = &peer->pairing;
	if (pairing->pasn) {
		wpa_pasn_reset(pairing->pasn);
	} else {
		pairing->pasn = pasn_data_init();
		if (!pairing->pasn) {
			wpa_printf(MSG_INFO,
				   "NAN: Pairing: Failed to initialize PASN data");
			return -1;
		}
	}

	pasn = pairing->pasn;
	pasn_set_own_addr(pasn, nan_data->cfg->nmi_addr);
	pasn_set_peer_addr(pasn, peer->nmi_addr);
	/* For non-cluster (USD) devices the local cluster ID is zero; use
	 * the peer's cluster ID as BSSID so frame validation passes.
	 */
	if (is_zero_ether_addr(nan_data->cluster_id) &&
	    !is_zero_ether_addr(peer->peer_cluster_id))
		pasn_set_bssid(pasn, peer->peer_cluster_id);
	else
		pasn_set_bssid(pasn, nan_data->cluster_id);

	if (self_role == NAN_PAIRING_ROLE_INITIATOR)
		pasn->pmksa = nan_data->initiator_pmksa;
	else
		pasn->pmksa = nan_data->responder_pmksa;

	if (cipher == WPA_CIPHER_GCMP_256 &&
	    (nan_data->cfg->pairing_cfg.cipher_suites & NAN_PAIRING_PASN_256)) {
		pasn->group = 20;
		pasn->cipher = WPA_CIPHER_GCMP_256;
	} else if (cipher == WPA_CIPHER_CCMP &&
		   (nan_data->cfg->pairing_cfg.cipher_suites &
		    NAN_PAIRING_PASN_128)) {
		pasn->group = 19;
		pasn->cipher = WPA_CIPHER_CCMP;
	} else {
		wpa_printf(MSG_INFO,
			   "NAN: Pairing: Unsupported cipher suite %s",
			   wpa_cipher_txt(cipher));
		goto fail;
	}

	pasn_enable_kdk_derivation(pasn);

	/* Set allowed PASN groups. This is needed for all modes */
	os_free(pasn->pasn_groups);
	pasn->pasn_groups = os_calloc(2, sizeof(*pasn->pasn_groups));
	if (!pasn->pasn_groups) {
		wpa_printf(MSG_INFO,
			   "NAN: Pairing: Failed to allocate PASN groups");
		goto fail;
	}
	pasn->pasn_groups[0] = pasn->group;

	if (auth_mode == NAN_PASN_AUTH_MODE_SAE) {
		u8 pkbst_pw[NAN_PKBST_PASSWORD_LEN];
		int res;

		pasn_set_akmp(pasn, WPA_KEY_MGMT_SAE);
		res = nan_pairing_pkbst_password(nan_data, peer, self_role,
						 pkbst_pw);
		if (res < 0)
			goto fail;
		if (res > 0) {
			res = nan_pairing_set_password(pasn, pkbst_pw,
						       sizeof(pkbst_pw));
			forced_memzero(pkbst_pw, sizeof(pkbst_pw));
		} else if (password) {
			res = nan_pairing_set_password(pasn,
						       (const u8 *) password,
						       os_strlen(password));
		} else {
			wpa_printf(MSG_INFO,
				   "NAN: Pairing: Password not available");
			goto fail;
		}
		if (res < 0) {
			wpa_printf(MSG_INFO,
				   "NAN: Pairing: Failed to set password");
			goto fail;
		}
	} else if (auth_mode == NAN_PASN_AUTH_MODE_PASN) {
		pasn_set_akmp(pasn, WPA_KEY_MGMT_PASN);
		pasn_set_noauth(pasn, true);
	} else if (auth_mode == NAN_PASN_AUTH_MODE_PMK) {
		if (nan_pasn_verification_init(nan_data, peer)) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: PASN verification init failed");
			goto fail;
		}
	} else {
		wpa_printf(MSG_INFO,
			   "NAN: Pairing: Unsupported authentication mode %u",
			   auth_mode);
		goto fail;
	}

	pasn_set_rsn_pairwise(pasn, pasn->cipher);
	pasn_set_wpa_key_mgmt(pasn, pasn->akmp);

	/* Enable KEK derivation when the peer is not in a NAN cluster so
	 * the NIK exchange can be encrypted in the PASN data element.
	 */
	if (peer->non_cluster || !nan_data->nan_started) {
		if (pasn->cipher == WPA_CIPHER_GCMP_256)
			pasn->kek_len = 32;
		else
			pasn->kek_len = 16;
		pasn->derive_kek = true;
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: KEK derivation enabled kek_len=%zu",
			   pasn->kek_len);
	}

	if (auth_mode != NAN_PASN_AUTH_MODE_PASN) {
		rsnxe = nan_pairing_generate_rsnxe(pasn->akmp,
						   peer->non_cluster ||
						   !nan_data->nan_started);
		if (!rsnxe) {
			wpa_printf(MSG_INFO,
				   "NAN: Pairing: Failed to generate RSNXE");
			goto fail;
		}

		pasn_set_rsnxe_ie(pairing->pasn, wpabuf_head_u8(rsnxe));
		wpabuf_free(rsnxe);
	}

	pasn_register_callbacks(pasn, nan_data, nan_pairing_send_cb,
				nan_validate_custom_pmkid, NULL, NULL);

	/* The prepare callback is also used for clustered responder pairing to
	 * install the NM-TK before M2 transmission.
	 */
	pasn->prepare_data_element = nan_pairing_prepare_data_element;
	pasn->verify_auth2 = nan_pairing_verify_auth2;

	/* Register encrypted data callbacks to embed and parse the NIK
	 * in PASN Authentication frames when the peer is not in a NAN cluster.
	 */
	if (nan_peer_no_shared_cluster(nan_data, peer->nmi_addr)) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Registering encrypted data callbacks");
		pasn->parse_data_element = nan_pairing_parse_data_element;
	}

	return 0;

fail:
	pasn_data_deinit(pasn);
	pairing->pasn = NULL;
	return -1;
}


/*
 * nan_pairing_add_csia - Add the pairing Cipher Suite Information attribute
 * @nan_data: Pointer to NAN data structure
 * @peer: Pointer to NAN peer structure
 * @extra_ies: Buffer to which the CSIA is appended
 * @publish_id: Local service handle; used as the CSIA Publish ID for the
 *              responder and as a fallback for the initiator when
 *              peer_instance_id is not yet known
 *
 * The responder advertises the service's configured cipher suite list, while
 * the initiator indicates the selected NCS-PK-PASN cipher suite (the best
 * NCS-PK-PASN cipher suite supported by both peers, Wi-Fi Aware spec v4.0,
 * section 7.6.4). The CSIA Publish ID always identifies the peer's publish
 * service when acting as initiator.
 */
static void nan_pairing_add_csia(const struct nan_data *nan_data,
				 const struct nan_peer *peer,
				 struct wpabuf *extra_ies, int publish_id)
{
	struct nan_cipher_suite cs_list[NAN_CS_MAX];
	size_t cs_count = 0;
	const int *cs_ids = NULL;
	u8 csia_publish_id;

	if (peer->pairing.self_pairing_role == NAN_PAIRING_ROLE_RESPONDER ||
	    peer->pairing.peer_instance_id <= 0)
		csia_publish_id = (u8) publish_id;
	else
		csia_publish_id = (u8) peer->pairing.peer_instance_id;

	/* The responder advertises the full service cipher suite list. */
	if (nan_data->cfg->get_cipher_suites_list && publish_id > 0 &&
	    peer->pairing.self_pairing_role == NAN_PAIRING_ROLE_RESPONDER)
		cs_ids = nan_data->cfg->get_cipher_suites_list(
			nan_data->cfg->cb_ctx, publish_id);

	/* For the initiator, cs_ids is intentionally left NULL; the selected
	 * cipher suite is derived from the completed PASN handshake below.
	 */
	if (cs_ids) {
		size_t i;

		for (i = 0; cs_ids[i] && cs_count < NAN_CS_MAX; i++) {
			cs_list[cs_count].csid = (u8) cs_ids[i];
			cs_list[cs_count].instance_id = csia_publish_id;
			cs_count++;
		}
	}

	if (cs_count == 0) {
		/* For the pairing initiator, indicate the selected NCS-PK-PASN
		 * cipher suite - the best cipher suite supported by both peers
		 * (Wi-Fi Aware spec v4.0, section 7.6.4).
		 */
		cs_list[0].csid =
			(peer->pairing.pasn->cipher == WPA_CIPHER_GCMP_256) ?
			NAN_CS_PK_PASN_256 : NAN_CS_PK_PASN_128;
		cs_list[0].instance_id = csia_publish_id;
		cs_count = 1;
	}

	nan_add_csia(extra_ies, nan_data->cfg->security_capab,
		     cs_count, cs_list);
}


/*
 * With PKBST, identify the selected records to the peer during PASN setup
 * with the same NAN Tags as in discovery.
 */
static void nan_pairing_add_pkbst_irsa(struct nan_data *nan,
				       struct nan_peer *peer,
				       struct wpabuf *buf, size_t start)
{
	u8 nonce[NAN_NIRA_NONCE_LEN];
	u8 *tags = NULL;
	u16 tags_len = 0;
	bool is_publisher =
		peer->pairing.self_pairing_role == NAN_PAIRING_ROLE_RESPONDER;

	if (peer->bootstrap.pkbst_mode == NAN_PKBST_MODE_NONE ||
	    nan_irsa_get_nonce_tag_tlv(nan, nonce, &tags, &tags_len,
					is_publisher) < 0 ||
	    !tags_len || wpabuf_tailroom(buf) < 3 + 1 + sizeof(nonce) +
	    tags_len ||
	    /* The NAN element carrying the attributes is limited to 255 */
	    wpabuf_len(buf) - start + 3 + 1 + sizeof(nonce) + tags_len > 255) {
		os_free(tags);
		return;
	}

	wpabuf_put_u8(buf, NAN_ATTR_IRSA);
	wpabuf_put_le16(buf, 1 + sizeof(nonce) + tags_len);
	wpabuf_put_u8(buf, NAN_IRSA_CIPHER_VER_SIPHASH_2_4);
	wpabuf_put_data(buf, nonce, sizeof(nonce));
	wpabuf_put_data(buf, tags, tags_len);
	os_free(tags);
}


/*
 * Wi-Fi Aware spec R5, section 7.6.4: when both devices support NPK/PIK
 * caching, they derive a pairwise PIK after pairing setup instead of exchanging
 * NIKs. Cache it with the NPK so that the peer can be rediscovered and pairing
 * verified with it later. Pairing verification keeps the cached entry.
 */
static void nan_pairing_cache_pik(struct nan_data *nan, struct nan_peer *peer)
{
	struct pasn_data *pasn = peer->pairing.pasn;
	const struct nan_pik_cache_entry *cached_pik = NULL;
	bool initiator =
		peer->pairing.self_pairing_role == NAN_PAIRING_ROLE_INITIATOR;
	u8 pik[NAN_PIK_LEN];

	if (nan->pik_cache)
		cached_pik = nan_pik_cache_get(nan->pik_cache, peer->nmi_addr);

	/*
	 * Derive a PIK only after successful pairing setup. Pairing
	 * verification reuses the cached PIK and must not replace it.
	 */
	if (!nan->pik_cache || !nan->cfg->pairing_cfg.pik_caching ||
	    !peer->pairing.pairing_cfg.pik_caching ||
	    peer->bootstrap.pkbst_mode == NAN_PKBST_MODE_NONE ||
	    cached_pik ||
	    (peer->pairing.flags & NAN_PAIRING_FLAG_NPK_VERIFICATION) ||
	    (pasn_get_akmp(pasn) == WPA_KEY_MGMT_SAE && !pasn->sae.tmp) ||
	    !pasn->ptk.kdk_len || !pasn->pmk_len)
		return;

	if (nan_crypto_derive_pik(pasn->ptk.kdk, pasn->ptk.kdk_len,
				  initiator ? nan->cfg->nmi_addr :
				  peer->nmi_addr,
				  initiator ? peer->nmi_addr :
				  nan->cfg->nmi_addr, pik) == 0)
		nan_pik_cache_add(nan->pik_cache, peer->nmi_addr, pik,
				  pasn->pmk, pasn->pmk_len,
				  pasn_get_akmp(pasn));
	forced_memzero(pik, sizeof(pik));
}


/*
 * nan_pairing_prepare_pasn_elems - Prepare NAN element for pairing PASN frames
 * @nan_data: Pointer to NAN data structure
 * @peer: Pointer to NAN peer structure
 * @extra_ies: Buffer to which the NAN element is appended
 * @publish_id: Publish ID to use in the CSIA
 * @auth_mode: Pairing authentication mode
 *
 * This function adds a NAN element containing the NAN attributes that shall be
 * included in the first and second PASN frames for NAN pairing.
 * The added attributes are:
 * - Device Capability Extension attribute (DCEA)
 * - Cipher Suite Information attribute (CSIA) with the service's configured
 *   cipher suite list (responder) or the selected NCS-PK-PASN cipher suite
 *   (initiator, Wi-Fi Aware spec v4.0, section 7.6.4)
 * - NAN Pairing Bootstrapping attribute (NPBA), if available
 * - Pairing Bootstrapping Extended attribute (PBEA), if available
 * - Identity Resolution Set attribute (IRSA), if available
 */
static void nan_pairing_prepare_pasn_elems(struct nan_data *nan_data,
					   struct nan_peer *peer,
					   struct wpabuf *extra_ies,
					   int publish_id, int auth_mode)
{
	u8 *len_ptr;
	size_t initial_len = wpabuf_len(extra_ies);

	wpabuf_put_u8(extra_ies, WLAN_EID_VENDOR_SPECIFIC);

	/* placeholder for length - to be filled later */
	len_ptr = wpabuf_put(extra_ies, 1);

	/* OUI + OUI Type */
	wpabuf_put_be32(extra_ies, NAN_IE_VENDOR_TYPE);

	nan_pairing_add_csia(nan_data, peer, extra_ies, publish_id);
	nan_add_dev_capa_ext_attr(nan_data, extra_ies);

	if (auth_mode == NAN_PASN_AUTH_MODE_SAE ||
	    auth_mode == NAN_PASN_AUTH_MODE_PASN) {
		if (peer->bootstrap.npba)
			wpabuf_put_buf(extra_ies, peer->bootstrap.npba);

		if (peer->bootstrap.extended_pbm ||
		    peer->bootstrap.pairing_setup_info) {
			u16 extended_pbm = 0;
			const u8 *pairing_setup_info = NULL;
			u16 pairing_setup_info_len = 0;
			struct wpabuf *pbea;

			if (nan_data->cfg->get_pbea_info)
				nan_data->cfg->get_pbea_info(
						nan_data->cfg->cb_ctx,
						publish_id, &extended_pbm,
						&pairing_setup_info,
						&pairing_setup_info_len);

			pbea = nan_build_pbea(extended_pbm, pairing_setup_info,
					      pairing_setup_info_len);
			if (pbea) {
				wpabuf_put_buf(extra_ies, pbea);
				wpabuf_free(pbea);
			}
		}

		nan_pairing_add_pkbst_irsa(nan_data, peer, extra_ies,
					   initial_len + 2);
	} else {
		const u8 *npkid = peer->pairing.pasn->custom_pmkid;

		/*
		 * Add the identity attribute with the same nonce and tag as in
		 * the NPKID. NPKID is: Nonce || NAN Tag. With NPK/PIK caching
		 * the tag is a PNTag and is carried in an IRSA.
		 */
		if (nan_pik_cache_get(nan_data->pik_cache, peer->nmi_addr))
			nan_pairing_add_pntag_irsa(extra_ies, npkid,
						   initial_len + 2);
		else if (nan_add_nira(extra_ies, &npkid[NAN_NIRA_NONCE_LEN],
				      npkid))
			wpa_printf(MSG_DEBUG, "NAN: Failed to add NIRA");
	}

	*len_ptr = wpabuf_len(extra_ies) - initial_len - 2;
}


/**
 * nan_pairing_initiate_pasn_auth - Initiate PASN authentication for NAN pairing
 * @nan_data: NAN data context
 * @addr: MAC address of the peer device
 * @auth_mode: Authentication mode to be used (PASN, SAE, or PMK)
 * @cipher: Cipher suite to be used for the pairing
 * @handle: Handle of the service instance for which pairing is requested
 * @peer_instance_id: Instance ID of the peer service for which pairing is
 *	requested
 * @responder: Whether this device is acting as PASN responder
 * @password: Password to be used for authentication (if applicable)
 * Returns: 0 on success, -1 on failure
 */
int nan_pairing_initiate_pasn_auth(struct nan_data *nan_data, const u8 *addr,
				   u8 auth_mode, int cipher, int handle,
				   u8 peer_instance_id, bool responder,
				   const char *password,
				   const struct nan_schedule *sched,
				   bool auto_nik_exchange)
{
	int ret = 0;
	struct pasn_data *pasn;
	struct nan_peer *peer;
	struct wpabuf *extra_ies;

	if (!addr) {
		wpa_printf(MSG_INFO, "NAN: Pairing: Peer address missing");
		return -1;
	}

	peer = nan_get_peer(nan_data, addr);
	if (!peer) {
		wpa_printf(MSG_INFO, "NAN: Pairing: Peer not known");
		return -1;
	}

	if (peer->bootstrap.in_progress) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Bootstrap in progress with peer");
		return -1;
	}

	if (!nan_pairing_is_supported(nan_data, peer, auth_mode)) {
		wpa_printf(MSG_INFO,
			   "NAN: Pairing: Invalid params to initiate authentication");
		return -1;
	}

	peer->pairing.self_pairing_role = responder ?
		NAN_PAIRING_ROLE_RESPONDER : NAN_PAIRING_ROLE_INITIATOR;

	if (nan_pairing_pasn_initialize(nan_data, peer, auth_mode, cipher,
					password,
					peer->pairing.self_pairing_role)) {
		wpa_printf(MSG_INFO, "NAN: Pairing: Initialize failed");
		return -1;
	}

	pasn = peer->pairing.pasn;

	extra_ies = wpabuf_alloc(NAN_ELEMENT_MAX_SIZE);
	if (!extra_ies)
		return -1;

	/* Record service instance IDs before building the NAN element so that
	 * nan_pairing_prepare_pasn_elems() can read peer_instance_id when
	 * selecting the CSIA Publish ID for the subscriber role.
	 */
	peer->pairing.handle = handle;
	peer->pairing.peer_instance_id = peer_instance_id;
	peer->pairing.flags = 0;
	peer->pairing.auto_nik_exchange = auto_nik_exchange;

	/* TODO: Add support for NAN element fragmentation if it's larger than
	 * 255 octets, as defined in Wi-Fi Aware Specification v4.0 section 9.1.
	 */
	nan_pairing_prepare_pasn_elems(nan_data, peer, extra_ies, handle,
				       auth_mode);
	pasn_set_extra_ies(pasn, wpabuf_head_u8(extra_ies),
			   wpabuf_len(extra_ies));
	wpabuf_free(extra_ies);

	/* Skip DW schedule negotiation for non-cluster (USD) peers. */
	if (!nan_peer_no_shared_cluster(nan_data, peer->nmi_addr) &&
	    nan_configure_peer_schedule(nan_data, peer, sched, false))
		wpa_printf(MSG_DEBUG, "NAN: Could not configure peer schedule");
	if (responder) {
		if (peer->pairing.pending_auth1) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: Responder - process pending Auth1");
			ret = nan_pairing_auth_rx(
				nan_data,
				wpabuf_head(peer->pairing.pending_auth1),
				wpabuf_len(peer->pairing.pending_auth1),
				(int) peer->freq);
			wpabuf_free(peer->pairing.pending_auth1);
			peer->pairing.pending_auth1 = NULL;

			return ret;
		}
		return 0;
	}

	if (auth_mode == NAN_PASN_AUTH_MODE_PMK) {
		peer->pairing.flags |= NAN_PAIRING_FLAG_NPK_VERIFICATION;
		ret = wpa_pasn_verify(pasn, pasn->own_addr, pasn->peer_addr,
				      pasn->bssid, pasn->akmp, pasn->cipher,
				      pasn->group, peer->freq,
				      NULL, 0, NULL, 0, NULL);
	} else {
		ret = wpas_pasn_start(pasn, pasn->own_addr, pasn->peer_addr,
				      pasn->bssid, pasn->akmp, pasn->cipher,
				      pasn->group, peer->freq,
				      NULL, 0, NULL, 0, NULL);
	}

	if (ret) {
		wpa_printf(MSG_INFO, "NAN: Pairing: Failed to start PASN");
		nan_pairing_deinit_peer(nan_data, peer, true);
	}

	return ret;
}


/**
 * nan_pairing_done - Derive NPK caching related keys after successful pairing
 * @nan_data: NAN interface data
 * @peer: NAN peer with which pairing is being completed
 *
 * This function completes the NAN pairing process by deriving the necessary
 * cryptographic keys (KEK and NPK for opportunistic pairing) when NPK caching
 * is enabled.
 */
static void nan_pairing_done(struct nan_data *nan_data, struct nan_peer *peer)
{
	u8 npk[NAN_NPK_LEN];
	struct pasn_data *pasn = peer->pairing.pasn;
	int cipher = pasn_get_cipher(pasn);
	u8 *initiator_nmi, *responder_nmi;
	int ret;

	peer->pairing.flags |= NAN_PAIRING_FLAG_PAIRED;

	peer->pairing.pairing_csid = cipher == WPA_CIPHER_GCMP_256 ?
		NAN_CS_PK_PASN_256 : NAN_CS_PK_PASN_128;
	peer->pairing.pairing_akmp = pasn_get_akmp(pasn);
	nan_pairing_cache_pik(nan_data, peer);

	/* Both pairing setup and verification leave an NPKSA in place */
	peer->cm.npksa = true;

	/* The NM-TK is installed only for pairing within the NAN cluster */
	if (!nan_peer_no_shared_cluster(nan_data, peer->nmi_addr))
		nan_cm_nm_tksa_established(nan_data, peer);

	if (!nan_data->cfg->pairing_cfg.npk_caching ||
	    !peer->pairing.pairing_cfg.npk_caching ||
	    (peer->pairing.flags & NAN_PAIRING_FLAG_NPK_VERIFICATION))
		return;

	wpa_printf(MSG_DEBUG, "NAN: Pairing: Derive KEK after PASN pairing");

	if (peer->pairing.self_pairing_role == NAN_PAIRING_ROLE_INITIATOR) {
		initiator_nmi = nan_data->cfg->nmi_addr;
		responder_nmi = peer->nmi_addr;
	} else {
		initiator_nmi = peer->nmi_addr;
		responder_nmi = nan_data->cfg->nmi_addr;
	}

	ret = nan_crypto_derive_kek(pasn->ptk.kdk, pasn->ptk.kdk_len,
				    peer->pairing.pairing_csid,
				    initiator_nmi, responder_nmi,
				    &pasn->ptk);
	if (ret) {
		wpa_printf(MSG_DEBUG, "NAN: Pairing: Failed to derive KEK");
		return;
	}

	/* Store the peer NIK received in the PASN Encrypted Data element. */
	if (nan_peer_no_shared_cluster(nan_data, peer->nmi_addr) &&
	    peer->pairing.peer_nik_valid) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Storing peer NIK received during PASN");
		nan_data->cfg->update_pairing_credentials(
			nan_data->cfg->cb_ctx, peer->pairing.peer_nik,
			NAN_NIK_LEN, NAN_NIRA_CIPHER_VER_128,
			peer->pairing.peer_nik_lifetime, pasn_get_akmp(pasn),
			pasn->pmk, pasn->pmk_len);
	}

	/* For SAE AKMP, NPK was already derived inside the PASN module and
	 * stored in pasn->pmk. For PASN AKMP, derive NPK here and configure it
	 * to the PASN module. The NPK will be stored alongside the peer's NIK
	 * when the NIK is received from the peer.
	 */
	if (pasn_get_akmp(pasn) != WPA_KEY_MGMT_PASN)
		return;

	wpa_printf(MSG_DEBUG, "NAN: Pairing: Derive NPK after PASN pairing");

	ret = nan_crypto_derive_npk(pasn->ptk.kdk, pasn->ptk.kdk_len,
				    peer->pairing.pairing_csid,
				    initiator_nmi, responder_nmi, npk,
				    sizeof(npk));
	if (ret) {
		wpa_printf(MSG_DEBUG, "NAN: Pairing: Failed to derive NPK");
		return;
	}

	os_memcpy(pasn->pmk, npk, NAN_NPK_LEN);
	pasn->pmk_len = NAN_NPK_LEN;
}


/**
 * nan_nik_build_key_data - Build NAN Identity Key (NIK) key data buffer
 * @nan_data: Pointer to NAN data structure containing configuration
 * Returns: Pointer to allocated wpabuf containing the key data, or NULL
 *	on failure.
 *
 * This function constructs a buffer containing NAN key data elements including:
 * - NIK KDE (Key Data Encapsulation) with cipher version and NIK value
 * - Key Lifetime KDE indicating the NIK key lifetime
 *
 * Note: Caller is responsible for freeing the returned buffer.
 */
static struct wpabuf * nan_nik_build_key_data(struct nan_data *nan_data)
{
	struct wpabuf *buf;

	buf = wpabuf_alloc(KDE_HDR_LEN + sizeof(struct nan_nik_kde) +
			   KDE_HDR_LEN + sizeof(struct nan_key_lifetime_kde));
	if (!buf)
		return NULL;

	nan_add_kde_hdr(buf, NAN_KEY_DATA_NIK, sizeof(struct nan_nik_kde));
	wpabuf_put_u8(buf, NAN_NIRA_CIPHER_VER_128);
	wpabuf_put_data(buf, nan_data->cfg->nik, sizeof(nan_data->cfg->nik));

	nan_add_kde_hdr(buf, NAN_KEY_DATA_LIFETIME,
			sizeof(struct nan_key_lifetime_kde));
	wpabuf_put_le16(buf, NAN_KEY_LIFETIME_NIK);
	wpabuf_put_be32(buf, nan_data->cfg->nik_lifetime);

	return buf;
}


/**
 * nan_send_nik - Send NAN Identity Key (NIK) to a peer
 * @nan_data: Pointer to NAN data structure containing configuration and state
 * @peer: Pointer to the NAN peer structure to send the NIK to
 * Returns: 0 on success, -1 in case of an error
 *
 * This function sends the NAN Identity Key (NIK) and the NIK lifetime to a peer
 * device as part of the NAN pairing process. The NIK is encrypted using the KEK
 * (Key Encryption Key) derived from PASN and sent in a Shared Key Descriptor
 * Attribute (SKDA) within a follow-up message.
 */
static int nan_send_nik(struct nan_data *nan_data, struct nan_peer *peer)
{
	struct wpabuf *skda, *key_data;
	struct wpa_eapol_key *key_desc;
	u16 info, key_len;
	int ret;
	struct wpabuf *encrypted_key_data = NULL;
	size_t skda_len;
	u8 mic[16] = { 0 };

	/* NIK was already exchanged in the PASN Encrypted Data element. */
	if (nan_peer_no_shared_cluster(nan_data, peer->nmi_addr)) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Skipping post-PASN NIK send");
		return 0;
	}

	if (peer->bootstrap.pkbst_mode != NAN_PKBST_MODE_NONE) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: PKBST pairing, don't send NIK");
		return 0;
	}

	if (!nan_data->cfg->pairing_cfg.npk_caching) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Local NPK caching not enabled, don't send NIK");
		return 0;
	}

	if (!peer->pairing.pairing_cfg.npk_caching) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Peer NPK caching not enabled, don't send NIK");
		return 0;
	}

	if (peer->pairing.flags & NAN_PAIRING_FLAG_NPK_VERIFICATION)
		return 0;

	if (!peer->pairing.pasn || !peer->pairing.pasn->ptk.kek_len) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: KEK not available for NIK encryption");
		return -1;
	}

	key_data = nan_nik_build_key_data(nan_data);
	if (!key_data) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Failed to build NIK key data");
		return -1;
	}

	/* Encrypt the key data using the KEK from the PASN data */
	encrypted_key_data = nan_crypto_encrypt_key_data(
		key_data, peer->pairing.pasn->ptk.kek,
		peer->pairing.pasn->ptk.kek_len);
	wpabuf_clear_free(key_data);
	if (!encrypted_key_data) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Failed to encrypt NIK key data");
		return -1;
	}

	skda_len = sizeof(struct nan_shared_key) +
		sizeof(struct wpa_eapol_key) + 2 + sizeof(mic) +
		wpabuf_len(encrypted_key_data);

	skda = wpabuf_alloc(NAN_ATTR_HDR_LEN + skda_len);
	if (!skda) {
		wpa_printf(MSG_INFO,
			   "NAN: Pairing: Failed to allocate SKDA buffer");
		wpabuf_free(encrypted_key_data);
		return -1;
	}

	wpabuf_put_u8(skda, NAN_ATTR_SHARED_KEY_DESCR);
	wpabuf_put_le16(skda, skda_len);
	wpabuf_put_u8(skda, peer->pairing.handle);

	key_desc = wpabuf_put(skda, sizeof(*key_desc));
	os_memset(key_desc, 0, sizeof(*key_desc));

	key_desc->type = NAN_KEY_DESC;
	info = WPA_KEY_INFO_TYPE_AKM_DEFINED | WPA_KEY_INFO_KEY_TYPE |
		WPA_KEY_INFO_ACK | WPA_KEY_INFO_ENCR_KEY_DATA |
		WPA_KEY_INFO_MIC;
	WPA_PUT_BE16(key_desc->key_info, info);

	key_len = wpa_cipher_key_len(peer->pairing.pasn->cipher);
	WPA_PUT_BE16(key_desc->key_length, key_len);

	wpabuf_put_data(skda, mic, sizeof(mic));
	wpabuf_put_be16(skda, wpabuf_len(encrypted_key_data));
	wpabuf_put_buf(skda, encrypted_key_data);
	wpa_printf(MSG_DEBUG, "NAN: Pairing: Sending NIK");

	ret = nan_data->cfg->transmit_followup(nan_data->cfg->cb_ctx,
					       peer->nmi_addr, skda,
					       peer->pairing.handle,
					       peer->pairing.peer_instance_id,
					       peer->freq);

	wpabuf_free(encrypted_key_data);
	wpabuf_free(skda);

	return ret;
}


/**
 * nan_send_nik_for_peer - Send the NIK follow-up to a peer by address
 * @nan_data: NAN module context
 * @peer_addr: Peer NMI address
 * Returns: 0 on success, -1 on failure
 */
int nan_send_nik_for_peer(struct nan_data *nan_data, const u8 *peer_addr)
{
	struct nan_peer *peer;

	if (!nan_data || !peer_addr)
		return -1;

	peer = nan_get_peer(nan_data, peer_addr);
	if (!peer) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: send_nik_for_peer: Peer " MACSTR
			   " not known", MAC2STR(peer_addr));
		return -1;
	}

	return nan_send_nik(nan_data, peer);
}


static int nan_pairing_derive_nd_pmk(struct nan_data *nan_data,
				     struct nan_peer *peer, u8 *nd_pmk)
{
	struct pasn_data *pasn = peer->pairing.pasn;
	int cipher = pasn_get_cipher(pasn);
	enum nan_cipher_suite_id csid;
	const u8 *initiator_nmi, *responder_nmi;
	int ret;

	wpa_printf(MSG_DEBUG, "NAN: Pairing: Derive ND-PMK after PASN pairing");

	if (peer->pairing.self_pairing_role == NAN_PAIRING_ROLE_INITIATOR) {
		initiator_nmi = nan_data->cfg->nmi_addr;
		responder_nmi = peer->nmi_addr;
	} else {
		initiator_nmi = peer->nmi_addr;
		responder_nmi = nan_data->cfg->nmi_addr;
	}

	csid = cipher == WPA_CIPHER_GCMP_256 ? NAN_CS_PK_PASN_256 :
		NAN_CS_PK_PASN_128;

	ret = nan_crypto_derive_nd_pmk_from_kdk(pasn->ptk.kdk,
						pasn->ptk.kdk_len, csid,
						initiator_nmi, responder_nmi,
						nd_pmk);
	if (ret)
		wpa_printf(MSG_INFO,
			   "NAN: Pairing: Failed to derive ND PMK");
	return ret;
}


/**
 * nan_pairing_pasn_auth_tx_status - Handle PASN Authentication frame TX status
 * @nan: Pointer to NAN data structure
 * @data: Pointer to the transmitted frame data
 * @data_len: Length of the transmitted frame data in bytes
 * @acked: Whether the frame was acknowledged
 * Returns: 0 on success, -1 on error
 *
 * This function processes the transmission status of a PASN Authentication
 * frame used in NAN pairing and triggers the pairing result callback in case
 * PASN is done.
 */
int nan_pairing_pasn_auth_tx_status(struct nan_data *nan, const u8 *data,
				    size_t data_len, bool acked)
{
	int ret;
	struct nan_peer *peer;
	struct pasn_data *pasn;
	const struct ieee80211_mgmt *mgmt =
		(const struct ieee80211_mgmt *) data;

	if (!nan || !data ||
	    data_len < offsetof(struct ieee80211_mgmt, u.auth.variable))
		return -1;

	peer = nan_get_peer(nan, mgmt->da);
	if (!peer) {
		wpa_printf(MSG_DEBUG, "NAN: Pairing: Peer not found " MACSTR,
			   MAC2STR(mgmt->da));
		return -1;
	}

	/* Pairing was rejected. Clear peer schedule if no active NDPs */
	if (!peer->pairing.pasn) {
		if (dl_list_empty(&peer->ndps) && !peer->ndp_setup.ndp)
			nan_clear_peer_schedule(nan, peer);

		return 0;
	}

	pasn = peer->pairing.pasn;

	ret = wpa_pasn_auth_tx_status(pasn, data, data_len, acked);
	if (ret == 1) {
		u8 nd_pmk[PMK_LEN];

		if (pasn->status == WLAN_STATUS_SUCCESS &&
		    nan_pairing_derive_nd_pmk(nan, peer, nd_pmk)) {
			pasn->status = WLAN_STATUS_UNSPECIFIED_FAILURE;
			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: Failed to derive ND PMK");
		}

		os_free(peer->pairing.psi_locale);
		os_free(peer->pairing.psi_vendor_name);
		os_free(peer->pairing.psi_model_name);
		os_free(peer->pairing.psi_pairing_name);

		nan_pairing_parse_setup_info(
			peer->bootstrap.pairing_setup_info,
			peer->bootstrap.pairing_setup_info_len,
			&peer->pairing.psi_locale,
			&peer->pairing.psi_vendor_name,
			&peer->pairing.psi_model_name,
			&peer->pairing.psi_pairing_name);

		ret = nan->cfg->pairing_result_cb(nan->cfg->cb_ctx,
						  peer->nmi_addr, pasn->akmp,
						  pasn->cipher, pasn->status,
						  &pasn->ptk,
						  pasn->status ==
						  WLAN_STATUS_SUCCESS ? nd_pmk :
						  NULL,
						  peer->pairing.psi_locale,
						  peer->pairing.psi_vendor_name,
						  peer->pairing.psi_model_name,
						  peer->pairing.psi_pairing_name);
		forced_memzero(nd_pmk, PMK_LEN);
		if (pasn->status != WLAN_STATUS_SUCCESS || ret < 0) {
			nan_pairing_deinit_peer(nan, peer, true);
			return -1;
		}

		nan_pairing_done(nan, peer);

		/*
		 * Allow the peer to install the keys before transmitting the
		 * follow-up.
		 */
		/* FIX: A blocking sleep should not really be used here, i.e.,
		 * this needs to be removed or replace with a registered eloop
		 * timeout to avoid blocking the process. */
		os_sleep(0, 30000);

		/* Only send the NIK follow-up automatically when
		 * auto_nik_exchange is enabled. When disabled, the upper layer
		 * controls the NIK exchange.
		 */
		if (peer->pairing.auto_nik_exchange) {
			if (nan_send_nik(nan, peer) < 0) {
				wpa_printf(MSG_DEBUG,
					   "NAN: Pairing: Failed to send NIK");
				nan_pairing_deinit_peer(nan, peer, true);
				return -1;
			}
		} else {
			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: NIK send deferred to upper layer");
		}
	}

	wpabuf_free(pasn->frame);
	pasn->frame = NULL;

	return 0;
}


/**
 * nan_parse_csia - Parse NAN Cipher Suite Info Attribute
 * @csia: Pointer to the CSIA data buffer
 * @len: Length of the CSIA data buffer
 * @cs: Pointer to nan_cipher_suite structure to store parsed information
 * Returns: 0 on success, -1 on failure
 *
 * Parses the NAN Cipher Suite Info attribute (CSIA) and extracts the first
 * PASN-capable cipher suite entry. The CSIA may contain multiple entries;
 * non-PASN entries are skipped and the first PASN-capable entry is selected.
 */
static int nan_parse_csia(const u8 *csia, size_t len,
			  struct nan_cipher_suite *cs)
{
	size_t offset;

	/* Capabilities (1) + at least one Cipher Suite entry (2) */
	if (len < sizeof(struct nan_cipher_suite_info) +
	    sizeof(struct nan_cipher_suite)) {
		wpa_printf(MSG_DEBUG, "NAN: Pairing: CSIA too short");
		return -1;
	}

	/* Iterate cipher suite entries and select the first PASN-capable
	 * one.
	 */
	for (offset = sizeof(struct nan_cipher_suite_info);
	     offset + sizeof(struct nan_cipher_suite) <= len;
	     offset += sizeof(struct nan_cipher_suite)) {
		u8 csid = csia[offset];

		if (csid == NAN_CS_PK_PASN_128 || csid == NAN_CS_PK_PASN_256) {
			cs->csid = csid;
			cs->instance_id = csia[offset + 1];
			return 0;
		}
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Unsupported cipher suite in CSIA: %u",
			   csid);
	}

	wpa_printf(MSG_DEBUG, "NAN: Pairing: CSIA missing or invalid");
	return -1;
}


/**
 * nan_pairing_process_elems - Process NAN pairing information elements
 * @nan_data: NAN state data
 * @peer: NAN peer information structure
 * @mgmt: PASN Authentication frame
 * @len: Length of the PASN Authentication frame
 * @cs: Output cipher suite structure to be filled
 * Returns: 0 on success, -1 on failure
 *
 * This function processes NAN pairing information elements from a PASN
 * Authentication frame. It extracts the selected cipher suite and intance ID.
 */
static int nan_pairing_process_elems(struct nan_data *nan_data,
				     struct nan_peer *peer,
				     const struct ieee80211_mgmt *mgmt,
				     size_t len, struct nan_cipher_suite *cs)
{
	const u8 *ies;
	size_t ies_len;
	const u8 *buf;
	struct wpabuf *ie_buf;
	struct nan_attrs attrs;
	int ret;

	if (len < offsetof(struct ieee80211_mgmt, u.auth.variable)) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: PASN frame too short for NAN elements");
		return -1;
	}

	ies = mgmt->u.auth.variable;
	ies_len = len - offsetof(struct ieee80211_mgmt, u.auth.variable);

	buf = get_vendor_ie(ies, ies_len, NAN_IE_VENDOR_TYPE);
	if (!buf)
		return -1;

	ie_buf = ieee802_11_defrag(buf + 2, buf[1], false);
	if (!ie_buf)
		return -1;

	buf = wpabuf_head(ie_buf);
	ret = nan_parse_attrs(nan_data, &buf[4], wpabuf_len(ie_buf) - 4,
			      &attrs);
	if (ret)
		goto fail;

	nan_parse_peer_dev_capa_ext(nan_data, peer, &attrs);
	nan_parse_pbea(nan_data, peer, &attrs);

	if (!attrs.cipher_suite_info || !attrs.cipher_suite_info_len ||
	    nan_parse_csia(attrs.cipher_suite_info, attrs.cipher_suite_info_len,
			   cs) < 0) {
		wpa_printf(MSG_DEBUG, "NAN: Pairing: CSIA missing or invalid");
		ret = -1;
	}


	nan_attrs_clear(nan_data, &attrs);
fail:
	wpabuf_free(ie_buf);
	return ret;
}


/**
 * nan_pairing_handle_auth_1 - Handle the first PASN frame in NAN pairing
 * @nan_data: Pointer to NAN data structure
 * @own_addr: Own MAC address
 * @peer: Pointer to NAN peer structure
 * @mgmt: Pointer to the received PASN frame
 * @len: Length of the PASN frame
 * Returns: 0 on success, -1 on failure
 *
 * This function processes the first PASN Authentication frame during NAN
 * pairing as a responder. It initializes the PASN data structure, prepares
 * the necessary information elements, and delegates to the PASN module to
 * handle the authentication.
 */
static int nan_pairing_handle_auth_1(struct nan_data *nan_data,
				     const u8 *own_addr,
				     struct nan_peer *peer,
				     const struct ieee80211_mgmt *mgmt,
				     size_t len)
{
	struct nan_cipher_suite cs;
	struct pasn_data *pasn;
	int cipher;

	if (peer->pairing.self_pairing_role != NAN_PAIRING_ROLE_RESPONDER) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Unexpected Auth1 frame");
		return -1;
	}

	/* Re-arm the early TK install for each M1 (including retransmissions)
	 * so that a new PTK derived from a fresh M1 is always pushed to the
	 * driver before the corresponding M2 is sent.
	 */
	peer->pairing.nm_tk_installed = false;

	pasn = peer->pairing.pasn;

	if (nan_pairing_process_elems(nan_data, peer, mgmt, len, &cs)) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Handle Auth1 NAN attributes failed");
		return -1;
	}

	cipher = cs.csid == NAN_CS_PK_PASN_256 ? WPA_CIPHER_GCMP_256 :
		WPA_CIPHER_CCMP;

	if (cipher != pasn->cipher) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Cipher suite mismatch (CSIA: %s, PASN: %s)",
			   wpa_cipher_txt(cipher),
			   wpa_cipher_txt(pasn->cipher));
		return -1;
	}

	if (handle_auth_pasn_1(pasn, own_addr, peer->nmi_addr, mgmt, len,
			       false) < 0) {
		wpa_printf(MSG_DEBUG, "NAN: Pairing: Handle Auth1 failed");
		return -1;
	}

	return 0;
}


/* KeyAuth of the FKCE in a received PASN authentication frame */
static struct wpabuf *
nan_pairing_get_key_auth(const struct ieee80211_mgmt *mgmt, size_t len)
{
	const u8 *ie;
	size_t ies_len;

	if (len < offsetof(struct ieee80211_mgmt, u.auth.variable))
		return NULL;
	ies_len = len - offsetof(struct ieee80211_mgmt, u.auth.variable);
	ie = get_ie_ext(mgmt->u.auth.variable, ies_len,
			WLAN_EID_EXT_FILS_KEY_CONFIRM);
	if (!ie || ie[1] < 2)
		return NULL;
	return wpabuf_alloc_copy(ie + 3, ie[1] - 1);
}


static int nan_pairing_handle_auth_2(struct nan_data *nan_data,
				     struct nan_peer *peer,
				     const struct ieee80211_mgmt *mgmt,
				     size_t len)
{
	struct wpa_pasn_params_data pasn_data;
	struct pasn_data *pasn = peer->pairing.pasn;

	/* Verified by nan_pairing_verify_auth2() once SAE is processed */
	wpabuf_free(peer->pairing.peer_key_auth);
	peer->pairing.peer_key_auth = nan_pairing_get_key_auth(mgmt, len);

	if (wpa_pasn_auth_rx(peer->pairing.pasn, (const u8 *)mgmt, len,
			     &pasn_data) < 0) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: wpa_pasn_auth_rx() failed");
		nan_data->cfg->pairing_result_cb(
			nan_data->cfg->cb_ctx, peer->nmi_addr, pasn->akmp,
			pasn->cipher, WLAN_STATUS_UNSPECIFIED_FAILURE, NULL,
			NULL, NULL, NULL, NULL, NULL);
		nan_pairing_deinit_peer(nan_data, peer, true);
		return -1;
	}

	return 0;
}


static int nan_pairing_handle_auth_3(struct nan_data *nan_data,
				     struct nan_peer *peer,
				     const struct ieee80211_mgmt *mgmt,
				     size_t len)
{
	struct pasn_data *pasn = peer->pairing.pasn;
	int ret;
	u16 status = WLAN_STATUS_SUCCESS;
	u8 nd_pmk[PMK_LEN];

	ret = handle_auth_pasn_3(pasn, nan_data->cfg->nmi_addr, peer->nmi_addr,
				 mgmt, len);
	if (ret < 0) {
		status = WLAN_STATUS_UNSPECIFIED_FAILURE;
		wpa_printf(MSG_DEBUG, "NAN: Pairing: Handle Auth3 failed");
	} else {
		/* Mutual PKBST: the initiator confirms its identity in M3 */
		if (nan_pairing_pkbst_setup(peer) &&
		    peer->bootstrap.pkbst_mode == NAN_PKBST_MODE_MUTUAL) {
			struct wpabuf *key_auth;

			key_auth = nan_pairing_get_key_auth(mgmt, len);
			if (nan_pairing_verify_fkce(nan_data, peer, key_auth))
				status = WLAN_STATUS_UNSPECIFIED_FAILURE;
			wpabuf_free(key_auth);
		}

		if (status == WLAN_STATUS_SUCCESS &&
		    nan_pairing_derive_nd_pmk(nan_data, peer, nd_pmk)) {
			status = WLAN_STATUS_UNSPECIFIED_FAILURE;
			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: Failed to derive ND PMK");
		}
	}

	nan_pairing_parse_setup_info(peer->bootstrap.pairing_setup_info,
				     peer->bootstrap.pairing_setup_info_len,
				     &peer->pairing.psi_locale,
				     &peer->pairing.psi_vendor_name,
				     &peer->pairing.psi_model_name,
				     &peer->pairing.psi_pairing_name);

	ret = nan_data->cfg->pairing_result_cb(nan_data->cfg->cb_ctx,
					       peer->nmi_addr, pasn->akmp,
					       pasn->cipher, status,
					       &pasn->ptk,
					       status == WLAN_STATUS_SUCCESS ?
					       nd_pmk : NULL,
					       peer->pairing.psi_locale,
					       peer->pairing.psi_vendor_name,
					       peer->pairing.psi_model_name,
					       peer->pairing.psi_pairing_name);
	forced_memzero(nd_pmk, PMK_LEN);
	if (ret < 0 || status != WLAN_STATUS_SUCCESS)
		nan_pairing_deinit_peer(nan_data, peer, true);
	else if (status == WLAN_STATUS_SUCCESS)
		nan_pairing_done(nan_data, peer);

	/* Don't clear PASN data if pairing is successful. If caching is
	 * enabled, it will still be needed when the NIK is received from
	 * the peer.
	 */
	return status == WLAN_STATUS_SUCCESS ? ret : -1;
}


/**
 * nan_pairing_auth_rx - Handle received NAN pairing Authentication frames
 * @nan_data: Pointer to NAN data structure
 * @mgmt: Pointer to the PASN Authentication frame
 * @len: Length of the PASN Authentication frame in bytes
 * @freq: Frequency on which the frame was received (MHz)
 * Returns: 0 on success, -1 on failure
 */
int nan_pairing_auth_rx(struct nan_data *nan_data,
			const struct ieee80211_mgmt *mgmt, size_t len,
			int freq)
{
	struct nan_peer *peer;
	u16 auth_alg, auth_transaction, status_code;
	int ret;
	struct wpabuf *nan_ie;
	const u8 *buf;

	if (len < offsetof(struct ieee80211_mgmt, u.auth.variable))
		return -1;

	if (!ether_addr_equal(mgmt->da, nan_data->cfg->nmi_addr)) {
		wpa_printf(MSG_DEBUG, "NAN: Pairing: Not our frame");
		return -1;
	}

	auth_alg = le_to_host16(mgmt->u.auth.auth_alg);
	auth_transaction = le_to_host16(mgmt->u.auth.auth_transaction);
	status_code = le_to_host16(mgmt->u.auth.status_code);

	if (auth_alg != WLAN_AUTH_PASN) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Not a PASN frame, auth_alg=%d",
			   auth_alg);
		return -1;
	}

	/* For Authentication frames 2 and 3, the peer already has an active
	 * PASN session; look up by source address directly since the NAN
	 * element is not present in the clear in these frames.
	 */
	if (auth_transaction == 2 || auth_transaction == 3) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Authentication frame %u received",
			   auth_transaction);

		peer = nan_get_peer(nan_data, mgmt->sa);
		if (!peer) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: No peer found for " MACSTR,
				   MAC2STR(mgmt->sa));
			return -1;
		}

		if (!peer->pairing.pasn) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: No active PASN session for "
				   MACSTR,
				   MAC2STR(mgmt->sa));
			return -1;
		}

		if (status_code != WLAN_STATUS_SUCCESS) {
			struct pasn_data *pasn = peer->pairing.pasn;

			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: Authentication frame %u rejected - status=%u",
				   auth_transaction, status_code);
			if (nan_data->cfg->pairing_result_cb)
				nan_data->cfg->pairing_result_cb(
					nan_data->cfg->cb_ctx,
					peer->nmi_addr,
					pasn ? pasn->akmp : 0,
					pasn ? pasn->cipher : 0,
					status_code, NULL, NULL,
					NULL, NULL, NULL, NULL);
			nan_pairing_deinit_peer(nan_data, peer, true);
			return -1;
		}

		if (auth_transaction == 2)
			return nan_pairing_handle_auth_2(nan_data, peer, mgmt,
							 len);
		return nan_pairing_handle_auth_3(nan_data, peer, mgmt, len);
	}

	buf = get_vendor_ie(mgmt->u.auth.variable,
			    len - offsetof(struct ieee80211_mgmt,
					   u.auth.variable),
			    NAN_IE_VENDOR_TYPE);
	if (!buf) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: NAN pairing element not found in Authentication frame 1");
		return -1;
	}

	nan_ie = ieee802_11_defrag(buf + 2, buf[1], false);
	if (!nan_ie) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: No NAN element in PASN Authentication frame");
		return -1;
	}

	ret = nan_add_peer(nan_data, mgmt->sa, NULL, 0,
			   wpabuf_head_u8(nan_ie) + 4,
			   wpabuf_len(nan_ie) - 4);
	wpabuf_free(nan_ie);
	if (ret) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Failed to add peer from PASN");
		return -1;
	}

	peer = nan_get_peer(nan_data, mgmt->sa);
	if (!peer) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Failed to get a peer that was just added");
		return -1;
	}

	if (!peer->pairing.pasn) {
		if (status_code == WLAN_STATUS_SUCCESS &&
		    auth_transaction == 1) {
			struct nan_cipher_suite cs;
			const u8 *rsne;
			struct wpa_ie_data rsn_data;

			if (nan_pairing_process_elems(nan_data, peer, mgmt, len,
						      &cs)) {
				wpa_printf(MSG_DEBUG,
					   "NAN: Pairing: Handle Auth1 NAN attributes failed");
				return -1;
			}

			rsne = get_ie(mgmt->u.auth.variable,
				      len - offsetof(struct ieee80211_mgmt,
						     u.auth.variable),
				      WLAN_EID_RSN);
			if (!rsne) {
				wpa_printf(MSG_DEBUG,
					   "NAN: Pairing: RSNE missing in Auth1");
				return -1;
			}

			if (wpa_parse_wpa_ie_rsn(rsne, rsne[1] + 2,
						 &rsn_data)) {
				wpa_printf(MSG_DEBUG,
					   "NAN: Pairing: Failed to parse RSNE in Auth1");
				return -1;
			}

			wpabuf_free(peer->pairing.pending_auth1);
			peer->pairing.pending_auth1 =
				wpabuf_alloc_copy(mgmt, len);
			if (!peer->pairing.pending_auth1)
				return -1;

			nan_data->cfg->pairing_request(nan_data->cfg->cb_ctx,
						       peer->nmi_addr, cs.csid,
						       cs.instance_id,
						       &rsn_data);
			return 0;
		}

		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: PASN data not initialized for peer");
		return -1;
	}

	if (status_code != WLAN_STATUS_SUCCESS) {
		struct pasn_data *pasn = peer->pairing.pasn;

		nan_data->cfg->pairing_result_cb(nan_data->cfg->cb_ctx,
						 peer->nmi_addr, pasn->akmp,
						 pasn->cipher, status_code,
						 NULL, NULL,
						 NULL, NULL, NULL, NULL);
		nan_pairing_deinit_peer(nan_data, peer, true);
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Authentication rejected - status=%u",
			   status_code);
		return -1;
	}

	if (auth_transaction == 1) {
		struct pasn_data *pasn = peer->pairing.pasn;

		/* Set the reception frequency so the response is sent on
		 * the correct channel; needed for non-cluster (USD) devices
		 * where the radio is not locked to a fixed channel.
		 */
		if (pasn && freq)
			pasn->freq = freq;

		/* For non-cluster (USD) devices the BSSID is zero until the
		 * first PASN M1 is received; update it from the frame so
		 * subsequent checks pass.
		 */
		if (pasn && is_zero_ether_addr(pasn->bssid) &&
		    !is_zero_ether_addr(mgmt->bssid)) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Pairing: Setting BSSID from PASN M1: "
				   MACSTR, MAC2STR(mgmt->bssid));
			pasn_set_bssid(pasn, mgmt->bssid);
		}

		return nan_pairing_handle_auth_1(nan_data,
						 nan_data->cfg->nmi_addr, peer,
						 mgmt, len);
	}

	return -1;
}


/**
 * nan_pairing_followup_rx - Process received NAN pairing follow-up frame
 * @nan_data: NAN data context
 * @peer_addr: MAC address of the peer device
 * @shared_key_descr: Pointer to the shared key descriptor attribute
 * @attr_len: Length of the shared key descriptor attribute
 * Returns: true if the follow-up frame was processed, false otherwise.
 *
 * This function processes a received NAN pairing follow-up frame. It extracts
 * the NIK (NAN Identity Key) from the frame and notifies about the received
 * NIK.
 *
 * If the local device acted as the responder in the pairing process, it also
 * sends the local NIK to the peer.
 */
bool nan_pairing_followup_rx(struct nan_data *nan_data, const u8 *peer_addr,
			     const struct nan_shared_key *shared_key_descr,
			     size_t attr_len)
{
	struct nan_peer *peer;
	struct pasn_data *pasn;
	const struct wpa_eapol_key *key_desc;
	struct wpa_eapol_ie_parse ie;
	const struct nan_nik_kde *nik_kde;
	const struct nan_key_lifetime_kde *lifetime_kde;
	const u8 *pos;
	struct wpabuf *key_data = NULL;
	u16 key_data_len, key_info;
	bool ret = false;
	u16 lifetime_bitmap;

	wpa_printf(MSG_DEBUG, "NAN: Pairing: Follow-up frame received");
	peer = nan_get_peer(nan_data, peer_addr);
	if (!peer) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Follow-up frame from unknown peer");
		return false;
	}

	pasn = peer->pairing.pasn;
	if (!pasn || !pasn->ptk.kek_len) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: No PASN data for follow-up frame");
		return false;
	}

	if (!nan_data->cfg->pairing_cfg.npk_caching) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: NPK caching not enabled, ignore follow-up frame");
		return false;
	}

	key_desc = (const struct wpa_eapol_key *) shared_key_descr->key;
	key_info = WPA_GET_BE16(key_desc->key_info);

	if (!(key_info & WPA_KEY_INFO_KEY_TYPE)) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Follow-up frame does not contain pairwise key");
		return false;
	}

	if (!(key_info & WPA_KEY_INFO_ENCR_KEY_DATA)) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Follow-up frame does not contain encrypted key data");
		return false;
	}

	if (attr_len < sizeof(*shared_key_descr) + sizeof(*key_desc) + 16 + 2) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Follow-up frame too short for Key Data Length field");
		return false;
	}

	pos = shared_key_descr->key + sizeof(*key_desc) + 16;
	key_data_len = WPA_GET_BE16(pos);

	if (attr_len < sizeof(*shared_key_descr) + sizeof(*key_desc) + 16 + 2 +
	    key_data_len) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Follow-up frame too short for Key Data field");
		return false;
	}

	pos += 2;

	key_data = nan_crypto_decrypt_key_data(pasn->ptk.kek, pasn->ptk.kek_len,
					       pos, key_data_len);
	if (!key_data) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Failed to decrypt key data in follow-up frame");
		goto fail;
	}

	if (wpa_parse_kde_ies(wpabuf_head(key_data), wpabuf_len(key_data),
			      &ie) < 0) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Failed to parse decrypted key data in follow-up frame");
		goto fail;
	}

	if (!ie.nan_nik) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: NIK KDE missing in decrypted key data");
		goto fail;
	}

	nik_kde = (const struct nan_nik_kde *) ie.nan_nik;
	if (nik_kde->cipher_ver != NAN_NIRA_CIPHER_VER_128) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Unsupported NIK cipher version: %u",
			   nik_kde->cipher_ver);
		goto fail;
	}

	if (!ie.nan_key_lifetime) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Key Lifetime KDE missing in decrypted key data");
		goto fail;
	}

	lifetime_kde = (const struct nan_key_lifetime_kde *)
		ie.nan_key_lifetime;
	lifetime_bitmap = le_to_host16(lifetime_kde->key_bitmap);
	if (!(lifetime_bitmap & NAN_KEY_LIFETIME_NIK)) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Pairing: Unexpected key bitmap in Key "
			   "Lifetime KDE: 0x%02x",
			   lifetime_bitmap);
		goto fail;
	}

	nan_data->cfg->update_pairing_credentials(
		nan_data->cfg->cb_ctx, nik_kde->nik, NAN_NIK_LEN,
		nik_kde->cipher_ver, be_to_host32(lifetime_kde->lifetime_sec),
		pasn_get_akmp(pasn),
		pasn_get_pmk(pasn), pasn_get_pmk_len(pasn));
	os_memcpy(peer->pairing.peer_nik, nik_kde->nik, NAN_NIK_LEN);
	peer->pairing.peer_nik_valid = true;

	if (peer->pairing.self_pairing_role == NAN_PAIRING_ROLE_RESPONDER)
		nan_send_nik(nan_data, peer);

	ret = true;
fail:
	nan_pairing_deinit_peer(nan_data, peer, !ret);
	wpabuf_free(key_data);
	return ret;
}


int nan_pairing_set_pairing_setup(struct nan_data *nan, bool value)
{
	wpa_printf(MSG_DEBUG, "NAN: SET: Pairing setup: %d -> %d",
		   nan->cfg->pairing_cfg.pairing_setup, value);
	nan->cfg->pairing_cfg.pairing_setup = value;
	return 0;
}


int nan_pairing_set_npk_caching(struct nan_data *nan, bool value)
{
	wpa_printf(MSG_DEBUG, "NAN: SET: NPK caching: %d -> %d",
		   nan->cfg->pairing_cfg.npk_caching, value);
	nan->cfg->pairing_cfg.npk_caching = value;
	return 0;
}


int nan_pairing_set_pairing_verification(struct nan_data *nan, bool value)
{
	wpa_printf(MSG_DEBUG, "NAN: SET: Pairing verification: %d -> %d",
		   nan->cfg->pairing_cfg.pairing_verification, value);

	if (!nan->cfg->pairing_cfg.pairing_verification && value &&
	    nan_nira_get_tag_nonce(nan->cfg, nan->nira_nonce,
				   nan->nira_tag) < 0) {
		wpa_printf(MSG_INFO,
			   "NAN: Failed to enable pairing verification");
		return -1;
	}

	nan->cfg->pairing_cfg.pairing_verification = value;

	return 0;
}


int nan_pairing_set_cipher_suites(struct nan_data *nan, u32 value)
{
	if (value & ~(NAN_PAIRING_PASN_128 | NAN_PAIRING_PASN_256)) {
		wpa_printf(MSG_INFO,
			   "NAN: Pairing: Invalid cipher suites 0x%08x", value);
		return -1;
	}

	wpa_printf(MSG_DEBUG,
		   "NAN: SET: Pairing cipher suites: 0x%08x -> 0x%08x",
		   nan->cfg->pairing_cfg.cipher_suites, value);

	nan->cfg->pairing_cfg.cipher_suites = value;
	return 0;
}


int nan_pairing_set_pik_caching(struct nan_data *nan, bool value)
{
	wpa_printf(MSG_DEBUG, "NAN: SET: PIK caching: %d -> %d",
		   nan->cfg->pairing_cfg.pik_caching, value);
	nan->cfg->pairing_cfg.pik_caching = value;
	return 0;
}


int nan_pairing_set_extended_pkbst_method(struct nan_data *nan, u8 value)
{
	if (value & ~(NAN_PBEA_PKBST_ONE_WAY | NAN_PBEA_PKBST_MUTUAL))
		return -1;

	wpa_printf(MSG_DEBUG, "NAN: SET: PKBST methods: 0x%x -> 0x%x",
		   nan->cfg->pairing_cfg.extended_pkbst_method, value);
	nan->cfg->pairing_cfg.extended_pkbst_method = value;
	return 0;
}


int nan_pairing_set_nik(struct nan_data *nan, const u8 *nik, size_t nik_len)
{
	u8 nonce[NAN_NIRA_NONCE_LEN];
	u8 tag[NAN_NIRA_TAG_LEN];

	if (!nik || nik_len != NAN_NIK_LEN) {
		wpa_printf(MSG_INFO, "NAN: Pairing: Invalid NIK (len=%zu)",
			   nik_len);
		return -1;
	}

	os_memcpy(nan->cfg->nik, nik, NAN_NIK_LEN);

	if (nan->cfg->pairing_cfg.pairing_verification) {
		if (nan_nira_get_tag_nonce(nan->cfg, nonce, tag) < 0) {
			wpa_printf(MSG_INFO,
				   "NAN: Failed to set NIRA for new NIK");
			return -1;
		}
		os_memcpy(nan->nira_nonce, nonce, NAN_NIRA_NONCE_LEN);
		wpa_hexdump_key(MSG_DEBUG, "NAN: NIRA nonce",
				nan->nira_nonce, NAN_NIRA_NONCE_LEN);
		os_memcpy(nan->nira_tag, tag, NAN_NIRA_TAG_LEN);
		wpa_hexdump_key(MSG_DEBUG, "NAN: NIRA tag",
				nan->nira_tag, NAN_NIRA_TAG_LEN);
	} else {
		os_memset(nan->nira_nonce, 0, NAN_NIRA_NONCE_LEN);
		os_memset(nan->nira_tag, 0, NAN_NIRA_TAG_LEN);
	}

	wpa_hexdump_key(MSG_DEBUG, "NAN: New NIK", nan->cfg->nik, NAN_NIK_LEN);

	return 0;
}


int nan_pairing_set_nik_lifetime(struct nan_data *nan, u32 lifetime)
{
	if (!lifetime) {
		wpa_printf(MSG_INFO, "NAN: Pairing: Invalid NIK lifetime (%u)",
			   lifetime);
		return -1;
	}

	nan->cfg->nik_lifetime = lifetime;
	wpa_printf(MSG_DEBUG, "NAN: SET: NIK lifetime: %u seconds",
		   lifetime);
	return 0;
}


/* A provisioned record is a PKRA body holding exactly one record */
static int nan_pairing_parse_pkr_blob(const u8 *blob, size_t len,
				      struct nan_pkr *pkr)
{
	int res;

	if (!blob || len < 1 || blob[0] != 1) {
		wpa_printf(MSG_INFO,
			   "NAN: PKR blob must contain exactly one record");
		return -1;
	}

	res = nan_pkr_parse(blob + 1, len - 1, pkr);
	if (res < 0 || (size_t) res != len - 1) {
		wpa_printf(MSG_INFO, "NAN: Invalid PKR blob");
		return -1;
	}

	return 0;
}


/*
 * The IIK of the local record resolves Source NAN Tags and its GIKs resolve
 * Group NAN Tags (Wi-Fi Aware spec R5, Table 24), so keep them in the identity
 * key lists that tag generation and resolution use.
 */
static void nan_pairing_self_pkr_iks(struct nan_data *nan,
				     const struct nan_pkr *pkr, bool add)
{
	unsigned int i;

	if (!pkr->valid)
		return;

	if (add)
		nan_add_nik(nan, pkr->iik, NAN_NIK_TYPE_SELF, true);
	else
		nan_remove_nik(nan, pkr->iik, NAN_NIK_TYPE_SELF);
	for (i = 0; i < pkr->num_giks; i++) {
		if (add)
			nan_add_nik(nan, pkr->giks[i], NAN_NIK_TYPE_GROUP,
				    true);
		else
			nan_remove_nik(nan, pkr->giks[i], NAN_NIK_TYPE_GROUP);
	}
}


/**
 * nan_pairing_set_self_pkr - Install the local Public Key Record
 * @nan: NAN data
 * @blob: Number of PKRs (1) followed by one signed record
 * @len: Length of @blob
 * Returns: 0 on success, -1 on failure
 *
 * The current record is kept unless the new one parses and verifies.
 * Installing a record with a different IPK invalidates the configured ISK.
 */
int nan_pairing_set_self_pkr(struct nan_data *nan, const u8 *blob,
			     size_t len)
{
	struct nan_pkr pkr;

	if (!nan || nan_pairing_parse_pkr_blob(blob, len, &pkr) < 0)
		return -1;

	if (!nan->self_pkr.valid ||
	    os_memcmp(nan->self_pkr.ipk, pkr.ipk, NAN_IPK_LEN) != 0)
		os_memset(nan->self_isk, 0, sizeof(nan->self_isk));
	nan_pairing_self_pkr_iks(nan, &nan->self_pkr, false);
	nan->self_pkr = pkr;
	nan_pairing_self_pkr_iks(nan, &nan->self_pkr, true);
	wpa_printf(MSG_DEBUG, "NAN: Local PKR installed");
	return 0;
}


/* Default Valid Duration of a locally generated record: one week */
#define NAN_PKR_DEFAULT_VALID_DURATION (7 * 24 * 60)

/* Generate a P-256 key pair; the IPK is the compressed public point */
static int nan_pairing_gen_ipk(u8 *ipk, u8 *isk)
{
	struct crypto_ec_key *key;
	struct crypto_bignum *priv = NULL;
	struct wpabuf *spki = NULL;
	int ret = -1;

	key = crypto_ec_key_gen(19);
	if (!key)
		return -1;

	/* SubjectPublicKeyInfo ends with the compressed point */
	spki = crypto_ec_key_get_subject_public_key(key);
	priv = crypto_ec_key_get_private_key(key);
	if (!spki || wpabuf_len(spki) < NAN_IPK_LEN || !priv ||
	    crypto_bignum_to_bin(priv, isk, NAN_ISK_LEN, NAN_ISK_LEN) < 0)
		goto out;
	os_memcpy(ipk, wpabuf_head_u8(spki) + wpabuf_len(spki) - NAN_IPK_LEN,
		  NAN_IPK_LEN);
	if (ipk[0] != 0x02 && ipk[0] != 0x03)
		goto out;
	ret = 0;
out:
	crypto_bignum_deinit(priv, 1);
	wpabuf_free(spki);
	crypto_ec_key_deinit(key);
	return ret;
}


/**
 * nan_pairing_generate_self_pkr - Generate a new local Public Key Record
 * @nan: NAN data
 * Returns: 0 on success, -1 on failure
 *
 * A new key pair and IIK are generated. Operation Control, Valid Duration,
 * and the GIKs of the current record are kept, since group membership does
 * not change with the individual identity; the first record gets one random
 * GIK. The current record is replaced only if generation succeeds.
 */
int nan_pairing_generate_self_pkr(struct nan_data *nan)
{
	struct nan_pkr pkr;
	u8 isk[NAN_ISK_LEN];
	int ret = -1;

	if (!nan)
		return -1;

	os_memset(&pkr, 0, sizeof(pkr));
	if (nan->self_pkr.valid) {
		pkr.op_ctrl = nan->self_pkr.op_ctrl & ~NAN_PKR_OP_CTRL_REVOKED;
		pkr.valid_duration = nan->self_pkr.valid_duration;
		pkr.num_giks = nan->self_pkr.num_giks;
		os_memcpy(pkr.giks, nan->self_pkr.giks, sizeof(pkr.giks));
	}
	if (!pkr.valid_duration)
		pkr.valid_duration = NAN_PKR_DEFAULT_VALID_DURATION;
	if (!pkr.num_giks) {
		pkr.num_giks = 1;
		if (os_get_random(pkr.giks[0], NAN_GIK_LEN) < 0)
			goto out;
	}

	if (nan_pairing_gen_ipk(pkr.ipk, isk) < 0 ||
	    os_get_random(pkr.iik, NAN_IIK_LEN) < 0) {
		wpa_printf(MSG_INFO, "NAN: Failed to generate PKR keys");
		goto out;
	}
	pkr.valid = true;
	os_get_reltime(&pkr.created_at);

	nan_pairing_self_pkr_iks(nan, &nan->self_pkr, false);
	/* Keep the replaced record so that peers can be told to delete it */
	nan->old_self_pkr = nan->self_pkr;
	os_memcpy(nan->old_self_isk, nan->self_isk, NAN_ISK_LEN);
	nan->self_pkr = pkr;
	os_memcpy(nan->self_isk, isk, NAN_ISK_LEN);
	nan_pairing_self_pkr_iks(nan, &nan->self_pkr, true);
	wpa_printf(MSG_DEBUG, "NAN: Local PKR generated (GIKs=%u)",
		   pkr.num_giks);
	ret = 0;
out:
	forced_memzero(isk, sizeof(isk));
	return ret;
}


/**
 * nan_pairing_set_pkr_op_ctrl - Set Operation Control on the self PKR
 * @nan: NAN data
 * @op_ctrl: Operation Control value (NAN_PKR_CTRL_* bits)
 */
void nan_pairing_set_pkr_op_ctrl(struct nan_data *nan, u16 op_ctrl)
{
	if (!nan || !nan_pairing_is_pkr_usable(&nan->self_pkr))
		return;

	nan->self_pkr.op_ctrl = op_ctrl;
	nan->self_pkr.valid_duration =
		(op_ctrl & NAN_PKR_OP_CTRL_ONE_TIME_USE) ?
		5 : NAN_PKR_DEFAULT_VALID_DURATION;
}


/**
 * nan_pairing_get_self_pkr - Export the local Public Key Record
 * @nan: NAN data
 * Returns: Number of PKRs (1) followed by the signed record, or %NULL
 *
 * The export is what a peer is provisioned with. It is signed with the ISK
 * but never contains it, and it is only available when the ISK matching the
 * record is configured. The caller is responsible for freeing the returned
 * buffer.
 */
struct wpabuf * nan_pairing_get_self_pkr(struct nan_data *nan)
{
	static const u8 zero_isk[NAN_ISK_LEN];
	const struct nan_pkr *pkrs[1];
	const u8 *isks[1];
	struct wpabuf *buf;

	if (!nan || !nan_pairing_is_pkr_usable(&nan->self_pkr) ||
	    os_memcmp(nan->self_isk, zero_isk, NAN_ISK_LEN) == 0)
		return NULL;

	buf = wpabuf_alloc(1 + 2 + NAN_ELEMENT_MAX_SIZE);
	pkrs[0] = &nan->self_pkr;
	isks[0] = nan->self_isk;
	if (!buf || nan_pkra_encode(buf, pkrs, isks, 1) < 0) {
		wpabuf_free(buf);
		return NULL;
	}

	return buf;
}


/* The IIK of a peer record resolves the peer's Source NAN Tags */
static void nan_pairing_store_peer_pkr(struct nan_data *nan,
				       struct nan_pkr *dst,
				       const struct nan_pkr *pkr)
{
	if (dst->valid &&
	    os_memcmp(dst->iik, pkr->iik, NAN_IIK_LEN) != 0)
		nan_remove_nik(nan, dst->iik, NAN_NIK_TYPE_PEER);
	*dst = *pkr;
	nan_add_nik(nan, dst->iik, NAN_NIK_TYPE_PEER, true);
}


/**
 * nan_pairing_set_peer_pkr - Provision a peer Public Key Record
 * @nan: NAN data
 * @peer_addr: Peer NMI address or %NULL if the peer is not yet known
 * @blob: Number of PKRs (1) followed by one signed record
 * @len: Length of @blob
 * Returns: 0 on success, -1 on failure
 *
 * Without a known peer, the record is staged and applied to the next peer
 * that is added.
 */
int nan_pairing_set_peer_pkr(struct nan_data *nan, const u8 *peer_addr,
			     const u8 *blob, size_t len)
{
	struct nan_peer *peer = NULL;
	struct nan_pkr pkr;

	if (!nan || nan_pairing_parse_pkr_blob(blob, len, &pkr) < 0)
		return -1;

	if (peer_addr) {
		peer = nan_get_peer(nan, peer_addr);
		if (!peer) {
			wpa_printf(MSG_DEBUG, "NAN: Unknown peer " MACSTR,
				   MAC2STR(peer_addr));
			return -1;
		}
	}

	nan_pairing_store_peer_pkr(nan,
				   peer ? &peer->peer_pkr :
				   &nan->pending_peer_pkr, &pkr);
	wpa_printf(MSG_DEBUG, "NAN: Peer PKR %s",
		   peer ? "installed" : "staged for the next peer");
	return 0;
}


/**
 * nan_pairing_add_peer - Apply a staged peer Public Key Record
 * @nan: NAN data
 * @peer: Newly added peer
 *
 * The staged record belongs to a single peer, so it is moved rather than
 * copied. The identity key registered at staging time stays in place.
 */
void nan_pairing_add_peer(struct nan_data *nan, struct nan_peer *peer)
{
	if (!nan->pending_peer_pkr.valid || peer->peer_pkr.valid)
		return;

	peer->peer_pkr = nan->pending_peer_pkr;
	os_memset(&nan->pending_peer_pkr, 0, sizeof(nan->pending_peer_pkr));
	wpa_printf(MSG_DEBUG, "NAN: Staged PKR applied to peer " MACSTR,
		   MAC2STR(peer->nmi_addr));
}


/**
 * nan_pairing_set_self_isk - Set the Individual Secret Key of the local PKR
 * @nan: NAN data
 * @isk: P-256 private key
 * @len: Length of @isk; must be NAN_ISK_LEN
 * Returns: 0 on success, -1 on failure
 */
int nan_pairing_set_self_isk(struct nan_data *nan, const u8 *isk,
			     size_t len)
{
	if (!nan || !isk || len != NAN_ISK_LEN)
		return -1;

	os_memcpy(nan->self_isk, isk, NAN_ISK_LEN);
	return 0;
}


bool nan_pairing_is_peer_paired(struct nan_data *nan_data, const u8 *peer_addr)
{
	struct nan_peer *peer;

	peer = nan_get_peer(nan_data, peer_addr);
	if (!peer)
		return false;

	return !!(peer->pairing.flags & NAN_PAIRING_FLAG_PAIRED);
}


void nan_pairing_unpair_peer(struct nan_data *nan_data, const u8 *peer_addr)
{
	struct nan_peer *peer;

	peer = nan_get_peer(nan_data, peer_addr);
	if (!peer)
		return;

	wpa_printf(MSG_DEBUG, "NAN: Unpair peer " MACSTR,
		   MAC2STR(peer->nmi_addr));

	peer->pairing.flags &= ~NAN_PAIRING_FLAG_PAIRED;
	nan_cm_unpair_peer(nan_data, peer);
	nan_pairing_deinit_peer(nan_data, peer, true);
}


/*
 * nan_add_nika_attr - Add NIKA (NAN Identity Key attribute) to a buffer
 *
 * NIKA format: attr_id(1) + attr_len(2) + cipher_ver(1) + NIK(16) + lifetime(4)
 */
static int nan_add_nika_attr(struct wpabuf *buf, const u8 *nik, size_t nik_len,
			     u32 nik_lifetime)
{
	size_t attr_len;

	if (!buf || !nik || nik_len != NAN_NIK_LEN) {
		wpa_printf(MSG_INFO, "NAN: Invalid parameters for NIKA");
		return -1;
	}

	/* NIKA format: Cipher Version (1) + NIK (16) + Lifetime (4) */
	attr_len = 1 + nik_len + 4;

	if (wpabuf_tailroom(buf) < NAN_ATTR_HDR_LEN + attr_len) {
		wpa_printf(MSG_INFO, "NAN: Not enough room for NIKA");
		return -1;
	}

	wpabuf_put_u8(buf, NAN_ATTR_NIKA);
	wpabuf_put_le16(buf, attr_len);
	wpabuf_put_u8(buf, NAN_NIRA_CIPHER_VER_128);
	wpabuf_put_data(buf, nik, nik_len);
	wpabuf_put_be32(buf, nik_lifetime);

	wpa_hexdump_key(MSG_DEBUG, "NAN: NIKA - NIK", nik, nik_len);
	wpa_printf(MSG_DEBUG, "NAN: NIKA - Lifetime: %u seconds", nik_lifetime);

	return 0;
}


/*
 * nan_pairing_build_nika - Build NIKA-containing wrapped data for
 * PASN M2 (responder) or M3 (initiator).
 *
 * M2 (include_pairing_attrs=true): DCEA + CSIA + NIKA
 * M3 (include_pairing_attrs=false): NIKA only
 */
static struct wpabuf *
nan_pairing_build_nika(struct nan_data *nan_data, const struct nan_peer *peer,
		       bool include_pairing_attrs)
{
	struct wpabuf *buf;
	u8 *len_ptr;
	size_t initial_len;
	struct nan_cipher_suite cs;

	buf = wpabuf_alloc(512);
	if (!buf)
		return NULL;

	/* Start NAN element */
	wpabuf_put_u8(buf, WLAN_EID_VENDOR_SPECIFIC);
	len_ptr = wpabuf_put(buf, 1); /* placeholder for length */
	initial_len = wpabuf_len(buf);

	/* OUI + OUI Type for NAN */
	wpabuf_put_be32(buf, NAN_IE_VENDOR_TYPE);

	if (include_pairing_attrs) {
		/* M2 (responder): DCEA + CSIA + NIKA */
		nan_add_dev_capa_ext_attr(nan_data, buf);

		if (peer->pairing.pasn->cipher == WPA_CIPHER_GCMP_256)
			cs.csid = NAN_CS_PK_PASN_256;
		else
			cs.csid = NAN_CS_PK_PASN_128;
		cs.instance_id = peer->pairing.handle;
		nan_add_csia(buf, 0, 1, &cs);
	}

	/* NIKA (both M2 and M3) */
	if (nan_add_nika_attr(buf, nan_data->cfg->nik, NAN_NIK_LEN,
			      nan_data->cfg->nik_lifetime) < 0) {
		wpa_printf(MSG_INFO, "NAN: Failed to add NIKA");
		wpabuf_free(buf);
		return NULL;
	}

	/* Length covers the bytes written after the length byte itself. */
	*len_ptr = wpabuf_len(buf) - initial_len;

	wpa_hexdump_buf(MSG_DEBUG, "NAN: NIKA wrapped data (before encryption)",
			buf);
	return buf;
}


/**
 * Wi-Fi Aware spec R5, section 7.6.8: the Pairing Responder includes an FKCE in
 * PASN auth 2 whose KeyAuth is signed with the ISK of its record; in mutual
 * PKBST, the Pairing Initiator also includes one in PASN auth 3. The element is
 * appended to the extra elements of the next PASN Authentication frame.
 */
static int nan_pairing_add_fkce(struct nan_data *nan, struct nan_peer *peer)
{
	struct pasn_data *pasn = peer->pairing.pasn;
	bool responder =
		peer->pairing.self_pairing_role == NAN_PAIRING_ROLE_RESPONDER;
	const u8 *init_nmi, *resp_nmi;
	struct wpabuf *input, *key_auth = NULL, *ies = NULL;
	int ret = -1;

	if (!nan_pairing_pkbst_setup(peer) ||
	    (!responder && peer->bootstrap.pkbst_mode != NAN_PKBST_MODE_MUTUAL))
		return 0;

	init_nmi = responder ? peer->nmi_addr : nan->cfg->nmi_addr;
	resp_nmi = responder ? nan->cfg->nmi_addr : peer->nmi_addr;
	input = nan_crypto_build_fkce_input(&pasn->sae, nan->self_pkr.ipk,
					    init_nmi, resp_nmi, responder);
	if (input)
		key_auth = nan_crypto_compute_fkce(nan->self_isk, input);
	if (!key_auth || wpabuf_len(key_auth) > 254) {
		wpa_printf(MSG_INFO, "NAN: Pairing: Failed to build FKCE");
		goto out;
	}

	ies = wpabuf_alloc(pasn->extra_ies_len + 3 + wpabuf_len(key_auth));
	if (!ies)
		goto out;
	if (pasn->extra_ies_len)
		wpabuf_put_data(ies, pasn->extra_ies, pasn->extra_ies_len);
	wpabuf_put_u8(ies, WLAN_EID_EXTENSION);
	wpabuf_put_u8(ies, 1 + wpabuf_len(key_auth));
	wpabuf_put_u8(ies, WLAN_EID_EXT_FILS_KEY_CONFIRM);
	wpabuf_put_buf(ies, key_auth);
	ret = pasn_set_extra_ies(pasn, wpabuf_head(ies), wpabuf_len(ies));
	wpa_printf(MSG_DEBUG, "NAN: Pairing: FKCE added to PASN auth %d",
		   responder ? 2 : 3);
out:
	wpabuf_free(ies);
	wpabuf_free(key_auth);
	wpabuf_free(input);
	return ret;
}


/*
 * nan_pairing_prepare_data_element - PASN callback for pairing data
 *
 * For clustered responder pairing, install the NM-TK after PTK derivation and
 * before M2 transmission. For non-cluster pairing, prepare the encrypted NIKA
 * data element for M2 or M3.
 */
static int nan_pairing_prepare_data_element(void *ctx, const u8 *peer_addr)
{
	struct nan_data *nan_data = ctx;
	struct nan_peer *peer;
	struct pasn_data *pasn;
	struct wpabuf *wrapped_data = NULL;
	struct wpabuf *extra_ies = NULL;
	bool include_pairing_attrs, is_non_cluster;
	int ret = -1;

	if (!nan_data || !peer_addr)
		return -1;

	peer = nan_get_peer(nan_data, peer_addr);
	if (!peer || !peer->pairing.pasn)
		return -1;

	pasn = peer->pairing.pasn;
	is_non_cluster =
		nan_peer_no_shared_cluster(nan_data, peer->nmi_addr);
	include_pairing_attrs =
		peer->pairing.self_pairing_role == NAN_PAIRING_ROLE_RESPONDER;

	wpa_printf(MSG_DEBUG,
		   "NAN: prepare_data_element for peer " MACSTR
		   " (role: %s)",
		   MAC2STR(peer_addr),
		   include_pairing_attrs ? "responder" : "initiator");

	/* The NM-TK is not needed for non-cluster pairing. */
	if (!is_non_cluster &&
	    peer->pairing.self_pairing_role == NAN_PAIRING_ROLE_RESPONDER &&
	    !peer->pairing.nm_tk_installed && pasn->ptk.tk_len &&
	    nan_data->cfg->install_nm_tk) {
		if (nan_data->cfg->install_nm_tk(nan_data->cfg->cb_ctx,
						 peer->nmi_addr, pasn->cipher,
						 pasn->ptk.tk,
						 pasn->ptk.tk_len) == 0)
			peer->pairing.nm_tk_installed = true;
	}

	if (nan_pairing_add_fkce(nan_data, peer) < 0)
		return -1;

	if (!is_non_cluster)
		return 0;

	/* Responder (M2): DCEA+CSIA+NIKA; Initiator (M3): NIKA only */
	wrapped_data = nan_pairing_build_nika(nan_data, peer,
					      include_pairing_attrs);
	if (!wrapped_data)
		goto out;

	extra_ies = wpabuf_alloc(wpabuf_len(wrapped_data) + 100);
	if (!extra_ies)
		goto out;

	/* Prepend any existing extra IEs so they are not lost when the
	 * encrypted data element is appended.
	 */
	if (pasn->extra_ies && pasn->extra_ies_len) {
		struct wpabuf *combined;

		combined = wpabuf_alloc(pasn->extra_ies_len +
					wpabuf_len(wrapped_data) + 100);
		if (!combined)
			goto out;

		wpabuf_put_data(combined, pasn->extra_ies, pasn->extra_ies_len);
		wpabuf_free(extra_ies);
		extra_ies = combined;
	}

	ret = pasn_add_encrypted_data(pasn, extra_ies,
				      wpabuf_head(wrapped_data),
				      wpabuf_len(wrapped_data));
	if (ret < 0)
		goto out;

	ret = pasn_set_extra_ies(pasn, wpabuf_head(extra_ies),
				 wpabuf_len(extra_ies));
	if (ret < 0)
		goto out;

	wpa_printf(MSG_DEBUG,
		   "NAN: Successfully prepared encrypted NIKA data for %s",
		   include_pairing_attrs ? "M2 (responder)" : "M3 (initiator)");
	ret = 0;

out:
	wpabuf_clear_free(wrapped_data);
	wpabuf_free(extra_ies);
	return ret;
}


/*
 * nan_pairing_parse_nika - Parse NIKA from NAN element body
 * (after OUI+type, i.e., the NAN attributes area).
 */
static int nan_pairing_parse_nika(const u8 *data, size_t len, u8 *nik,
				  u32 *nik_lifetime)
{
	const u8 *pos = data;
	const u8 *end = data + len;

	while (pos + NAN_ATTR_HDR_LEN <= end) {
		u8 attr_id = *pos++;
		u16 attr_len = WPA_GET_LE16(pos);

		pos += 2;

		if (attr_len > end - pos) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Invalid attribute length in NIKA parsing");
			return -1;
		}

		if (attr_id == NAN_ATTR_NIKA) {
			/* NIKA: Cipher Version (1) + NIK (16) + Lifetime (4)
			 */
			if (attr_len < 1 + NAN_NIK_LEN + 4) {
				wpa_printf(MSG_DEBUG,
					   "NAN: NIKA too short: %u",
					   attr_len);
				return -1;
			}
			pos++; /* Skip cipher version */
			os_memcpy(nik, pos, NAN_NIK_LEN);
			pos += NAN_NIK_LEN;
			*nik_lifetime = WPA_GET_BE32(pos);

			wpa_hexdump_key(MSG_DEBUG, "NAN: Parsed NIKA - NIK",
					nik, NAN_NIK_LEN);
			wpa_printf(MSG_DEBUG,
				   "NAN: Parsed NIKA - Lifetime: %u seconds",
				   *nik_lifetime);
			return 0;
		}

		pos += attr_len;
	}

	wpa_printf(MSG_DEBUG, "NAN: NIKA not found");
	return -1;
}


/*
 * nan_pairing_parse_data_element - PASN callback to parse decrypted data
 * from M2 (initiator receives) or M3 (responder receives).
 * Only called for non-cluster peers.
 */
static int nan_pairing_parse_data_element(void *ctx, const u8 *data,
					  size_t len)
{
	struct nan_data *nan_data = ctx;
	struct nan_peer *peer = NULL;
	const u8 *pos = data;
	const u8 *end = data + len;
	u8 peer_nik[NAN_NIK_LEN];
	u32 nik_lifetime;
	bool found = false;

	if (!nan_data || !data || len == 0)
		return -1;

	wpa_hexdump(MSG_DEBUG, "NAN: parse_data_element: Decrypted data",
		    data, len);

	/* Find the peer with an active PASN session */
	dl_list_for_each(peer, &nan_data->peer_list, struct nan_peer, list) {
		if (peer->pairing.pasn &&
		    (peer->non_cluster || !nan_data->nan_started)) {
			found = true;
			break;
		}
	}

	if (!found) {
		wpa_printf(MSG_DEBUG,
			   "NAN: parse_data_element: No peer with active PASN");
		return -1;
	}

	/* Parse NAN element(s) from decrypted data */
	while (end - pos >= 2) {
		u8 eid = *pos++;
		u8 elen = *pos++;

		if (elen > end - pos) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Invalid element length in encrypted data");
			return -1;
		}

		if (eid == WLAN_EID_VENDOR_SPECIFIC && elen >= 4) {
			u32 oui_type = WPA_GET_BE32(pos);

			if (oui_type == NAN_IE_VENDOR_TYPE &&
			    nan_pairing_parse_nika(pos + 4, elen - 4, peer_nik,
						   &nik_lifetime) == 0) {
				os_memcpy(peer->pairing.peer_nik,
					  peer_nik, NAN_NIK_LEN);
				peer->pairing.peer_nik_valid = true;
				peer->pairing.peer_nik_lifetime = nik_lifetime;

				wpa_printf(MSG_DEBUG,
					   "NAN: Successfully parsed peer NIK from %s",
					   peer->pairing.self_pairing_role ==
					   NAN_PAIRING_ROLE_INITIATOR ?
					   "M2 (responder's NIK)" :
					   "M3 (initiator's NIK)");
				return 0;
			}
		}

		pos += elen;
	}

	wpa_printf(MSG_DEBUG, "NAN: Failed to find NIKA in encrypted data");
	return -1;
}


void nan_pairing_store_sae_pmkid(struct nan_data *nan_data, const u8 *addr)
{
	struct nan_peer *peer;

	peer = nan_get_peer(nan_data, addr);
	if (!peer) {
		wpa_printf(MSG_DEBUG,
			   "NAN: store_sae_pmkid: Peer " MACSTR " not found",
			   MAC2STR(addr));
		return;
	}

	if (!peer->pairing.pasn) {
		wpa_printf(MSG_DEBUG,
			   "NAN: store_sae_pmkid: No PASN context for " MACSTR,
			   MAC2STR(addr));
		return;
	}

	if (peer->pairing.pasn->akmp != WPA_KEY_MGMT_SAE) {
		wpa_printf(MSG_DEBUG,
			   "NAN: store_sae_pmkid: akmp=0x%x is not SAE, skipping",
			   peer->pairing.pasn->akmp);
		return;
	}

	wpa_hexdump(MSG_DEBUG, "NAN: store_sae_pmkid: SAE PMKID",
		    peer->pairing.pasn->sae.pmkid, PMKID_LEN);

	os_memcpy(peer->pairing.npkid, peer->pairing.pasn->sae.pmkid,
		  PMKID_LEN);
	peer->pairing.npkid_valid = true;
	wpa_printf(MSG_DEBUG,
		   "NAN: Pairing: Stored SAE PMKID for " MACSTR,
		   MAC2STR(addr));
}


/* Category, Action, OUI, OUI Type and OUI Subtype of a NAF */
#define NAN_PT_HDR_LEN (1 + 1 + 3 + 1 + 1)


/* First attribute with @id in a list of NAN attributes */
static const u8 * nan_pairing_find_attr(const u8 *pos, size_t len, u8 id)
{
	const u8 *end = pos + len;

	while (end - pos >= NAN_ATTR_HDR_LEN) {
		u16 attr_len = WPA_GET_LE16(pos + 1);

		if (end - pos - NAN_ATTR_HDR_LEN < attr_len)
			return NULL;
		if (pos[0] == id)
			return pos;
		pos += NAN_ATTR_HDR_LEN + attr_len;
	}
	return NULL;
}


struct nan_pt_rx {
	struct nan_data *nan;
	struct nan_peer *peer;
	unsigned int accepted;
};


/*
 * Wi-Fi Aware spec R5 draft v0.0.16, section 7.6.8: a revoked record asks the
 * recipient to delete the stored record with the same IPK and IIK; otherwise
 * the record replaces the one held for the peer.
 */
static int nan_pairing_rx_pt_pkr(void *ctx, const struct nan_pkr *pkr)
{
	struct nan_pt_rx *rx = ctx;
	struct nan_peer *peer = rx->peer;
	bool revoked = !!(pkr->op_ctrl & NAN_PKR_OP_CTRL_REVOKED);

	if (revoked) {
		if (!peer->peer_pkr.valid ||
		    os_memcmp(peer->peer_pkr.ipk, pkr->ipk, NAN_IPK_LEN) != 0 ||
		    os_memcmp(peer->peer_pkr.iik, pkr->iik, NAN_IIK_LEN) != 0)
			return 0;
		nan_remove_nik(rx->nan, peer->peer_pkr.iik, NAN_NIK_TYPE_PEER);
		os_memset(&peer->peer_pkr, 0, sizeof(peer->peer_pkr));
		wpa_printf(MSG_DEBUG, "NAN: PT: Peer PKR revoked");
	} else {
		if (!nan_pairing_is_pkr_usable(pkr))
			return 0;
		nan_pairing_store_peer_pkr(rx->nan, &peer->peer_pkr, pkr);
		wpa_printf(MSG_DEBUG, "NAN: PT: Peer PKR updated");
	}

	rx->accepted++;
	if (rx->nan->cfg->pkr_updated)
		rx->nan->cfg->pkr_updated(rx->nan->cfg->cb_ctx, peer->nmi_addr,
					  pkr->iik, revoked);
	return 0;
}


static void nan_pairing_send_pt_response(struct nan_data *nan,
					 struct nan_peer *peer, u8 token,
					 u8 status)
{
	struct wpabuf *buf;

	if (!nan->cfg->send_naf)
		return;
	buf = wpabuf_alloc(NAN_PT_HDR_LEN + NAN_ATTR_HDR_LEN + 3);
	if (!buf)
		return;

	wpabuf_put_u8(buf, WLAN_ACTION_PROTECTED_DUAL);
	wpabuf_put_u8(buf, WLAN_PA_VENDOR_SPECIFIC);
	wpabuf_put_be24(buf, OUI_WFA);
	wpabuf_put_u8(buf, NAN_NAF_OUI_TYPE);
	wpabuf_put_u8(buf, NAN_SUBTYPE_PROTECTED_TRANSPORT);
	wpabuf_put_u8(buf, NAN_ATTR_PTA);
	wpabuf_put_le16(buf, 3);
	wpabuf_put_u8(buf, token);
	wpabuf_put_u8(buf, 0); /* Attribute Control: no list of PT-TLVs */
	wpabuf_put_u8(buf, NAN_PTA_TYPE_RESPONSE |
		      (status << NAN_PTA_STATUS_SHIFT));
	nan->cfg->send_naf(nan->cfg->cb_ctx, peer->nmi_addr, NULL,
			   nan->cluster_id, buf);
	wpabuf_free(buf);
}


/**
 * nan_pairing_rx_pt - Process a received Protected Transport NAF
 * @nan: NAN data
 * @peer: Sending peer
 * @mgmt: Received frame; only protected frames reach this function
 * @len: Length of @mgmt
 * Returns: 0 on success, -1 on failure
 *
 * Wi-Fi Aware spec R5 draft v0.0.16, section 7.6.8 and Table 156: a request
 * carries a PTA with a nonzero Dialog Token and may carry a PKRA. Records are
 * accepted only from paired peers, and the request is answered with a
 * response PTA echoing the Dialog Token.
 */
int nan_pairing_rx_pt(struct nan_data *nan, struct nan_peer *peer,
		      const struct ieee80211_mgmt *mgmt, size_t len)
{
	const u8 *attrs = mgmt->u.action.u.naf.variable;
	size_t attrs_len = len - IEEE80211_MIN_ACTION_LEN(naf);
	const u8 *pta, *pkra;
	struct nan_pt_rx rx;
	u8 token, type;

	pta = nan_pairing_find_attr(attrs, attrs_len, NAN_ATTR_PTA);
	if (!pta || WPA_GET_LE16(pta + 1) < 3) {
		wpa_printf(MSG_DEBUG, "NAN: PT: Missing or invalid PTA");
		return -1;
	}
	token = pta[3];
	type = pta[5] & NAN_PTA_TYPE_MASK;

	if (type == NAN_PTA_TYPE_RESPONSE) {
		wpa_printf(MSG_DEBUG, "NAN: PT: Response (token %u status %u)",
			   token, pta[5] >> NAN_PTA_STATUS_SHIFT);
		return 0;
	}
	if (type != NAN_PTA_TYPE_REQUEST || !token) {
		wpa_printf(MSG_DEBUG, "NAN: PT: Unsupported PTA");
		return -1;
	}

	if (!nan_pairing_is_peer_paired(nan, peer->nmi_addr)) {
		wpa_printf(MSG_DEBUG, "NAN: PT: Peer not paired");
		nan_pairing_send_pt_response(nan, peer, token,
					     NAN_PTA_STATUS_REJECTED);
		return -1;
	}

	os_memset(&rx, 0, sizeof(rx));
	rx.nan = nan;
	rx.peer = peer;
	pkra = nan_pairing_find_attr(attrs, attrs_len, NAN_ATTR_PKRA);
	if (pkra)
		nan_pkra_parse(pkra + NAN_ATTR_HDR_LEN, WPA_GET_LE16(pkra + 1),
			       nan_pairing_rx_pt_pkr, &rx);

	nan_pairing_send_pt_response(nan, peer, token,
				     !pkra || rx.accepted ?
				     NAN_PTA_STATUS_ACCEPTED :
				     NAN_PTA_STATUS_REJECTED);
	return 0;
}


/**
 * nan_pairing_send_pkr_update - Send the local record to a paired peer
 * @nan: NAN data
 * @peer: Paired peer to receive the update
 * @send_revoked: Whether to also send the replaced record as revoked
 * Returns: 0 on success, -1 on failure
 *
 * Wi-Fi Aware spec R5 draft v0.0.16, section 7.6.8: records are sent through a
 * secured channel, here a Protected Transport request. A revoked record
 * has the Revoked bit set and a Valid Duration of zero, and is placed before
 * the record replacing it.
 */
int nan_pairing_send_pkr_update(struct nan_data *nan, struct nan_peer *peer,
				bool send_revoked)
{
	struct nan_pkr revoked;
	const struct nan_pkr *pkrs[2];
	const u8 *isks[2];
	unsigned int n = 0;
	struct wpabuf *buf;
	u8 *len_pos;
	int ret = -1;

	if (!nan || !peer ||
	    !nan_pairing_is_peer_paired(nan, peer->nmi_addr) ||
	    !nan_pairing_is_pkr_usable(&nan->self_pkr) ||
	    !nan->cfg->send_naf) {
		wpa_printf(MSG_DEBUG, "NAN: Cannot send PKR update");
		return -1;
	}

	if (send_revoked && nan->old_self_pkr.valid) {
		revoked = nan->old_self_pkr;
		revoked.op_ctrl |= NAN_PKR_OP_CTRL_REVOKED;
		revoked.valid_duration = 0;
		pkrs[n] = &revoked;
		isks[n++] = nan->old_self_isk;
	}
	pkrs[n] = &nan->self_pkr;
	isks[n++] = nan->self_isk;

	buf = wpabuf_alloc(NAN_PT_HDR_LEN + NAN_ATTR_HDR_LEN + 3 +
			   NAN_ATTR_HDR_LEN + 1 + n * NAN_PKR_MAX_LEN);
	if (!buf)
		return -1;
	wpabuf_put_u8(buf, WLAN_ACTION_PROTECTED_DUAL);
	wpabuf_put_u8(buf, WLAN_PA_VENDOR_SPECIFIC);
	wpabuf_put_be24(buf, OUI_WFA);
	wpabuf_put_u8(buf, NAN_NAF_OUI_TYPE);
	wpabuf_put_u8(buf, NAN_SUBTYPE_PROTECTED_TRANSPORT);

	wpabuf_put_u8(buf, NAN_ATTR_PTA);
	wpabuf_put_le16(buf, 3);
	wpabuf_put_u8(buf, nan_get_next_dialog_token(nan));
	wpabuf_put_u8(buf, 0); /* Attribute Control: no list of PT-TLVs */
	wpabuf_put_u8(buf, NAN_PTA_TYPE_REQUEST);

	wpabuf_put_u8(buf, NAN_ATTR_PKRA);
	len_pos = wpabuf_put(buf, 2);
	if (nan_pkra_encode(buf, pkrs, isks, n) < 0)
		goto out;
	WPA_PUT_LE16(len_pos, wpabuf_len(buf) -
		     (len_pos + 2 - wpabuf_head_u8(buf)));

	ret = nan->cfg->send_naf(nan->cfg->cb_ctx, peer->nmi_addr, NULL,
				 nan->cluster_id, buf);
	wpa_printf(MSG_DEBUG, "NAN: PKR update (%u records) to " MACSTR ": %d",
		   n, MAC2STR(peer->nmi_addr), ret);
out:
	wpabuf_free(buf);
	return ret;
}

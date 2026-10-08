/*
 * NAN Discovery Engine
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef NAN_DE_H
#define NAN_DE_H

#include "nan_defs.h"

/* Maximum number of active local publish and subscribe instances */
#ifndef NAN_DE_MAX_SERVICE
#define NAN_DE_MAX_SERVICE 20
#endif /* NAN_DE_MAX_SERVICE */

struct nan_de;

enum nan_de_reason {
	NAN_DE_REASON_TIMEOUT,
	NAN_DE_REASON_USER_REQUEST,
	NAN_DE_REASON_FAILURE,
};

struct nan_discovery_result {
	int subscribe_id;
	enum nan_service_protocol_type srv_proto_type;
	const u8 *ssi;
	size_t ssi_len;
	int peer_publish_id;
	const u8 *peer_addr;
	bool fsd;
	bool fsd_gas;
	bool data_path;
	bool security_required;
	const u8 *pmkid_list;
	unsigned int pmkid_count;
	const u8 *cipher_suites;
	unsigned int n_cipher_suites;
	bool pairing_setup_supp;
	bool npk_nik_caching_supp;
	u16 pbm;
	const u8 *orig_addr;
	const char *psi_locale;
	const char *psi_vendor_name;
	const char *psi_model_name;
	const char *psi_pairing_name;
};

struct nan_callbacks {
	void *ctx;

	int (*tx)(void *ctx, unsigned int freq, unsigned int wait_time,
		  const u8 *dst, const u8 *src, const u8 *bssid,
		  const struct wpabuf *buf, int handle);
	int (*listen)(void *ctx, unsigned int freq, unsigned int duration,
		      const u8 *forced_addr);

	/* NAN DE Events */
	void (*discovery_result)(void *ctx, struct nan_discovery_result *res);

	void (*replied)(void *ctx, int publish_id, const u8 *peer_addr,
			int peer_subscribe_id,
			enum nan_service_protocol_type srv_proto_type,
			const u8 *ssi, size_t ssi_len);

	void (*publish_terminated)(void *ctx, int publish_id,
				    enum nan_de_reason reason);

	void (*subscribe_terminated)(void *ctx, int subscribe_id,
				     enum nan_de_reason reason);

	void (*offload_cancel_publish)(void *ctx, int publish_id);
	void (*offload_cancel_subscribe)(void *ctx, int subscribe_id);

	void (*receive)(void *ctx, int id, int peer_instance_id,
			const u8 *ssi, size_t ssi_len,
			const u8 *peer_addr,
			const u8 *buf, size_t len);
	void (*rsia_get_rsids)(void *ctx, const u8 *service_id,
			       const u8 *irsa_tag_tlv,
			       u16 irsa_tag_tlv_len, u8 *rsid_num,
			       u8 **rsid_list, u8 *rsid_list_len,
			       bool is_unicast, bool *has_zero_rsid);
	struct dl_list * (*get_nik_list)(void *ctx, u8 tag_type);

	/**
	 * resolve_pntag - Resolve a Pairing NAN Tag of a paired peer
	 * @ctx: Callback context
	 * @peer_addr: NMI address the tag was derived with
	 * @nonce: Nonce from the IRSA
	 * @tag: Received NAN Tag
	 * @pik: Buffer for the matching Pairwise Identity Key
	 * Returns: true if a cached PIK produced @tag
	 */
	bool (*resolve_pntag)(void *ctx, const u8 *peer_addr, const u8 *nonce,
			      const u8 *tag, u8 *pik);

	int (*irsa_get_nonce_tag_tlv)(void *ctx, u8 *irsa_nonce,
				      u8 **irsa_tag_tlv, u16 *irsa_tag_tlv_len,
				      bool is_publisher);

	void (*process_p2p_usd_elems)(void *ctx, const u8 *buf,
				      u16 buf_len, const u8 *peer_addr,
				      unsigned int freq);

	void (*process_pr_usd_elems)(void *ctx, const u8 *buf,
				     u16 buf_len, const u8 *peer_addr,
				     unsigned int freq);
	void (*add_extra_attrs)(void *ctx, struct wpabuf *buf);
	bool (*is_peer_paired)(void *ctx, const u8 *addr);
	void (*transmit_req_status)(void *ctx, u32 cookie, bool ack);
};

extern const u8 nan_network_id[ETH_ALEN];
extern const u8 p2p_network_id[ETH_ALEN];

bool nan_de_is_nan_network_id(const u8 *addr);
bool nan_de_is_p2p_network_id(const u8 *addr);
const u8 * nan_de_get_attr(const u8 *buf, size_t len, enum nan_attr_id id,
			   unsigned int skip);
struct nan_de * nan_de_init(const u8 *nmi, bool offload, bool ap,
			    unsigned int max_listen,
			    const struct nan_callbacks *cb);
void nan_de_flush(struct nan_de *de);
void nan_de_deinit(struct nan_de *de);

void nan_de_listen_started(struct nan_de *de, unsigned int freq,
			   unsigned int duration);
void nan_de_listen_ended(struct nan_de *de, unsigned int freq);
void nan_de_update_nmi(struct nan_de *de, const u8 *nmi);
void nan_de_tx_status(struct nan_de *de, unsigned int freq, const u8 *dst,
		      const u8 *data, size_t data_len, bool ack);
void nan_de_tx_wait_ended(struct nan_de *de);

bool nan_de_rx_sdf(struct nan_de *de, const u8 *peer_addr, const u8 *a3,
		   unsigned int freq, const u8 *buf, size_t len, int rssi,
		   const u8 *orig_addr);
void nan_de_rx_beacon(struct nan_de *de, const u8 *peer_addr,
		      const u8 *cluster_id, const u8 *elems, size_t elems_len);
const u8 * nan_de_get_service_id(struct nan_de *de, int id);
struct wpabuf * nan_de_get_service_id_attrs(struct nan_de *de);

struct nan_publish_params {
	/* configuration_parameters */

	/* Publish type */
	bool unsolicited;
	bool solicited;

	/* Solicited transmission type */
	bool solicited_multicast;

	/* Time to live (in seconds); 0 = one TX only */
	unsigned int ttl;

	/* Event conditions */
	bool disable_events;

	/* When acting as a proxy */
	int orig_id;
	u8 orig_nmi[ETH_ALEN];

	/* Further Service Discovery flag */
	bool fsd;

	/* Further Service Discovery function */
	bool fsd_gas;

	/* Default frequency (defaultPublishChannel) */
	unsigned int freq;

	/* Multi-channel frequencies (publishChannelList) */
	const int *freq_list;

	/* Announcement period in ms; 0 = use default */
	unsigned int announcement_period;

	/* Proximity ranging flag */
	bool proximity_ranging;

	/* Synchronized discovery */
	bool sync;

	/* USD service willing to discover a synchronized peer */
	bool discover_sync;

	/*
	 * Null-terminated string containing the hex-encoded
	 * representation of the matching filters.
	 */
	const char *match_filter_tx;
	const char *match_filter_rx;

	/* RSSI range limit */
	bool close_proximity;

	/* Source MAC address for this service (optional) */
	const u8 *forced_addr;

	/* Randomize service ID for NAN services */
	bool randomize_service_id;

	/* Data Path Type flag (0=unicast, 1=multicast) */
	bool dp_type;

	/*
	 * Pairing Bootstrapping Methods as defined in Wi-Fi Aware spec v4.0,
	 * Table 128
	 */
	u16 pbm;

	/*
	 * Additional Pairing Bootstrapping Methods as defined for PBEA in
	 * Wi-Fi Aware specification R5
	 */
	u16 extended_pbm;

	/*
	 * Optional Pairing Setup Info field for PBEA as defined in Wi-Fi Aware
	 * specification R5
	 */
	u8 *pairing_setup_info;
	u16 pairing_setup_info_len;

	/* int_array of cipher suites */
	const int *cipher_suites_list;

	/* Bitmap of NAN_CS_INFO_CAPA_* */
	u8 security_capab;

	/* ND-PMK to use for creating a list of PMKIDs for the service */
	const u8 *nd_pmk;

	/*
	 * GTK protection required for group-addressed Data frames transmitted
	 * and received for the service
	 */
	bool gtk_required;

	/* Request NAN Data Path */
	bool data_path;

	bool security_required;
};

/* Returns -1 on failure or >0 publish_id */
int nan_de_publish(struct nan_de *de, const char *service_name,
		   enum nan_service_protocol_type srv_proto_type,
		   const struct wpabuf *ssi, const struct wpabuf *elems,
		   struct nan_publish_params *params, bool p2p,
		   const u8 *addr);

void nan_de_cancel_publish(struct nan_de *de, int publish_id);

int nan_de_update_publish(struct nan_de *de, int publish_id,
			  const struct wpabuf *ssi);

int nan_de_unpause_publish(struct nan_de *de, int publish_id,
			   u8 peer_instance_id, const u8 *peer_addr);

struct nan_subscribe_params {
	/* configuration_parameters */

	/* Subscribe type */
	bool active;

	/* Time to live (in seconds); 0 = until first result */
	unsigned int ttl;

	/* Selected frequency */
	unsigned int freq;

	/* Multi-channel frequencies (publishChannelList) */
	const int *freq_list;

	/* Query period in ms; 0 = use default */
	unsigned int query_period;

	/* Proximity ranging flag */
	bool proximity_ranging;

	/* Synchronized discovery */
	bool sync;

	/* USD service willing to discover a synchronized peer */
	bool discover_sync;

	/*
	 * Null-terminated string containing the hex-encoded
	 * representation of the matching filters.
	 */
	const char *match_filter_tx;
	const char *match_filter_rx;

	/* Service response filter include flag */
	bool srf_include;

	/* Service response filter MAC list */
	const char *srf_mac_list;

	/* Bloom filter length in octets. If 0, MAC list is used instead */
	u8 srf_bf_len;

	/* Bloom filter index (0-3) */
	u8 srf_bf_idx;

	/* RSSI range limit */
	bool close_proximity;

	/* Source MAC address for this service (optional) */
	const u8 *forced_addr;

	/*
	 * Pairing Bootstrapping Methods as defined in Wi-Fi Aware spec v4.0,
	 * Table 128
	 */
	u16 pbm;

	/*
	 * Additional Pairing Bootstrapping Methods as defined for PBEA in
	 * Wi-Fi Aware specification R5
	 */
	u16 extended_pbm;

	/*
	 * Optional Pairing Setup Info field for PBEA as defined in Wi-Fi Aware
	 * specification R5
	 */
	u8 *pairing_setup_info;
	u16 pairing_setup_info_len;

	/* int_array of cipher suites */
	const int *cipher_suites_list;

	/* Randomize service ID for NAN services */
	bool randomize_service_id;

	/* Data Path Required flag */
	bool dp_required;

	/* Data Path Type flag */
	bool dp_type;

	/* Security Required flag */
	bool security_required;

	/*
	 * GTK protection required for group-addressed Data frames transmitted
	 * and received for the service
	 */
	bool gtk_required;
};

/* Returns -1 on failure or >0 subscribe_id */
int nan_de_subscribe(struct nan_de *de, const char *service_name,
		     enum nan_service_protocol_type srv_proto_type,
		     const struct wpabuf *ssi, const struct wpabuf *elems,
		     struct nan_subscribe_params *params, bool p2p,
		     const u8 *addr);

void nan_de_cancel_subscribe(struct nan_de *de, int subscribe_id);

/* handle = publish_id or subscribe_id
 * req_instance_id = peer publish_id or subscribe_id */
int nan_de_transmit(struct nan_de *de, int handle,
		    const struct wpabuf *ssi, const struct wpabuf *elems,
		    const u8 *peer_addr, u8 req_instance_id,
		    const struct wpabuf *nan_attrs, u32 *cookie,
		    unsigned int peer_freq);

void nan_de_dw_trigger(struct nan_de *de, int freq);
void nan_de_set_cluster_id(struct nan_de *de, const u8 *cluster_id);
bool nan_de_is_valid_instance_id(struct nan_de *de, int handle,
				 bool publish, u8 *service_id);
u16 nan_de_get_service_bootstrap_methods(struct nan_de *de, int handle);
const int * nan_de_get_cipher_suites_list(struct nan_de *de, int handle);
bool nan_de_service_supports_csid(struct nan_de *de, int handle, int csid);
void nan_de_set_tx_mcast_follow_up_prot(struct nan_de *de, bool prot);
int nan_de_get_status(struct nan_de *de, char *buf, size_t buflen);

int nan_de_stop_listen(struct nan_de *de, int handle);
int nan_de_get_pbea_info(struct nan_de *de, int handle, u16 *extended_pbm,
			 const u8 **pairing_setup_info,
			 u16 *pairing_setup_info_len);
struct wpabuf * nan_build_pbea(u16 extended_pbm,
			       const u8 *pairing_setup_info,
			       u16 pairing_setup_info_len);

struct nan_de_cfg {
	/* N and M minimal and maximal values */
	u32 n_min, n_max;

	/* When not in pause state, stop the DE radio usage for 'suspend' ms
	 * every 'cycle' ms.
	 */
	u32 suspend, cycle;
};

int nan_de_config(struct nan_de *de, struct nan_de_cfg *cfg);

void nan_pairing_parse_setup_info(const u8 *info, size_t info_len,
				  char **locale, char **vendor_name,
				  char **model_name, char **pairing_name);

#endif /* NAN_DE_H */

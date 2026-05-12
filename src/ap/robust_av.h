/*
 * hostapd / DSCP Policy
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef ROBUST_AV_H
#define ROBUST_AV_H

struct hostapd_data;
struct sta_info;

#define CLASSIFIER_TYPE_4	4

/* Bit positions for classifier mask */
#define TCLAS_MASK_VERSION	BIT(0)
#define TCLAS_MASK_SRC_IP	BIT(1)
#define TCLAS_MASK_DST_IP	BIT(2)
#define TCLAS_MASK_SRC_PORT	BIT(3)
#define TCLAS_MASK_DST_PORT	BIT(4)
#define TCLAS_MASK_PROTOCOL	BIT(6)

#define IPV4_CLASSIFIER_LEN 18
#define IPV6_CLASSIFIER_LEN 44
/* Field sizes */
#define IPV4_ADDR_LEN	4
#define IPV6_ADDR_LEN	16
#define PORT_LEN	2
#define PROTOCOL_LEN	1
#define HEADER_LEN	3

#define MAX_DSCP_REQ_SIZE 1500

#define QM_ATTR_DSCP_POLICY_LEN 3

enum ip_version {
	IPV4 = 4,
	IPV6 = 6,
};


struct ipv4_params {
	struct in_addr src_ip;
	struct in_addr dst_ip;
	u16 src_port;
	u16 dst_port;
	u8 dscp;
	u8 protocol;
};


struct ipv6_params {
	struct in6_addr src_ip;
	struct in6_addr dst_ip;
	u16 src_port;
	u16 dst_port;
	u8 dscp;
	u8 next_header;
	u8 flow_label[3];
};


struct type4_params {
	u8 classifier_mask;
	enum ip_version ip_version;
	union {
		struct ipv4_params v4;
		struct ipv6_params v6;
	} ip_params;
};


struct hostapd_dscp_policy {
	u8 policy_id;  /* Unique Identifier */
	u8 req_type;
	u8 dscp;
	bool dscp_info;
	u8 *frame_classifier;
	u8 frame_classifier_len;
	struct type4_params type4_param;
	char *domain_name;
	u8 domain_name_len;
	u16 start_port;
	u16 end_port;
	bool port_range_info;
};

struct dscp_context {
	struct hostapd_data *hapd;
	struct sta_info *sta;
	u8 dialog_token;
	struct hostapd_dscp_policy **query_policy;
	unsigned int num_query_policies;
	struct hostapd_dscp_policy **req_policy;
	unsigned int num_req_policies;
	bool is_wildcard;
};


#ifdef CONFIG_ROBUST_AV

void hostapd_update_dscp_policy_capability(struct hostapd_data *hapd,
					   struct sta_info *sta,
					   const u8 *pos, size_t len);
void free_dscp_policies(struct sta_info *sta);

#else /* CONFIG_ROBUST_AV */

static inline void
hostapd_update_dscp_policy_capability(struct hostapd_data *hapd,
				      struct sta_info *sta,
				      const u8 *pos, size_t len)
{
}

static inline void free_dscp_policies(struct sta_info *sta)
{
}

#endif /* CONFIG_ROBUST_AV */

int validate_dscp_policy(struct hostapd_dscp_policy *policy);
void free_dscp_policy(struct hostapd_dscp_policy *policy);
int parse_dscp_policy_string(struct sta_info *sta,
			     struct hostapd_dscp_policy *policy,
			     const char *params);
int build_frame_classifier(struct hostapd_dscp_policy *policy);
int add_dscp_policy_to_sta(struct sta_info *sta,
			   const struct hostapd_dscp_policy *new_policy);
int hostapd_send_unsolicited_dscp_policy_request(struct hostapd_data *hapd,
						 struct sta_info *sta,
						 u8 reset,
						 const int *policy_ids,
						 unsigned int num_policies);
int hostapd_handle_dscp_policy_query(struct hostapd_data *hapd,
				     struct sta_info *sta,
				     const u8 *data, size_t len);

#endif /* ROBUST_AV_H */

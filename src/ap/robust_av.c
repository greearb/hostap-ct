/*
 * hostapd / DSCP Policy
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "hostapd.h"
#include "ieee802_11.h"
#include "sta_info.h"
#include "ap_config.h"
#include "ap_drv_ops.h"
#include "robust_av.h"


/*
 * Update DSCP policy capabilities for a STA based on the received Capabilities
 * field of a WFA Capabilities element.
 */
void hostapd_update_dscp_policy_capability(struct hostapd_data *hapd,
					   struct sta_info *sta,
					   const u8 *pos, size_t len)
{

	sta->flags &= ~WLAN_STA_DSCP_POLICY;

	if (!(sta->flags & WLAN_STA_MFP))
		return;

	if (!pos || len < 1)
		return;

	if (pos[0] & WFA_CAPA_QM_DSCP_POLICY) {
		sta->flags |= WLAN_STA_DSCP_POLICY;
		wpa_printf(MSG_DEBUG, "DSCP: STA " MACSTR
			   " supports DSCP Policy", MAC2STR(sta->addr));
	}
}


static int parse_ipv4_params(struct hostapd_dscp_policy *policy,
			     const char *token)
{
	if (os_strncmp(token, "dst_ip=", 7) == 0) {
		if (inet_pton(AF_INET, token + 7,
			      &policy->type4_param.ip_params.v4.dst_ip) <= 0)
			return -EINVAL;
	} else if (os_strncmp(token, "src_ip=", 7) == 0) {
		if (inet_pton(AF_INET, token + 7,
			      &policy->type4_param.ip_params.v4.src_ip) <= 0)
			return -EINVAL;
	} else if (os_strncmp(token, "dst_port=", 9) == 0) {
		policy->type4_param.ip_params.v4.dst_port = atoi(token + 9);
	} else if (os_strncmp(token, "src_port=", 9) == 0) {
		policy->type4_param.ip_params.v4.src_port = atoi(token + 9);
	} else if (os_strncmp(token, "protocol=", 9) == 0) {
		policy->type4_param.ip_params.v4.protocol = atoi(token + 9);
	}
	return 0;
}


static int parse_ipv6_params(struct hostapd_dscp_policy *policy,
			     const char *token)
{
	if (os_strncmp(token, "dst_ip=", 7) == 0) {
		if (inet_pton(AF_INET6, token + 7,
			      &policy->type4_param.ip_params.v6.dst_ip) <= 0)
			return -EINVAL;
	} else if (os_strncmp(token, "src_ip=", 7) == 0) {
		if (inet_pton(AF_INET6, token + 7,
			      &policy->type4_param.ip_params.v6.src_ip) <= 0)
			return -EINVAL;
	} else if (os_strncmp(token, "dst_port=", 9) == 0) {
		policy->type4_param.ip_params.v6.dst_port = atoi(token + 9);
	} else if (os_strncmp(token, "src_port=", 9) == 0) {
		policy->type4_param.ip_params.v6.src_port = atoi(token + 9);
	} else if (os_strncmp(token, "protocol=", 9) == 0) {
		policy->type4_param.ip_params.v6.next_header = atoi(token + 9);
	}

	return 0;
}


static int parse_dscp_value(struct hostapd_dscp_policy *policy,
			    const char *token)
{
	if (os_strncmp(token, "policy_id=", 10) == 0) {
		int policy_id = atoi(token + 10);

		if (policy_id > 0 && policy_id < 256) {
			policy->policy_id = policy_id;
		} else {
			wpa_printf(MSG_INFO, "Invalid policy id value: %d",
				   policy_id);
			return -EINVAL;
		}
	} else if (os_strncmp(token, "request_type=", 13) == 0) {
		const char *val = token + 13;

		if (os_strcasecmp(val, "add") == 0 ||
		    os_strcasecmp(val, "update") == 0) {
			policy->req_type = DSCP_POLICY_REQ_ADD;
		} else if (os_strcasecmp(val, "remove") == 0) {
			policy->req_type = DSCP_POLICY_REQ_REMOVE;
		} else {
			wpa_printf(MSG_INFO, "Invalid request_type: %s", val);
			return -EINVAL;
		}
	} else if (os_strncmp(token, "dscp=", 5) == 0) {
		unsigned long dscp = strtoul(token + 5, NULL, 0);

		if (dscp <= 63) {
			policy->dscp = dscp;
			policy->dscp_info = true;
		} else {
			wpa_printf(MSG_INFO, "Invalid DSCP value: %lu", dscp);
			return -EINVAL;
		}
	}

	return 0;
}


static int parse_domain_name(struct hostapd_dscp_policy *policy,
			     const char *token)
{
	const char *name;

	if (os_strncmp(token, "domain_name=", 12) == 0) {
		name = token + 12;
		if (os_strlen(name) <= 255) {
			os_free(policy->domain_name);
			policy->domain_name = os_strdup(name);
			if (!policy->domain_name)
				return -ENOMEM;
			policy->domain_name_len =
				os_strlen(policy->domain_name);
		} else {
			wpa_printf(MSG_INFO, "Domain name too long");
			return -EINVAL;
		}
	}
	return 0;
}


static int parse_port_range(struct hostapd_dscp_policy *policy,
			    const char *token)
{
	int port;

	if (os_strncmp(token, "start_port=", 11) == 0) {
		port = atoi(token + 11);
		if (port >= 0 && port <= 65535) {
			policy->start_port = port;
			policy->port_range_info = true;
		} else {
			wpa_printf(MSG_INFO, "Invalid start port: %d", port);
			return -EINVAL;
		}
	} else if (os_strncmp(token, "end_port=", 9) == 0) {
		port = atoi(token + 9);
		if (port >= 0 && port <= 65535) {
			policy->end_port = port;
			policy->port_range_info = true;
		} else {
			wpa_printf(MSG_INFO, "Invalid end port: %d", port);
			return -EINVAL;
		}
	}
	return 0;
}


int validate_dscp_policy(struct hostapd_dscp_policy *policy)
{
	if (!policy)
		return -1;

	if (policy->policy_id < 1) {
		wpa_printf(MSG_INFO, "DSCP Invalid policy_id");
		return -EINVAL;
	}

	/* Domain name + destination IP not allowed */
	if (policy->domain_name &&
	    (policy->type4_param.classifier_mask & TCLAS_MASK_DST_IP)) {
		wpa_printf(MSG_INFO,
			   "DSCP: Both domain name and destination IP address not expected");
		return -EINVAL;
	}

	/* Port range + Destination port not allowed */
	if ((policy->type4_param.classifier_mask & TCLAS_MASK_DST_PORT) &&
	    policy->port_range_info) {
		wpa_printf(MSG_INFO,
			   "DSCP: Both port range and destination port not expected");
		return -EINVAL;
	}
	return 0;
}


void free_dscp_policy(struct hostapd_dscp_policy *policy)
{
	if (!policy)
		return;
	os_free(policy->domain_name);
	policy->domain_name = NULL;
	os_free(policy->frame_classifier);
	policy->frame_classifier = NULL;
}


int parse_dscp_policy_string(struct sta_info *sta,
			     struct hostapd_dscp_policy *policy,
			     const char *params)
{
	char *token, *buf;
	char *context;
	int ret = 0;

	buf = os_strdup(params);
	if (!buf)
		return -1;

	os_memset(policy, 0, sizeof(*policy));
	context = buf;

	while ((token = str_token(buf, " ", &context))) {
		if (os_strncmp(token, "classifier_mask=", 16) == 0) {
			policy->type4_param.classifier_mask =
				strtoul(token + 16, NULL, 0);
		} else if (os_strncmp(token, "ip_version=", 11) == 0) {
			policy->type4_param.ip_version = atoi(token + 11);
		} else if (os_strncmp(token, "policy_id=", 10) == 0 ||
			   os_strncmp(token, "request_type=", 13) == 0 ||
			   os_strncmp(token, "dscp=", 5) == 0) {
			ret = parse_dscp_value(policy, token);
			if (ret < 0)
				break;
		} else if (os_strncmp(token, "domain_name=", 12) == 0) {
			ret = parse_domain_name(policy, token);
			if (ret < 0)
				break;
		} else if (os_strncmp(token, "start_port=", 11) == 0 ||
			   os_strncmp(token, "end_port=", 9) == 0) {
			ret = parse_port_range(policy, token);
			if (ret < 0)
				break;
		} else if (policy->type4_param.ip_version == 4) {
			ret = parse_ipv4_params(policy, token);
			if (ret < 0)
				break;
		} else if (policy->type4_param.ip_version == 6) {
			ret = parse_ipv6_params(policy, token);
			if (ret < 0)
				break;
		} else {
			wpa_printf(MSG_DEBUG,
				   "DSCP: Unknown attribute '%s' skipped",
				   token);
			ret = -EINVAL;
			break;
		}
	}

	os_free(buf);
	if (ret)
		free_dscp_policy(policy);
	return ret;
}


static int build_frame_classifier_type4_ipv4(struct hostapd_dscp_policy *policy)
{
	u8 *buf;
	u8 classifier_mask;
	size_t len = IPV4_CLASSIFIER_LEN;

	if (!policy)
		return -1;

	classifier_mask = policy->type4_param.classifier_mask;
	buf = os_zalloc(len);
	if (!buf)
		return -1;

	buf[0] = CLASSIFIER_TYPE_4;
	buf[1] = classifier_mask;
	buf[2] = IPV4;

	if (classifier_mask & TCLAS_MASK_SRC_IP)
		os_memcpy(&buf[3], &policy->type4_param.ip_params.v4.src_ip,
			  IPV4_ADDR_LEN);

	if (classifier_mask & TCLAS_MASK_DST_IP)
		os_memcpy(&buf[7], &policy->type4_param.ip_params.v4.dst_ip,
			  IPV4_ADDR_LEN);

	if (classifier_mask & TCLAS_MASK_SRC_PORT)
		WPA_PUT_BE16(&buf[11],
			     policy->type4_param.ip_params.v4.src_port);

	if (classifier_mask & TCLAS_MASK_DST_PORT)
		WPA_PUT_BE16(&buf[13],
			     policy->type4_param.ip_params.v4.dst_port);

	if (classifier_mask & TCLAS_MASK_PROTOCOL)
		buf[16] = policy->type4_param.ip_params.v4.protocol;

	os_free(policy->frame_classifier);
	policy->frame_classifier = buf;
	policy->frame_classifier_len = len;
	return 0;
}


static int build_frame_classifier_type4_ipv6(struct hostapd_dscp_policy *policy)
{
	u8 *buf;
	u8 classifier_mask;
	size_t len = IPV6_CLASSIFIER_LEN;

	if (!policy)
		return -EINVAL;

	classifier_mask = policy->type4_param.classifier_mask;
	buf = os_zalloc(len);
	if (!buf)
		return -ENOMEM;

	buf[0] = CLASSIFIER_TYPE_4;
	buf[1] = classifier_mask;
	buf[2] = IPV6;

	if (classifier_mask & TCLAS_MASK_SRC_IP)
		os_memcpy(&buf[3], &policy->type4_param.ip_params.v6.src_ip,
			  IPV6_ADDR_LEN);

	if (classifier_mask & TCLAS_MASK_DST_IP)
		os_memcpy(&buf[19], &policy->type4_param.ip_params.v6.dst_ip,
			  IPV6_ADDR_LEN);

	if (classifier_mask & TCLAS_MASK_SRC_PORT)
		WPA_PUT_BE16(&buf[35],
			     policy->type4_param.ip_params.v6.src_port);

	if (classifier_mask & TCLAS_MASK_DST_PORT)
		WPA_PUT_BE16(&buf[37],
			     policy->type4_param.ip_params.v6.dst_port);

	if (classifier_mask & TCLAS_MASK_PROTOCOL)
		buf[40] = policy->type4_param.ip_params.v6.next_header;

	os_free(policy->frame_classifier);
	policy->frame_classifier = buf;
	policy->frame_classifier_len = len;

	return 0;
}


int build_frame_classifier(struct hostapd_dscp_policy *policy)
{
	switch (policy->type4_param.ip_version) {
	case IPV4:
		return build_frame_classifier_type4_ipv4(policy);
	case IPV6:
		return build_frame_classifier_type4_ipv6(policy);
	default:
		wpa_printf(MSG_DEBUG, "IP version not specified");
		return 0;
	}
}


int add_dscp_policy_to_sta(struct sta_info *sta,
			   const struct hostapd_dscp_policy *new_policy)
{
	struct hostapd_dscp_policy **updated_policy_list;
	struct hostapd_dscp_policy *copy;
	unsigned int i;

	/* Check for existing policy_id and update */
	for (i = 0; i < sta->num_dscp_policies; i++) {
		struct hostapd_dscp_policy *existing = sta->policies[i];
		char *new_domain = NULL;
		u8 *new_fc = NULL;

		if (!existing || existing->policy_id != new_policy->policy_id)
			continue;

		wpa_printf(MSG_DEBUG, "DSCP: Updating policy ID %u for STA "
			   MACSTR, new_policy->policy_id, MAC2STR(sta->addr));
		if (new_policy->domain_name) {
			new_domain = os_strdup(new_policy->domain_name);
			if (!new_domain)
				return -ENOMEM;
		}

		if (new_policy->frame_classifier &&
		    new_policy->frame_classifier_len > 0) {
			new_fc = os_memdup(new_policy->frame_classifier,
					   new_policy->frame_classifier_len);
			if (!new_fc) {
				os_free(new_domain);
				return -ENOMEM;
			}
		}
		free_dscp_policy(existing);
		os_memcpy(existing, new_policy, sizeof(*existing));
		existing->domain_name = new_domain;
		existing->frame_classifier = new_fc;
		return 0;
	}

	copy = os_memdup(new_policy, sizeof(*copy));
	if (!copy)
		return -ENOMEM;

	copy->domain_name = NULL;
	copy->frame_classifier = NULL;

	if (new_policy->domain_name) {
		copy->domain_name = os_strdup(new_policy->domain_name);
		if (!copy->domain_name) {
			os_free(copy);
			return -ENOMEM;
		}
	}

	if (new_policy->frame_classifier &&
	    new_policy->frame_classifier_len > 0) {
		copy->frame_classifier =
			os_memdup(new_policy->frame_classifier,
				  new_policy->frame_classifier_len);
		if (!copy->frame_classifier) {
			free_dscp_policy(copy);
			os_free(copy);
			return -ENOMEM;
		}
	}

	updated_policy_list = os_realloc_array(sta->policies,
					       sta->num_dscp_policies + 1,
					       sizeof(*sta->policies));
	if (!updated_policy_list) {
		free_dscp_policy(copy);
		os_free(copy);
		return -1;
	}

	sta->policies = updated_policy_list;
	sta->policies[sta->num_dscp_policies++] = copy;

	return 0;
}


void free_dscp_policies(struct sta_info *sta)
{
	unsigned int i;

	if (!sta || !sta->policies)
		return;

	for (i = 0; i < sta->num_dscp_policies; i++) {
		free_dscp_policy(sta->policies[i]);
		os_free(sta->policies[i]);
	}

	os_free(sta->policies);
	sta->policies = NULL;
	sta->num_dscp_policies = 0;
}


static u8 get_next_unsolicited_dialog_token(struct sta_info *sta)
{
	sta->unsolicited_dialog_token++;
	if (sta->unsolicited_dialog_token == 0)
		sta->unsolicited_dialog_token = 1;
	return sta->unsolicited_dialog_token;
}


static struct hostapd_dscp_policy *
hostapd_get_dscp_policy_by_id(struct sta_info *sta, int id)
{
	unsigned int i;

	for (i = 0; i < sta->num_dscp_policies; i++) {
		if (sta->policies[i] && sta->policies[i]->policy_id == id)
			return sta->policies[i];
	}

	return NULL;
}


static struct wpabuf *
hostapd_build_qos_element(struct hostapd_dscp_policy *policy)
{
	struct wpabuf *elem;
	size_t domain_len;

	elem = wpabuf_alloc(512);
	if (!elem)
		return NULL;

	wpabuf_put_be32(elem, QM_IE_VENDOR_TYPE);
	wpabuf_put_u8(elem, QM_ATTR_DSCP_POLICY);
	wpabuf_put_u8(elem, QM_ATTR_DSCP_POLICY_LEN);
	wpabuf_put_u8(elem, policy->policy_id);
	wpabuf_put_u8(elem, policy->req_type);
	wpabuf_put_u8(elem, policy->req_type == DSCP_POLICY_REQ_REMOVE ?
		      255 : policy->dscp);

	if (policy->frame_classifier && policy->frame_classifier_len > 0) {
		wpabuf_put_u8(elem, QM_ATTR_TCLAS);
		wpabuf_put_u8(elem, policy->frame_classifier_len);
		wpabuf_put_data(elem, policy->frame_classifier,
				policy->frame_classifier_len);
	}

	if (policy->domain_name) {
		domain_len = os_strlen(policy->domain_name);
		if (domain_len < 256) {
			wpabuf_put_u8(elem, QM_ATTR_DOMAIN_NAME);
			wpabuf_put_u8(elem, domain_len);
			wpabuf_put_data(elem, policy->domain_name, domain_len);
		}
	}

	if (policy->port_range_info) {
		wpabuf_put_u8(elem, QM_ATTR_PORT_RANGE);
		wpabuf_put_u8(elem, 4);
		wpabuf_put_be16(elem, policy->start_port);
		wpabuf_put_be16(elem, policy->end_port);
	}

	return elem;
}


static struct wpabuf * new_dscp_policy_req_frame(struct hostapd_data *hapd,
						 struct sta_info *sta,
						 u8 dialog_token,
						 u8 reset, u8 more)
{
	u8 request_control = 0;
	struct wpabuf *frame;

	frame = wpabuf_alloc(MAX_DSCP_REQ_SIZE);
	if (!frame)
		return NULL;

	wpabuf_put_u8(frame, WLAN_ACTION_VENDOR_SPECIFIC_PROTECTED);
	wpabuf_put_be32(frame, QM_ACTION_VENDOR_TYPE);
	wpabuf_put_u8(frame, QM_DSCP_POLICY_REQ);
	wpabuf_put_u8(frame, dialog_token);

	if (reset)
		request_control |= DSCP_POLICY_CTRL_RESET;
	if (more)
		request_control |= DSCP_POLICY_CTRL_MORE;

	wpabuf_put_u8(frame, request_control);

	return frame;
}


int hostapd_send_unsolicited_dscp_policy_request(struct hostapd_data *hapd,
						 struct sta_info *sta,
						 u8 reset,
						 const int *policy_ids,
						 unsigned int num_policies)
{
	struct wpabuf *frame = NULL;
	u8 dialog_token;
	size_t i;
	size_t frame_len;
	bool more = false;

	/* TODO: When sending a request, if this is not a resync (reset == 0),
	 * start a response timer bound to dialog_token. If no DSCP Policy
	 * Response frame with the same token is received before timeout, set a
	 * per-STA flag (e.g, sta->dscp_state.force_reset = 1). The next time
	 * this function is called for this STA, force reset = 1 and include all
	 * policies relevant to the STA to resynchronize state.
	 */

	if (!(sta->flags & WLAN_STA_DSCP_POLICY))
		return -1;

	dialog_token = get_next_unsolicited_dialog_token(sta);
	frame = new_dscp_policy_req_frame(hapd, sta, dialog_token, reset, more);
	if (!frame)
		return -1;

	frame_len = wpabuf_len(frame);

	for (i = 0; i < num_policies; i++) {
		struct hostapd_dscp_policy *policy;
		struct wpabuf *elem;

		policy = hostapd_get_dscp_policy_by_id(sta, policy_ids[i]);
		if (!policy)
			continue;

		if (reset && policy->req_type == DSCP_POLICY_REQ_REMOVE)
			continue;

		elem = hostapd_build_qos_element(policy);
		if (!elem)
			continue;

		if (frame_len + 2 + wpabuf_len(elem) > MAX_DSCP_REQ_SIZE) {
			more = true;
			wpabuf_free(elem);
			break;
		}

		wpabuf_put_u8(frame, WLAN_EID_VENDOR_SPECIFIC);
		wpabuf_put_u8(frame, wpabuf_len(elem));
		wpabuf_put_buf(frame, elem);
		wpabuf_free(elem);
		frame_len = wpabuf_len(frame);
	}

	if (more) {
		u8 *buf = wpabuf_mhead_u8(frame);

		buf[7] |= DSCP_POLICY_CTRL_MORE;
	}

	/* Only send if the frame contains at least one QoS element beyond the
	 * header */
	if (frame && wpabuf_len(frame) > 5 &&
	    hostapd_drv_send_action(hapd, hapd->iface->freq, 0, sta->addr,
				    wpabuf_head(frame), wpabuf_len(frame))) {
		wpa_printf(MSG_DEBUG, "DSCP: Failed to send policy request to "
			   MACSTR, MAC2STR(sta->addr));
		wpabuf_free(frame);
		return -1;
	}

	wpabuf_free(frame);

	sta->dscp_state.offset = i;
	sta->dscp_state.last_dialog_token = dialog_token;
	sta->dscp_state.pending_more = more;
	return 0;
}


static bool is_valid_qm_elem(const u8 *ie, size_t rem_len)
{
	return ie && rem_len >= 6 &&
		ie[0] == WLAN_EID_VENDOR_SPECIFIC && ie[1] >= 4 &&
		WPA_GET_BE32(&ie[2]) == QM_IE_VENDOR_TYPE;
}


static int set_frame_classifier_type4_ipv4(struct hostapd_dscp_policy *policy)
{
	u8 classifier_mask;
	const u8 *frame_classifier = policy->frame_classifier;
	struct type4_params *type4_param = &policy->type4_param;

	if (policy->frame_classifier_len < IPV4_CLASSIFIER_LEN) {
		wpa_printf(MSG_INFO,
			   "QM: Received IPv4 frame classifier with insufficient length %d",
			   policy->frame_classifier_len);
		return -1;
	}

	classifier_mask = frame_classifier[1];

	/* Classifier Mask - bit 1 = Source IP Address */
	if (classifier_mask & TCLAS_MASK_SRC_IP) {
		type4_param->classifier_mask |= TCLAS_MASK_SRC_IP;
		os_memcpy(&type4_param->ip_params.v4.src_ip,
			  &frame_classifier[3], IPV4_ADDR_LEN);
	}

	/* Classifier Mask - bit 2 = Destination IP Address */
	if (classifier_mask & TCLAS_MASK_DST_IP) {
		if (policy->domain_name) {
			wpa_printf(MSG_INFO,
				   "QM: IPv4: Both domain name and destination IP address not expected");
			return -1;
		}

		type4_param->classifier_mask |= TCLAS_MASK_DST_IP;
		os_memcpy(&type4_param->ip_params.v4.dst_ip,
			  &frame_classifier[7], IPV4_ADDR_LEN);
	}

	/* Classifier Mask - bit 3 = Source Port */
	if (classifier_mask & TCLAS_MASK_SRC_PORT) {
		type4_param->classifier_mask |= TCLAS_MASK_SRC_PORT;
		type4_param->ip_params.v4.src_port =
			WPA_GET_BE16(&frame_classifier[11]);
	}

	/* Classifier Mask - bit 4 = Destination Port */
	if (classifier_mask & TCLAS_MASK_DST_PORT) {
		if (policy->port_range_info) {
			wpa_printf(MSG_INFO,
				   "QM: IPv4: Both port range and destination port not expected");
			return -1;
		}

		type4_param->classifier_mask |= TCLAS_MASK_DST_PORT;
		type4_param->ip_params.v4.dst_port =
			WPA_GET_BE16(&frame_classifier[13]);
	}

	/* Classifier Mask - bit 5 = DSCP (ignored) */

	/* Classifier Mask - bit 6 = Protocol */
	if (classifier_mask & TCLAS_MASK_PROTOCOL) {
		type4_param->classifier_mask |= TCLAS_MASK_PROTOCOL;
		type4_param->ip_params.v4.protocol = frame_classifier[16];
	}

	return 0;
}


static int set_frame_classifier_type4_ipv6(struct hostapd_dscp_policy *policy)
{
	u8 classifier_mask;
	const u8 *frame_classifier = policy->frame_classifier;
	struct type4_params *type4_param = &policy->type4_param;

	if (policy->frame_classifier_len < IPV6_CLASSIFIER_LEN) {
		wpa_printf(MSG_INFO,
			   "QM: Received IPv6 frame classifier with insufficient length %d",
			   policy->frame_classifier_len);
		return -1;
	}

	classifier_mask = frame_classifier[1];

	/* Classifier Mask - bit 1 = Source IP Address */
	if (classifier_mask & TCLAS_MASK_SRC_IP) {
		type4_param->classifier_mask |= TCLAS_MASK_SRC_IP;
		os_memcpy(&type4_param->ip_params.v6.src_ip,
			  &frame_classifier[3], IPV6_ADDR_LEN);
	}

	/* Classifier Mask - bit 2 = Destination IP Address */
	if (classifier_mask & TCLAS_MASK_DST_IP) {
		if (policy->domain_name) {
			wpa_printf(MSG_INFO,
				   "QM: IPv6: Both domain name and destination IP address not expected");
			return -1;
		}
		type4_param->classifier_mask |= TCLAS_MASK_DST_IP;
		os_memcpy(&type4_param->ip_params.v6.dst_ip,
			  &frame_classifier[19], IPV6_ADDR_LEN);
	}

	/* Classifier Mask - bit 3 = Source Port */
	if (classifier_mask & TCLAS_MASK_SRC_PORT) {
		type4_param->classifier_mask |= TCLAS_MASK_SRC_PORT;
		type4_param->ip_params.v6.src_port =
			WPA_GET_BE16(&frame_classifier[35]);
	}

	/* Classifier Mask - bit 4 = Destination Port */
	if (classifier_mask & TCLAS_MASK_DST_PORT) {
		if (policy->port_range_info) {
			wpa_printf(MSG_INFO,
				   "IPv6: Both port range and destination port not expected");
			return -1;
		}

		type4_param->classifier_mask |= TCLAS_MASK_DST_PORT;
		type4_param->ip_params.v6.dst_port =
			WPA_GET_BE16(&frame_classifier[37]);
	}

	/* Classifier Mask - bit 5 = DSCP (ignored) */

	/* Classifier Mask - bit 6 = Next Header */
	if (classifier_mask & BIT(6)) {
		type4_param->classifier_mask |= BIT(6);
		type4_param->ip_params.v6.next_header = frame_classifier[40];
	}

	return 0;
}


static int ap_set_frame_classifier_params(struct hostapd_dscp_policy *policy)
{
	const u8 *frame_classifier = policy->frame_classifier;
	u8 frame_classifier_len = policy->frame_classifier_len;

	if (frame_classifier_len < 3) {
		wpa_printf(MSG_INFO,
			   "QM: Received frame classifier with insufficient length %d",
			   frame_classifier_len);
		return -1;
	}

	/* Only allowed Classifier Type: IP and higher layer parameters (4) */
	if (frame_classifier[0] != CLASSIFIER_TYPE_4) {
		wpa_printf(MSG_INFO,
			   "QM: Received frame classifier with invalid classifier type %d",
			   frame_classifier[0]);
		return -1;
	}

	/* Classifier Mask - bit 0 = Version */
	if (!(frame_classifier[1] & TCLAS_MASK_VERSION)) {
		wpa_printf(MSG_INFO,
			   "QM: Received frame classifier without IP version");
		return -1;
	}

	/* Version (4 or 6) */
	if (frame_classifier[2] == IPV4) {
		if (set_frame_classifier_type4_ipv4(policy)) {
			wpa_printf(MSG_INFO,
				   "QM: Failed to set IPv4 parameters");
			return -1;
		}

		policy->type4_param.ip_version = IPV4;
	} else if (frame_classifier[2] == IPV6) {
		if (set_frame_classifier_type4_ipv6(policy)) {
			wpa_printf(MSG_INFO,
				   "QM: Failed to set IPv6 parameters");
			return -1;
		}

		policy->type4_param.ip_version = IPV6;
	} else {
		wpa_printf(MSG_INFO, "QM: Received unknown IP version %d",
			   frame_classifier[2]);
		return -1;
	}

	return 0;
}


static int hostapd_parse_query_elements(struct hostapd_dscp_policy *query,
					u8 attr_id, u8 attr_len,
					const u8 *attr_data)
{
	switch (attr_id) {
	case QM_ATTR_PORT_RANGE:
		if (attr_len < 4) {
			wpa_printf(MSG_INFO,
				   "DSCP: Received Port Range attribute with insufficient length %d",
				   attr_len);
			return -EINVAL;
		}
		if (query->port_range_info) {
			wpa_printf(MSG_INFO,
				   "DSCP Policy: Duplicate Port Range");
			return -EINVAL;
		}
		query->start_port = WPA_GET_BE16(attr_data);
		query->end_port = WPA_GET_BE16(attr_data + 2);
		query->port_range_info = true;
		break;
	case QM_ATTR_TCLAS:
		if (attr_len < 1) {
			wpa_printf(MSG_INFO,
				   "DSCP: Received TCLAS attribute with insufficient length %d",
				   attr_len);
			return -EINVAL;
		}
		if (query->frame_classifier) {
			wpa_printf(MSG_DEBUG, "DSCP Policy: Duplicate TCLAS");
			return -EINVAL;
		}
		query->frame_classifier = (u8 *) attr_data;
		query->frame_classifier_len = attr_len;

		if (ap_set_frame_classifier_params(query)) {
			wpa_printf(MSG_INFO,
				   "DSCP: Failed to set frame classifier parameters");
			return -EINVAL;
		}
		break;
	case QM_ATTR_DOMAIN_NAME:
		if (attr_len < 1) {
			wpa_printf(MSG_INFO,
				   "DSCP: Received domain name attribute with insufficient length %d",
				   attr_len);
			return -EINVAL;
		}
		if (query->domain_name) {
			wpa_printf(MSG_DEBUG,
				   "DSCP Policy: Duplicate Domain Name");
			return -EINVAL;
		}
		query->domain_name = (char *) attr_data;
		query->domain_name_len = attr_len;
		break;
	default:
		break;
	}
	return 0;
}


static int parse_single_policy(const u8 *ie, size_t ie_len,
			       struct hostapd_dscp_policy **el_out,
			       unsigned int index)
{
	const u8 *attr;
	int rem_attrs;
	struct hostapd_dscp_policy *el;

	if (!ie || ie_len < 6 || ie[1] < 4)
		return -EINVAL;

	el = os_zalloc(sizeof(*el));
	if (!el)
		return -ENOMEM;

	attr = ie + 6;
	rem_attrs = ie[1] - 4;

	while (rem_attrs >= 2 && rem_attrs >= 2 + attr[1]) {
		u8 id = attr[0];

		if (id == QM_ATTR_DSCP_POLICY) {
			wpa_printf(MSG_INFO,
				   "DSCP Query: DSCP Policy attribute not allowed");
			os_free(el);
			return -EINVAL;
		}

		if (hostapd_parse_query_elements(el, attr[0], attr[1],
						 &attr[2])) {
			os_free(el);
			return -EINVAL;
		}

		rem_attrs -= 2 + attr[1];
		attr += 2 + attr[1];
	}

	*el_out = el;
	return 0;
}


static int parse_dscp_query(const u8 *data, size_t len,
			    struct dscp_context *ctx)
{
	const u8 *pos, *end;
	struct hostapd_dscp_policy **parsed;
	unsigned int count = 0, i = 0, j;
	int ie_len;

	if (!data || len < 1 || !ctx)
		return -EINVAL;

	pos = data + 1;
	end = data + len;

	ctx->dialog_token = data[0];

	if (ctx->dialog_token == 0) {
		wpa_printf(MSG_INFO, "DSCP: Invalid dialog_token in query");
		return -EINVAL;
	}

	/* First pass: count valid elements */
	while (end - pos >= 2) {
		ie_len = 2 + pos[1];
		if (end - pos < ie_len)
			break;

		if (is_valid_qm_elem(pos, ie_len))
			count++;

		pos += ie_len;
	}

	if (count == 0) {
		ctx->is_wildcard = true;
		return 0;
	}

	parsed = os_calloc(count, sizeof(*parsed));
	if (!parsed)
		return -ENOMEM;

	/* Second pass: parse and populate */
	pos = data + 1;
	while (end - pos >= 2 && i < count) {
		ie_len = 2 + pos[1];
		if (end - pos < ie_len)
			break;

		if (!is_valid_qm_elem(pos, ie_len)) {
			pos += ie_len;
			continue;
		}

		if (parse_single_policy(pos, ie_len, &parsed[i], i) != 0)
			goto error;
		i++;

		pos += ie_len;
	}

	ctx->query_policy = parsed;
	ctx->num_query_policies = i;
	return 0;

error:
	for (j = 0; j < i; j++)
		os_free(parsed[j]);
	os_free(parsed);
	return -1;
}


static bool match_ipv4_classifier(const struct type4_params *query,
				  const struct type4_params *policy)
{
	if ((query->classifier_mask & TCLAS_MASK_SRC_IP) &&
	    os_memcmp(&query->ip_params.v4.src_ip,
		      &policy->ip_params.v4.src_ip, 4) != 0)
		return false;

	if ((query->classifier_mask & TCLAS_MASK_DST_IP) &&
	    os_memcmp(&query->ip_params.v4.dst_ip,
		      &policy->ip_params.v4.dst_ip, 4) != 0)
		return false;

	if ((query->classifier_mask & TCLAS_MASK_SRC_PORT) &&
	    query->ip_params.v4.src_port != policy->ip_params.v4.src_port)
		return false;

	if ((query->classifier_mask & TCLAS_MASK_DST_PORT) &&
	    query->ip_params.v4.dst_port != policy->ip_params.v4.dst_port)
		return false;

	if ((query->classifier_mask & TCLAS_MASK_PROTOCOL) &&
	    query->ip_params.v4.protocol != policy->ip_params.v4.protocol)
		return false;

	return true;
}


static bool match_ipv6_classifier(const struct type4_params *query,
				  const struct type4_params *policy)
{
	if ((query->classifier_mask & TCLAS_MASK_SRC_IP) &&
	    os_memcmp(&query->ip_params.v6.src_ip,
		      &policy->ip_params.v6.src_ip, 16) != 0)
		return false;

	if ((query->classifier_mask & TCLAS_MASK_DST_IP) &&
	    os_memcmp(&query->ip_params.v6.dst_ip,
		      &policy->ip_params.v6.dst_ip, 16) != 0)
		return false;

	if ((query->classifier_mask & TCLAS_MASK_SRC_PORT) &&
	    query->ip_params.v6.src_port != policy->ip_params.v6.src_port)
		return false;

	if ((query->classifier_mask & TCLAS_MASK_DST_PORT) &&
	    query->ip_params.v6.dst_port != policy->ip_params.v6.dst_port)
		return false;

	if ((query->classifier_mask & BIT(6)) &&
	    query->ip_params.v6.next_header != policy->ip_params.v6.next_header)
		return false;

	return true;
}


static bool match_type4_classifier(const struct type4_params *query,
				   const struct type4_params *policy,
				   u8 ip_version)
{
	if (query->classifier_mask != policy->classifier_mask)
		return false;

	switch (ip_version) {
	case IPV4:
		if (!match_ipv4_classifier(query, policy))
			return false;
		break;
	case IPV6:
		if (!match_ipv6_classifier(query, policy))
			return false;
		break;
	default:
		return false;
	}

	return true;
}


static int policy_matches_query(struct dscp_context *ctx)
{
	struct hostapd_dscp_policy *policy, *query;
	struct hostapd_dscp_policy **tmp;
	unsigned int max_policies = 0, i, j;

	ctx->num_req_policies = 0;
	ctx->req_policy = NULL;

	/* Wildcard query: match all policies for the STA */
	if (ctx->is_wildcard) {
		max_policies = ctx->sta->num_dscp_policies;
		ctx->req_policy = os_calloc(max_policies,
					    sizeof(*ctx->req_policy));
		if (!ctx->req_policy)
			return 0;

		for (j = 0; j < max_policies; j++) {
			policy = ctx->sta->policies[j];
			ctx->req_policy[ctx->num_req_policies++] = policy;
		}
		return ctx->num_req_policies;
	}

	for (i = 0; i < ctx->num_query_policies; i++) {
		query = ctx->query_policy[i];

		for (j = 0; j < ctx->sta->num_dscp_policies; j++) {
			bool match = false;

			policy = ctx->sta->policies[j];

			/* Match port range */
			if (query->port_range_info && policy->port_range_info) {
				if (policy->start_port <= query->end_port &&
				    policy->end_port >= query->start_port)
					match = true;
			}


			if (!match && query->domain_name &&
			    policy->domain_name &&
			    query->domain_name_len == policy->domain_name_len &&
			    os_memcmp(query->domain_name, policy->domain_name,
				      query->domain_name_len) == 0)
				match = true;

			if (!match && query->frame_classifier &&
			    policy->frame_classifier) {
				u8 ip_version = query->type4_param.ip_version;
				u8 classifier_mask =
					query->type4_param.classifier_mask;

				if (ip_version ==
				    policy->type4_param.ip_version &&
				    classifier_mask ==
				    policy->type4_param.classifier_mask &&
				    match_type4_classifier(&query->type4_param,
							   &policy->type4_param,
							   ip_version))
					match = true;
			}

			if (!match)
				continue;

			tmp = os_realloc_array(ctx->req_policy,
					       ctx->num_req_policies + 1,
					       sizeof(*ctx->req_policy));
			if (!tmp)
				continue;

			ctx->req_policy = tmp;
			ctx->req_policy[ctx->num_req_policies++] = policy;
		}
	}

	return ctx->num_req_policies;
}


static size_t policy_element_len(const struct hostapd_dscp_policy *policy)
{
	size_t len = 0;

	/* QoS Management element header: Element ID (1), Length (1), OUI (3),
	 * OUI Type (1) */
	len += 6;

	/* DSCP Policy attribute:Attr ID(1) + Len(1) + Policy ID(1) +
	 * Req Type(1) + DSCP (1) */
	len += 5;

	/* Classifier attributes */
	if (policy->frame_classifier_len)
		len += 2 + policy->frame_classifier_len;

	/* Port Range attribute: Attribute ID (1) + Length (1) +
	 * Start Port (2) + End Port (2) */
	if (policy->port_range_info)
		len += 6;

	/* Domain Name attribute: Attribute ID (1) + Length (1) +
	 * domain_name_len */
	if (policy->domain_name_len)
		len += 2 + policy->domain_name_len;

	return len;
}


static void add_policy_element(struct wpabuf *buf,
			       const struct hostapd_dscp_policy *policy)
{
	struct wpabuf *elem;

	elem = wpabuf_alloc(policy_element_len(policy));
	if (!elem)
		return;

	wpabuf_put_be32(elem, QM_IE_VENDOR_TYPE);

	/* DSCP Policy attribute */
	wpabuf_put_u8(elem, QM_ATTR_DSCP_POLICY);
	wpabuf_put_u8(elem, 3);
	wpabuf_put_u8(elem, policy->policy_id);
	wpabuf_put_u8(elem, policy->req_type);

	if (policy->req_type == DSCP_POLICY_REQ_REMOVE)
		wpabuf_put_u8(elem, 255); /* DSCP = 255 for REMOVE */
	else
		wpabuf_put_u8(elem, policy->dscp);

	if (policy->frame_classifier && policy->frame_classifier_len) {
		wpabuf_put_u8(elem, QM_ATTR_TCLAS);
		wpabuf_put_u8(elem, policy->frame_classifier_len);
		wpabuf_put_data(elem, policy->frame_classifier,
				policy->frame_classifier_len);
	}

	/* Classifier: Domain Name */
	if (policy->domain_name && policy->domain_name_len > 0) {
		wpabuf_put_u8(elem, QM_ATTR_DOMAIN_NAME);
		wpabuf_put_u8(elem, policy->domain_name_len);
		wpabuf_put_data(elem, policy->domain_name,
				policy->domain_name_len);
	}

	if (policy->port_range_info) {
		wpabuf_put_u8(elem, QM_ATTR_PORT_RANGE);
		wpabuf_put_u8(elem, 4);
		wpabuf_put_be16(elem, policy->start_port);
		wpabuf_put_be16(elem, policy->end_port);
	}

	wpabuf_put_u8(buf, WLAN_EID_VENDOR_SPECIFIC);
	wpabuf_put_u8(buf, wpabuf_len(elem));
	wpabuf_put_buf(buf, elem);

	wpabuf_free(elem);
}


/* Build DSCP Policy Request frame */
static struct wpabuf * build_dscp_policy_request(struct hostapd_data *hapd,
						 struct sta_info *sta,
						 const struct dscp_context *ctx,
						 size_t offset,
						 size_t *policies_used,
						 u8 dialog_token,
						 bool *more)
{
	struct wpabuf *buf;
	u8 *rc_field;
	size_t i;

	buf = wpabuf_alloc(MAX_DSCP_REQ_SIZE);
	if (!buf)
		return NULL;

	/* Action frame header */
	wpabuf_put_u8(buf, WLAN_ACTION_VENDOR_SPECIFIC_PROTECTED);
	wpabuf_put_be32(buf, QM_ACTION_VENDOR_TYPE);
	wpabuf_put_u8(buf, QM_DSCP_POLICY_REQ);

	/* Dialog Token */
	wpabuf_put_u8(buf, dialog_token);

	/* Request Control */
	rc_field = wpabuf_put(buf, 1);
	*rc_field = sta->dscp_reset ? DSCP_POLICY_CTRL_RESET : 0x00;
	*more = false;

	for (i = offset; i < ctx->num_req_policies; i++) {
		const struct hostapd_dscp_policy *policy = ctx->req_policy[i];

		if (sta->dscp_reset &&
		    policy->req_type == DSCP_POLICY_REQ_REMOVE)
			continue;

		if (wpabuf_len(buf) + policy_element_len(policy) >
		    MAX_DSCP_REQ_SIZE) {
			*rc_field |= DSCP_POLICY_CTRL_MORE;
			*more = true;
			break;
		}

		add_policy_element(buf, policy);
	}

	if (policies_used)
		*policies_used = i - offset;

	/* If no matching policies, leave QoS Management element list empty */
	if (ctx->num_req_policies == 0 && sta->dscp_reset == 0)
		wpa_printf(MSG_DEBUG,
			   "QM: No matching policies - sending empty response");

	return buf;
}


int hostapd_handle_dscp_policy_query(struct hostapd_data *hapd,
				     struct sta_info *sta,
				     const u8 *data, size_t len)
{
	struct wpabuf *resp;
	struct dscp_context ctx;
	size_t offset = 0, used;
	u8 dialog_token;
	bool more = false;
	unsigned int i;

	if (!sta || !(sta->flags & WLAN_STA_AUTHORIZED)) {
		wpa_printf(MSG_DEBUG, "DSCP Policy: STA not authorized");
		return -1;
	}

	if (!(sta->flags & WLAN_STA_DSCP_POLICY)) {
		wpa_printf(MSG_DEBUG, "DSCP: STA " MACSTR " not capable",
			   MAC2STR(sta->addr));
		return -1;
	}

	if (len == 0)
		return -1;

	os_memset(&ctx, 0, sizeof(ctx));
	ctx.hapd = hapd;
	ctx.sta = sta;

	if (parse_dscp_query(data, len, &ctx) < 0) {
		wpa_printf(MSG_DEBUG, "DSCP: Failed to parse query from "
			   MACSTR,
			   MAC2STR(sta->addr));
		return -1;
	}

	if (policy_matches_query(&ctx) <= 0)
		wpa_printf(MSG_DEBUG, "QM: No matching DSCP policies found");

	dialog_token = ctx.dialog_token;

	resp = build_dscp_policy_request(hapd, sta, &ctx, offset, &used,
					 dialog_token, &more);
	if (!resp)
		goto cleanup;

	if (hostapd_drv_send_action(hapd, hapd->iface->freq, 0, sta->addr,
				    wpabuf_head(resp), wpabuf_len(resp))) {

		wpa_printf(MSG_DEBUG, "DSCP: Failed to send policy request to "
			   MACSTR, MAC2STR(sta->addr));
		wpabuf_free(resp);
		goto cleanup;
	}

	wpabuf_free(resp);

	if (used && more) {
		sta->dscp_state.offset = offset + used;
		sta->dscp_state.last_dialog_token = dialog_token;
		sta->dscp_state.pending_more = true;
	}

cleanup:
	for (i = 0; i < ctx.num_query_policies; i++)
		os_free(ctx.query_policy[i]);
	os_free(ctx.query_policy);
	os_free(ctx.req_policy);
	return 0;
}


static void update_policy_status(struct sta_info *sta, u8 policy_id,
				 enum dscp_policy_status status)
{
	unsigned int i;

	if (!sta || !sta->policies)
		return;

	for (i = 0; i < sta->num_dscp_policies; i++) {
		if (!sta->policies[i] ||
		    sta->policies[i]->policy_id != policy_id)
			continue;

		sta->policies[i]->status = status;

		if (status == DSCP_STATUS_SUCCESS) {
			wpa_printf(MSG_DEBUG,
				   "DSCP: Policy %u marked as accepted",
				   policy_id);
		} else {
			wpa_printf(MSG_DEBUG,
				   "DSCP: Policy %u marked as rejected %u",
				   policy_id, status);
		}
		return;
	}

	wpa_printf(MSG_DEBUG, "DSCP: Policy %u not found to update status",
		   policy_id);
}


static void invalidate_policy_by_id(struct sta_info *sta, u8 policy_id)
{
	unsigned int i;

	for (i = 0; i < sta->num_dscp_policies; i++) {
		struct hostapd_dscp_policy *policy = sta->policies[i];

		if (policy && policy->policy_id == policy_id) {
			wpa_printf(MSG_DEBUG, "DSCP: Invalidating policy %u",
				   policy_id);
			free_dscp_policy(policy);
			sta->policies[i] = NULL;
			break;
		}
	}
}


static void reset_dscp_state(struct sta_info *sta)
{
	if (sta) {
		sta->dscp_state.offset = 0;
		sta->dscp_state.last_dialog_token = 0;
		sta->dscp_state.pending_more = false;
	}
}


static struct wpabuf *
hostapd_build_dscp_policy_request_from_offset(struct hostapd_data *hapd,
					      struct sta_info *sta,
					      u8 dialog_token,
					      u8 reset, size_t offset,
					      size_t *next_offset,
					      bool *more)
{
	struct wpabuf *buf;
	size_t i, frame_len;

	buf = new_dscp_policy_req_frame(hapd, sta, dialog_token, reset, 0);
	if (!buf)
		return NULL;

	frame_len = wpabuf_len(buf);
	*more = false;

	for (i = offset; i < sta->num_dscp_policies; i++) {
		struct hostapd_dscp_policy *policy = sta->policies[i];
		struct wpabuf *elem;

		if (!policy)
			continue;

		elem = hostapd_build_qos_element(policy);
		if (!elem)
			continue;

		if (frame_len + 2 + wpabuf_len(elem) > MAX_DSCP_REQ_SIZE) {
			wpabuf_free(elem);
			*more = true;
			break;
		}

		wpabuf_put_u8(buf, WLAN_EID_VENDOR_SPECIFIC);
		wpabuf_put_u8(buf, wpabuf_len(elem));
		wpabuf_put_buf(buf, elem);
		wpabuf_free(elem);
		frame_len = wpabuf_len(buf);
	}

	if (*more) {
		u8 *buf_ptr = wpabuf_mhead_u8(buf);

		buf_ptr[7] |= DSCP_POLICY_CTRL_MORE;
	}

	if (next_offset)
		*next_offset = i;

	return buf;
}


static void hostapd_send_next_dscp_policy_batch(struct hostapd_data *hapd,
						struct sta_info *sta,
						size_t start_offset)
{
	struct wpabuf *frame;
	size_t next_offset = 0;
	u8 dialog_token;
	bool more = false;

	if (!hapd || !sta || !sta->policies || sta->num_dscp_policies == 0)
		return;

	dialog_token = get_next_unsolicited_dialog_token(sta);

	frame = hostapd_build_dscp_policy_request_from_offset(hapd, sta,
							      dialog_token,
							      0, start_offset,
							      &next_offset,
							      &more);
	if (!frame)
		return;

	if (hostapd_drv_send_action(hapd, hapd->iface->freq, 0, sta->addr,
				    wpabuf_head(frame), wpabuf_len(frame)) < 0)
	{
		wpa_printf(MSG_INFO,
			   "DSCP: Failed to send next policy frame to " MACSTR,
			   MAC2STR(sta->addr));
	}

	wpabuf_free(frame);

	sta->dscp_state.offset = next_offset;
	sta->dscp_state.last_dialog_token = dialog_token;
	sta->dscp_state.pending_more = more;
}


/* Handle DSCP Policy Response frame */
int hostapd_handle_dscp_policy_response(struct hostapd_data *hapd,
					struct sta_info *sta,
					const u8 *data, size_t len)
{
	const u8 *pos = data, *end = data + len;
	u8 dialog_token;
	u8 response_control;
	u8 count;

	if (!sta || !(sta->flags & WLAN_STA_DSCP_POLICY)) {
		wpa_printf(MSG_DEBUG, "DSCP: STA " MACSTR " not capable",
			   MAC2STR(sta->addr));
		return -1;
	}

	if (len < 2)
		return -1;

	dialog_token = *pos++;
	response_control = *pos++;

	/* Handle reset case */
	if (response_control & DSCP_POLICY_CTRL_RESET) {
		free_dscp_policies(sta);
		reset_dscp_state(sta);
	}

	/* Unsolicited Response (Dialog Token 0) */
	if (dialog_token == 0 && (response_control & DSCP_POLICY_CTRL_RESET)) {
		wpa_printf(MSG_DEBUG, "DSCP: STA " MACSTR
			   " issued unsolicited reset", MAC2STR(sta->addr));
		free_dscp_policies(sta);
		reset_dscp_state(sta);
		return 0;
	}

	if (len < 3)
		return -1;
	count = *pos++;

	/* Process status duples */
	while (count > 0 && end - pos >= 2) {
		struct hostapd_dscp_policy *policy = NULL;
		u8 policy_id = *pos++;
		u8 status = *pos++;
		unsigned int i;

		count--;

		for (i = 0; i < sta->num_dscp_policies; i++) {
			if (sta->policies[i]->policy_id == policy_id) {
				policy = sta->policies[i];
				break;
			}
		}

		if (!policy) {
			wpa_printf(MSG_DEBUG,
				   "DSCP: Unknown policy ID %u in response",
				   policy_id);
			continue;
		}

		switch (status) {
		case DSCP_STATUS_SUCCESS:
			if (policy->req_type == DSCP_POLICY_REQ_REMOVE)
				invalidate_policy_by_id(sta, policy_id);
			else
				update_policy_status(sta, policy_id, status);
			break;
		case DSCP_STATUS_CLASSIFIER_NOT_SUPPORTED:
		case DSCP_STATUS_REQUEST_DECLINED:
		case DSCP_STATUS_INSUFFICIENT_RESOURCES:
			invalidate_policy_by_id(sta, policy_id);
			break;
		default:
			wpa_printf(MSG_DEBUG,
				   "DSCP: Unknown status %u for policy %u",
				   status, policy_id);
			break;
		}
	}

	/* If More bit is set, STA wants more policies */
	if ((response_control & DSCP_POLICY_CTRL_MORE) &&
	    sta->dscp_state.pending_more) {
		wpa_printf(MSG_DEBUG,
			   "DSCP: STA " MACSTR
			   " requested additional policy batch",
			   MAC2STR(sta->addr));
		hostapd_send_next_dscp_policy_batch(hapd, sta,
						    sta->dscp_state.offset);
	}

	return 0;
}

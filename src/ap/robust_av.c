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

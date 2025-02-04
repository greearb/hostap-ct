#include "utils/includes.h"

#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "hostapd.h"
#include "ieee802_11.h"
#include "sta_info.h"
#include "ap_config.h"
#include "ap_drv_ops.h"
#include "drivers/netlink.h"
#include "drivers/priv_netlink.h"
#include "scs.h"

static int send_mtk_mscs_nl_msg(struct hostapd_data *hapd,
				 struct hostapd_mscs_desc_info *info)
{
	ssize_t info_len = sizeof(struct hostapd_mscs_desc_info);
	ssize_t buf_len = info_len + sizeof(struct qos_netlink_msg);
	struct qos_netlink_msg *qos_msg;
	struct sockaddr_nl dest_addr;
	struct nlmsghdr *nlh;
	struct msghdr msg;
	struct iovec iov;

	if (!hapd->iface || !hapd->iface->interfaces ||
	    hapd->iface->interfaces->mtk_mscs_sock <= 0) {
		wpa_printf(MSG_ERROR, "%s: socket is not ready", __func__);
		return -1;
	}

	nlh = (struct nlmsghdr *) os_zalloc(NLMSG_SPACE(buf_len));
	if (!nlh) {
		wpa_printf(MSG_ERROR, "%s: Error to alloc mem", __func__);
		return -1;
	}

	nlh->nlmsg_len = NLMSG_SPACE(buf_len);
	nlh->nlmsg_pid = hapd->iface->interfaces->mtk_mscs_pid;
	nlh->nlmsg_flags = 0;

	qos_msg = NLMSG_DATA(nlh);
	qos_msg->type = MSCS_POLICY;
	qos_msg->len = info_len;
	os_memcpy(&qos_msg->variable[0], info, info_len);

	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;

	os_memset(&dest_addr, 0, sizeof(struct sockaddr_nl));
	dest_addr.nl_family= AF_NETLINK;
	dest_addr.nl_pid= 0;
	dest_addr.nl_groups= 0;

	os_memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (sendmsg(hapd->iface->interfaces->mtk_mscs_sock, &msg, 0) < 0)
		wpa_printf(MSG_ERROR, "%s: sendmsg failed: %s",
			   __func__, strerror(errno));
	os_free(nlh);

	return 0;
}

int hostapd_mtk_mscs_daemon_init(struct hapd_interfaces *ifaces)
{
	struct sockaddr_nl src_addr;

	ifaces->mtk_mscs_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_QOS_CTRL);
	if (ifaces->mtk_mscs_sock < 0) {
		wpa_printf(MSG_ERROR, "%s: Error to create socket", __func__);
		return -1;
	}

	ifaces->mtk_mscs_pid = getpid();

	os_memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = ifaces->mtk_mscs_pid;

	if (bind(ifaces->mtk_mscs_sock, (struct sockaddr *) &src_addr, sizeof(src_addr)) < 0) {
		wpa_printf(MSG_ERROR, "%s: Error to bind socket", __func__);
		close(ifaces->mtk_mscs_sock);
		return -1;
	}

	return 0;
}

void hostapd_mtk_mscs_daemon_deinit(struct hapd_interfaces *ifaces)
{
	if (ifaces->mtk_mscs_sock <= 0)
		return;

	close(ifaces->mtk_mscs_sock);
	ifaces->mtk_mscs_sock = 0;
	ifaces->mtk_mscs_pid = 0;
}

static void send_mscs_response(struct hostapd_data *hapd, const u8 *da,
			       u8 dialog_token, u16 status)
{
	struct wpabuf *buf;
	size_t len = 5;

	/* Reference to 802_11be_D5.0 Figure 9-960 */
	buf = wpabuf_alloc(len);
	if (!buf)
		return;

	wpabuf_put_u8(buf, WLAN_ACTION_ROBUST_AV_STREAMING);
	wpabuf_put_u8(buf, ROBUST_AV_MSCS_RESP);
	wpabuf_put_u8(buf, dialog_token);
	wpabuf_put_le16(buf, status);

	len = wpabuf_len(buf);
	hostapd_drv_send_action(hapd, hapd->iface->freq, 0, da,
				wpabuf_head(buf), len);
	wpabuf_free(buf);
}

static u16 hostapd_parse_mscs_desc_elem(struct hostapd_mscs_desc_info *info,
					const u8 *pos, size_t len)
{
#define FRAME_CLASS_TYPE_IP_AND_HIGHER_PARAMS 4
	bool tclas_mask_required = true;
	const struct element *elem;

	/* Check for enough bytes: (1B)Req Type + (2B)User Priority Control +
	 * (4B) Stream Timeout.
	 */
	if (!pos || len < MSCS_DESCRIPTOR_FIXED_LEN - 1) {
		wpa_printf(MSG_ERROR, "%s MSCS Desc len %zu is not enough!",
			   __func__, len);
		return WLAN_STATUS_REQUEST_DECLINED;
	}

	info->req_type = *pos++;
	info->up_bitmap = *pos++;
	info->up_limit = *pos++ & 0x7;
	info->stream_timeout = WPA_GET_LE32(pos);
	pos += 4;

	switch (info->req_type) {
	case SCS_REQ_REMOVE:
		tclas_mask_required = false;
		break;
	case SCS_REQ_ADD:
	case SCS_REQ_CHANGE:
		break;
	default:
		wpa_printf(MSG_ERROR, "%s Unsupported MSCS req type %u!",
			   __func__, info->req_type);
		return WLAN_STATUS_REQUEST_DECLINED;
	}

	for_each_element(elem, pos, len - 7) {
		switch (elem->id) {
		case WLAN_EID_EXTENSION:
			if (elem->data[0] != WLAN_EID_EXT_TCLAS_MASK) {
				wpa_printf(MSG_ERROR, "%s: Unexpected ext element %d",
					   __func__, elem->data[0]);

				return WLAN_STATUS_REQUEST_DECLINED;
			}

			if (!tclas_mask_required)
				return WLAN_STATUS_REQUEST_DECLINED;

			info->classifier_type = elem->data[1];
			info->classifier_mask = elem->data[2];
			break;
		default:
			/* the rest elements would be ignored now. */
			break;
		}
	}

	switch (info->req_type) {
	case SCS_REQ_ADD:
	case SCS_REQ_CHANGE:
		if (info->classifier_type != FRAME_CLASS_TYPE_IP_AND_HIGHER_PARAMS) {
			wpa_printf(MSG_ERROR, "%s: Unsupported Classifier type.\n",
				   __func__);
			return WLAN_STATUS_REQUESTED_TCLAS_NOT_SUPPORTED;
		}

		return WLAN_STATUS_SUCCESS;
	case SCS_REQ_REMOVE:
		return WLAN_STATUS_TCLAS_PROCESSING_TERMINATED;
	default:
		return WLAN_STATUS_REQUEST_DECLINED;
	}
}

u16 hostapd_set_mscs(struct hostapd_data *hapd, const u8 *addr,
		     const u8 *elem, size_t elem_len)
{
	struct hostapd_mscs_desc_info info;
	u16 status;

	os_memset(&info, 0, sizeof(info));
	os_memcpy(info.peer_addr, addr, ETH_ALEN);

	status = hostapd_parse_mscs_desc_elem(&info, elem, elem_len);

	switch (status) {
	case WLAN_STATUS_SUCCESS:
	case WLAN_STATUS_TCLAS_PROCESSING_TERMINATED:
		if (send_mtk_mscs_nl_msg(hapd, &info))
			status = WLAN_STATUS_REQUEST_DECLINED;
		break;
	case WLAN_STATUS_REQUEST_DECLINED:
	default:
		break;
	}

	return status;
}

static void hostapd_handle_mscs_req(struct hostapd_data *hapd,
				    const u8 *buf, size_t len)
{
	const struct ieee80211_mgmt *mgmt = (const struct ieee80211_mgmt *) buf;
	const struct element *elem;
	struct sta_info *sta;
	u8 token;

	sta = ap_get_sta(hapd, mgmt->sa);
	if (!sta) {
		wpa_printf(MSG_ERROR, "Station " MACSTR " not found "
			   "for MSCS Request frame", MAC2STR(mgmt->sa));
		return;
	}

	token = mgmt->u.action.u.mscs.dialog_token;
	elem = (const struct element *) mgmt->u.action.u.mscs.variable;

	if (elem->id != WLAN_EID_EXTENSION ||
	    elem->data[0] != WLAN_EID_EXT_MSCS_DESCRIPTOR) {
		wpa_printf(MSG_ERROR, "%s: no MSCS Descriptor element", __func__);
		return;
	}

	sta->mscs_assoc_setup_status =
		hostapd_set_mscs(hapd, mgmt->sa, &elem->data[1], elem->datalen - 1);

	send_mscs_response(hapd, mgmt->sa, token,
			   sta->mscs_assoc_setup_status);
}

static bool hostapd_find_scs_session(struct sta_info *sta, u8 scsid,
				     int *session_idx)
{
	u8 idx;

	for (idx = 0; idx < SCS_MAX_CFG_CNT; idx++) {
		if (sta->scs_session[idx].scs_id == scsid) {
			*session_idx = idx;
			return sta->scs_session[idx].alive;
		}
	}

	return false;
}

static int hostapd_find_available_scs_session(struct sta_info *sta)
{
	u8 idx;

	for (idx = 0; idx < SCS_MAX_CFG_CNT; idx++) {
		if (!sta->scs_session[idx].alive)
			return idx;
	}

	return -1;
}

static bool hostapd_parse_qos_char_element(const struct element *elem,
					   struct hostapd_scs_desc_info *info)
{
	u8 id_extension = elem->data[0];
	u32 control_info;

	info->qos_ie_len = elem->datalen + 2;

	if (id_extension != WLAN_EID_EXT_QOS_CHARACTERISTICS ||
	    info->qos_ie_len > sizeof(info->qos_ie))
		return false;

	control_info = WPA_GET_LE32(&elem->data[1]);
	info->dir = control_info & 0x3;

	/* Only support Uplink direction SCS request now. */
	if (info->dir != SCS_DIRECTION_UP)
		return false;

	os_memcpy(info->qos_ie, elem, info->qos_ie_len);

	return true;
}

static u16 hostapd_process_scs_descriptor(struct hostapd_data *hapd,
					  struct sta_info *sta, const u8 *payload,
					  u8 scs_desc_len,
					  struct hostapd_scs_desc_info *info)
{
	bool scs_avail, qos_char_elem_avail = false;
	const struct element *elem;
	int session_idx;
	int ret;

	scs_avail = hostapd_find_scs_session(sta, info->id, &session_idx);

	switch (info->req_type) {
	case SCS_REQ_ADD:
	case SCS_REQ_CHANGE:
		if ((info->req_type == SCS_REQ_ADD && scs_avail) ||
		    (info->req_type == SCS_REQ_CHANGE && !scs_avail))
			goto decline;

		if (info->req_type == SCS_REQ_ADD) {
			session_idx = hostapd_find_available_scs_session(sta);
			if (session_idx < 0) {
				wpa_printf(MSG_ERROR, "%s: Out of SCS resource.\n",
					   __func__);
				goto decline;
			}
		}

		for_each_element(elem, payload + 2, scs_desc_len - 2) {
			switch (elem->id) {
			case WLAN_EID_EXTENSION:
				qos_char_elem_avail =
					hostapd_parse_qos_char_element(elem, info);
				break;
			default:
				/* The rest elements would be ignored now. */
				break;
			}
		}

		if (!qos_char_elem_avail) {
			wpa_printf(MSG_ERROR, "%s: The content of QoS Charactristics"
				   " element is empty or not supported yet!\n",
				   __func__);
			goto decline;
		}

		break;
	case SCS_REQ_REMOVE:
		if (!scs_avail)
			goto decline;

		break;
	default:
		goto decline;
	}

	ret = hostapd_drv_set_scs(hapd, info);
	if (ret)
		goto decline;

	sta->scs_session[session_idx].scs_id = info->id;
	sta->scs_session[session_idx].alive =
		info->req_type == SCS_REQ_REMOVE ? false : true;

	return (info->req_type == SCS_REQ_REMOVE) ?
		WLAN_STATUS_TCLAS_PROCESSING_TERMINATED : WLAN_STATUS_SUCCESS;

decline:
	wpa_printf(MSG_ERROR, "%s: Decline Request Type %d\n",
		   __func__, info->req_type);

	return WLAN_STATUS_REQUEST_DECLINED;
}

static void send_scs_response(struct hostapd_data *hapd,
			      struct scs_status_duple *scs_status, const u8 *da,
			      u8 dialog_token, u8 count)
{
	struct wpabuf *buf;
	size_t len;
	u8 i;

	if (count == 0)
		return;

	/* Reference to 802_11be_D5.0 Figure 9-1183  */
	len = 4 + count * sizeof(struct scs_status_duple);
	buf = wpabuf_alloc(len);
	if (buf == NULL)
		return;

	wpabuf_put_u8(buf, WLAN_ACTION_ROBUST_AV_STREAMING);
	wpabuf_put_u8(buf, ROBUST_AV_SCS_RESP);
	wpabuf_put_u8(buf, dialog_token);
	wpabuf_put_u8(buf, count);

	for (i = 0; i < count && i < SCS_MAX_CFG_CNT; i++) {
		wpabuf_put_u8(buf, scs_status[i].scs_id);
		wpabuf_put_le16(buf, scs_status[i].status);
	}

	len = wpabuf_len(buf);
	hostapd_drv_send_action(hapd, hapd->iface->freq, 0, da,
				wpabuf_head(buf), len);
	wpabuf_free(buf);
}

static void hostapd_handle_scs_req(struct hostapd_data *hapd,
				   const u8 *buf, size_t len)
{
	const struct ieee80211_mgmt *mgmt = (const struct ieee80211_mgmt *) buf;
	struct hostapd_scs_desc_info info;
	struct sta_info *sta;
	struct scs_status_duple scs_status_list[SCS_MAX_CFG_CNT];
	const u8 *pos, *end;
	u8 token, index = 0;
	const struct element *elem;

	sta = ap_get_sta(hapd, mgmt->sa);

	if (!sta) {
		wpa_printf(MSG_ERROR, "Station " MACSTR " not found "
			   "for SCS Request frame\n", MAC2STR(mgmt->sa));
		return;
	}

	token = mgmt->u.action.u.scs.dialog_token;
	pos = mgmt->u.action.u.scs.variable;

	end = buf + len;
	len = end - pos;

	for_each_element(elem, pos, len) {
		if (elem->id != WLAN_EID_SCS_DESCRIPTOR) {
			wpa_printf(MSG_ERROR, "%s: no scs elem %d in scs req frame!\n",
				   __func__, WLAN_EID_SCS_DESCRIPTOR);
			break;
		}

		info.id = elem->data[0];
		if (!info.id) {
			wpa_printf(MSG_ERROR, "%s: SCSID = 0 is invalid\n", __func__);
			break;
		}

		info.req_type = elem->data[1];
		os_memcpy(info.peer_addr, mgmt->sa, ETH_ALEN);
		scs_status_list[index].scs_id = info.id;
		scs_status_list[index].status =
			hostapd_process_scs_descriptor(hapd, sta, elem->data,
						       elem->datalen, &info);
		index++;
	}

	send_scs_response(hapd, scs_status_list, mgmt->sa, token, index);
}

void hostapd_handle_robust_av_streaming(struct hostapd_data *hapd, const u8 *buf,
					size_t len)
{
	const struct ieee80211_mgmt *mgmt = (const struct ieee80211_mgmt *) buf;

	/*
	 * Check for enough bytes: header + (1B)Category + (1B)Action +
	 * (1B)Dialog Token.
	 */
	if (len < IEEE80211_HDRLEN + 3) {
		wpa_printf(MSG_ERROR, "%s Robust AV frame len %zu is not enough!",
			   __func__, len);
		return;
	}

	switch (mgmt->u.action.u.scs.action) {
	case ROBUST_AV_SCS_REQ:
		hostapd_handle_scs_req(hapd, buf, len);
		break;
	case ROBUST_AV_MSCS_REQ:
		hostapd_handle_mscs_req(hapd, buf, len);
		break;
	case ROBUST_AV_SCS_RESP:
	case ROBUST_AV_MSCS_RESP:
		/* Not supported yet. */
		break;
	default:
		break;
	}
}

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

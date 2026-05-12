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

#ifdef CONFIG_ROBUST_AV

void hostapd_update_dscp_policy_capability(struct hostapd_data *hapd,
					   struct sta_info *sta,
					   const u8 *pos, size_t len);

#else /* CONFIG_ROBUST_AV */

static inline void
hostapd_update_dscp_policy_capability(struct hostapd_data *hapd,
				      struct sta_info *sta,
				      const u8 *pos, size_t len)
{
}

#endif /* CONFIG_ROBUST_AV */

#endif /* ROBUST_AV_H */

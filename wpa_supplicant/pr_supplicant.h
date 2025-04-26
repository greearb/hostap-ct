/*
 * Proxmity Ranging
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef PR_SUPPLICANT_H
#define PR_SUPPLICANT_H

#ifdef CONFIG_PR

int wpas_pr_init(struct wpa_global *global, struct wpa_supplicant *wpa_s,
		 const struct wpa_driver_capa *capa);
void wpas_pr_deinit(struct wpa_supplicant *wpa_s);

#else /* CONFIG_PR */

static inline int wpas_pr_init(struct wpa_global *global,
			       struct wpa_supplicant *wpa_s,
			       const struct wpa_driver_capa *capa)
{
	return -1;
}

static inline void wpas_pr_deinit(struct wpa_supplicant *wpa_s)
{
}

#endif /* CONFIG_PR */

#endif /* PR_SUPPLICANT_H */

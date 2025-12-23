/*
 * wpa_supplicant - NAN
 * Copyright (C) 2025 Intel Corporation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef NAN_SUPPLICANT_H
#define NAN_SUPPLICANT_H

#ifdef CONFIG_NAN

int wpas_nan_init(struct wpa_supplicant *wpa_s);
void wpas_nan_deinit(struct wpa_supplicant *wpa_s);
int wpas_nan_start(struct wpa_supplicant *wpa_s);
int wpas_nan_stop(struct wpa_supplicant *wpa_s);
void wpas_nan_flush(struct wpa_supplicant *wpa_s);

#else /* CONFIG_NAN */

static inline int wpas_nan_init(struct wpa_supplicant *wpa_s)
{
	return -1;
}

static inline void wpas_nan_deinit(struct wpa_supplicant *wpa_s)
{}

static inline int wpas_nan_start(struct wpa_supplicant *wpa_s)
{
	return -1;
}

static inline int wpas_nan_stop(struct wpa_supplicant *wpa_s)
{
	return -1;
}

static inline void wpas_nan_flush(struct wpa_supplicant *wpa_s)
{}

#endif /* CONFIG_NAN */

#endif /* NAN_SUPPLICANT_H */

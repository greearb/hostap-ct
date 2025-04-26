/*
 * Proxmity Ranging
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "proximity_ranging.h"


static void pr_device_free(struct pr_data *pr, struct pr_device *dev)
{
	os_free(dev);
}


static struct pr_device * pr_get_device(struct pr_data *pr, const u8 *addr)
{
	struct pr_device *dev;

	dl_list_for_each(dev, &pr->devices, struct pr_device, list) {
		if (ether_addr_equal(dev->pr_device_addr, addr))
			return dev;
	}
	return NULL;
}


static struct pr_device * pr_create_device(struct pr_data *pr, const u8 *addr)
{
	struct pr_device *dev, *oldest = NULL;
	size_t count = 0;

	dev = pr_get_device(pr, addr);
	if (dev)
		return dev;

	dl_list_for_each(dev, &pr->devices, struct pr_device, list) {
		count++;
		if (!oldest ||
		    os_reltime_before(&dev->last_seen, &oldest->last_seen))
			oldest = dev;
	}
	if (count + 1 > PR_MAX_PEER && oldest) {
		wpa_printf(MSG_DEBUG,
			   "PR: Remove oldest peer entry to make room for a new peer "
			   MACSTR, MAC2STR(oldest->pr_device_addr));
		dl_list_del(&oldest->list);
		pr_device_free(pr, oldest);
	}

	dev = os_zalloc(sizeof(*dev));
	if (!dev)
		return NULL;

	dl_list_add(&pr->devices, &dev->list);
	os_memcpy(dev->pr_device_addr, addr, ETH_ALEN);
	wpa_printf(MSG_DEBUG, "PR: New Proximity Ranging device " MACSTR
		   " added to list", MAC2STR(addr));

	return dev;
}


struct pr_data * pr_init(const struct pr_config *cfg)
{
	struct pr_data *pr;

	pr = os_zalloc(sizeof(*pr) + sizeof(*cfg));
	if (!pr)
		return NULL;

	pr->cfg = (struct pr_config *) (pr + 1);
	os_memcpy(pr->cfg, cfg, sizeof(*cfg));
	if (cfg->dev_name)
		pr->cfg->dev_name = os_strdup(cfg->dev_name);
	else
		pr->cfg->dev_name = NULL;

	dl_list_init(&pr->devices);

	return pr;
}


void pr_deinit(struct pr_data *pr)
{
	struct pr_device *dev, *prev;

	if (!pr)
		return;

	os_free(pr->cfg->dev_name);

	dl_list_for_each_safe(dev, prev, &pr->devices, struct pr_device, list) {
		dl_list_del(&dev->list);
		pr_device_free(pr, dev);
	}

	os_free(pr);
	wpa_printf(MSG_DEBUG, "PR: Deinit done");
}


static struct wpabuf * pr_encaps_elem(const struct wpabuf *subelems,
				      u32 ie_type)
{
	struct wpabuf *ie = NULL;
	const u8 *pos, *end;
	size_t len = 0;

	if (!subelems)
		return NULL;

	len = wpabuf_len(subelems) + 1000;
	ie = wpabuf_alloc(len);
	if (!ie)
		return NULL;

	pos = wpabuf_head(subelems);
	end = pos + wpabuf_len(subelems);

	while (end > pos) {
		size_t frag_len = end - pos;

		if (frag_len > 251)
			frag_len = 251;
		wpabuf_put_u8(ie, WLAN_EID_VENDOR_SPECIFIC);
		wpabuf_put_u8(ie, 4 + frag_len);
		wpabuf_put_be32(ie, ie_type);
		wpabuf_put_data(ie, pos, frag_len);
		pos += frag_len;
	}
	return ie;
}


static void pr_get_ranging_capabilities(struct pr_data *pr,
					struct pr_capabilities *capab)
{
	os_memset(capab, 0, sizeof(struct pr_capabilities));

	if (pr->cfg->dev_name)
		os_strlcpy(capab->device_name, pr->cfg->dev_name,
			   sizeof(capab->device_name));

	if (pr->cfg->edca_ista_support || pr->cfg->edca_rsta_support)
		capab->edca_support = true;

	if (pr->cfg->ntb_ista_support || pr->cfg->ntb_rsta_support)
		capab->ntb_support = true;

	capab->secure_he_ltf = pr->cfg->secure_he_ltf;
	capab->pasn_type = pr->cfg->pasn_type;
	capab->support_6ghz = pr->cfg->support_6ghz;
}


static void pr_buf_add_ranging_capa_info(struct wpabuf *buf,
					 const struct pr_capabilities *capab)
{
	u8 *len;
	u8 capa_6g = 0;
	u8 protocol_type = 0;
	size_t _len;

	/* Proximity Ranging Capability Attribute */
	wpabuf_put_u8(buf, PR_ATTR_RANGING_CAPABILITY);
	len = wpabuf_put(buf, 2); /* Attribute length to be filled */

	/* Ranging Protocol Type */
	if (capab->edca_support)
		protocol_type |= PR_EDCA_BASED_RANGING;
	if (capab->ntb_support && capab->secure_he_ltf)
		protocol_type |= PR_NTB_SECURE_LTF_BASED_RANGING;
	if (capab->ntb_support)
		protocol_type |= PR_NTB_OPEN_BASED_RANGING;
	wpabuf_put_u8(buf, protocol_type);

	/* PASN Type */
	wpabuf_put_u8(buf, capab->pasn_type);

	/* 6GHz band */
	if (capab->support_6ghz)
		capa_6g |= BIT(0);

	wpabuf_put_u8(buf, capa_6g);

	/* Device Name */
	wpabuf_put_data(buf, capab->device_name, WPS_DEV_NAME_MAX_LEN);
	wpa_printf(MSG_DEBUG, "PR: Device name: %s", capab->device_name);

	_len = (u8 *) wpabuf_put(buf, 0) - len - 2;
	WPA_PUT_LE16(len, _len);
	wpa_hexdump(MSG_DEBUG, "PR: * Capability Attribute", len + 2, _len);
}


struct wpabuf * pr_prepare_usd_elems(struct pr_data *pr)
{
	u32 ie_type;
	struct wpabuf *buf, *buf2;
	struct pr_capabilities pr_caps;

	buf = wpabuf_alloc(1000);
	if (!buf)
		return NULL;

	pr_get_ranging_capabilities(pr, &pr_caps);
	pr_buf_add_ranging_capa_info(buf, &pr_caps);

	ie_type = (OUI_WFA << 8) | PR_OUI_TYPE;
	buf2 = pr_encaps_elem(buf, ie_type);
	wpabuf_free(buf);

	return buf2;
}


void pr_process_usd_elems(struct pr_data *pr, const u8 *ies, u16 ies_len,
			  const u8 *peer_addr, unsigned int freq)
{
	struct pr_device *dev;

	dev = pr_create_device(pr, peer_addr);
	if (!dev) {
		wpa_printf(MSG_INFO, "PR: Failed to create a device");
		return;
	}

	os_get_reltime(&dev->last_seen);
	dev->listen_freq = freq;
}

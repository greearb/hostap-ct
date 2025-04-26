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

	dl_list_for_each_safe(dev, prev, &pr->devices, struct pr_device, list)
		dl_list_del(&dev->list);

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


struct wpabuf * pr_prepare_usd_elems(struct pr_data *pr)
{
	u32 ie_type;
	struct wpabuf *buf, *buf2;

	buf = wpabuf_alloc(1000);
	if (!buf)
		return NULL;

	ie_type = (OUI_WFA << 8) | PR_OUI_TYPE;
	buf2 = pr_encaps_elem(buf, ie_type);
	wpabuf_free(buf);

	return buf2;
}

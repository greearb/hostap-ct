/*
 * Hotspot 2.0 - OSU client
 * Copyright (c) 2013-2014, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef OSU_CLIENT_H
#define OSU_CLIENT_H

struct hs20_osu_client {
	struct xml_node_ctx *xml;
	struct http_ctx *http;
	const char *result_file;
	const char *summary_file;
	const char *ifname;
	const char *dns_file;
	const char* dns;
	int do_bind_iface;
#define WORKAROUND_OCSP_OPTIONAL 0x00000001
	unsigned long int workarounds;
	int ignore_tls; /* whether to ignore TLS validation issues with HTTPS
			 * server certificate */
};

void check_dns_file(struct hs20_osu_client* ctx);

#endif /* OSU_CLIENT_H */

/*
 * Proxmity Ranging
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef PROXIMITY_RANGING_H
#define PROXIMITY_RANGING_H

#include "utils/list.h"

/**
 * PR_MAX_OP_CLASSES - Maximum number of operating classes
 */
#define PR_MAX_OP_CLASSES 15

/**
 * PR_MAX_OP_CLASS_CHANNELS - Maximum number of channels per operating class
 */
#define PR_MAX_OP_CLASS_CHANNELS 60

/**
 * PR_MAX_PEER - Maximum number of Proximity Ranging peers that device can store
 */
#define PR_MAX_PEER 100

/**
 * struct pr_channels - List of supported channels
 */
struct pr_channels {
	/**
	 * struct pr_op_class - Supported operating class
	 */
	struct pr_op_class {
		/**
		 * op_class - Operating class
		 */
		u8 op_class;

		/**
		 * channel - Supported channels
		 */
		u8 channel[PR_MAX_OP_CLASS_CHANNELS];

		/**
		 * channels - Number of channel entries in use
		 */
		size_t channels;
	} op_class[PR_MAX_OP_CLASSES];

	/**
	 * op_classes - Number of op_class entries in use
	 */
	size_t op_classes;
};

/**
 * Format and Bandwidth values for EDCA based ranging with range of 10-16
 * from IEEE Std 802.11-2024, 9.4.2.166 (FTM Parameters element), Table 9-325
 * (Format And Bandwidth subfield) as specified in Proximity Ranging
 * Implementation Considerations for P2P Operation, Draft 1.8, Table 8
 * (Proximity Ranging EDCA Capability Attribute format) for the the Ranging
 * Parameters field B0-B3.
 */
enum edca_format_and_bw_value {
	EDCA_FORMAT_AND_BW_VHT20 = 10,
	EDCA_FORMAT_AND_BW_HT40 = 11,
	EDCA_FORMAT_AND_BW_VHT40 = 12,
	EDCA_FORMAT_AND_BW_VHT80 = 13,
	EDCA_FORMAT_AND_BW_VHT80P80 = 14,
	EDCA_FORMAT_AND_BW_VHT160_DUAL_LO = 15,
	EDCA_FORMAT_AND_BW_VHT160_SINGLE_LO = 16,
};

/**
 * Format and Bandwidth values for NTB based ranging as from IEEE Std
 * 802.11-2024, 9.4.2.300 (Ranging Parameters element), Table 9-412 (Format And
 * Bandwidth subfield) as specified in Proximity Ranging Implementation
 * Considerations for P2P Operation, Draft 1.8, Table 9 (Proximity Ranging 11az
 * NTB Capability Attribute format) for the Ranging Parameter field B0-B2.
 */
enum ntb_format_and_bw_value {
	NTB_FORMAT_AND_BW_HE20 = 0,
	NTB_FORMAT_AND_BW_HE40 = 1,
	NTB_FORMAT_AND_BW_HE80 = 2,
	NTB_FORMAT_AND_BW_HE80P80 = 3,
	NTB_FORMAT_AND_BW_HE160_DUAL_LO = 4,
	NTB_FORMAT_AND_BW_HE160_SINGLE_LO = 5,
};

/**
 * struct pr_device_info - Proximity ranging peer information
 */
struct pr_device {
	struct dl_list list;
	struct os_reltime last_seen;

	/**
	 * pr_device_addr - PR Device Address of the peer
	 */
	u8 pr_device_addr[ETH_ALEN];
};


struct pr_config {
	u8 pasn_type;

	int preferred_ranging_role;

	char country[3];

	u8 dev_addr[ETH_ALEN];

	/**
	 * dev_name - Device Name
	 */
	char *dev_name;

	bool edca_ista_support;

	bool edca_rsta_support;

	u8 edca_format_and_bw;

	u8 max_tx_antenna;

	u8 max_rx_antenna;

	struct pr_channels edca_channels;

	bool ntb_ista_support;

	bool ntb_rsta_support;

	bool secure_he_ltf;

	u8 max_tx_ltf_repetations;

	u8 max_rx_ltf_repetations;

	u8 max_tx_ltf_total;

	u8 max_rx_ltf_total;

	u8 max_rx_sts_le_80;

	u8 max_rx_sts_gt_80;

	u8 max_tx_sts_le_80;

	u8 max_tx_sts_gt_80;

	u8 ntb_format_and_bw;

	struct pr_channels ntb_channels;

	bool support_6ghz;

	/**
	 * cb_ctx - Context to use with callback functions
	 */
	void *cb_ctx;
};

struct pr_data {
	/**
	 * cfg - PR module configuration
	 *
	 * This is included in the same memory allocation with the
	 * struct pr_data and as such, must not be freed separately.
	 */
	struct pr_config *cfg;

	struct dl_list devices;
};

struct pr_data * pr_init(const struct pr_config *cfg);
void pr_deinit(struct pr_data *pr);

#endif /* PROXIMITY_RANGING_H */

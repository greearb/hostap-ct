#ifndef SCS_H
#define SCS_H

struct hostapd_data;

/* Only support TUAO certification */
#define SCS_MAX_CFG_CNT 2

struct scs_status_duple {
	u8 scs_id;
	u16 status;
};

struct scs_session_status {
	u8 scs_id;
	bool alive;
};

void hostapd_handle_scs(struct hostapd_data *hapd, const u8 *buf, size_t len);
#endif

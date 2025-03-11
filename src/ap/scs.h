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

struct qos_netlink_msg {
    u8 type;
    u8 rsv;
    u16 len;
    u8 variable[];
};

enum qos_netlink_type {
	MSCS_POLICY,
};

#define NETLINK_QOS_CTRL 27

void hostapd_handle_robust_av_streaming(struct hostapd_data *hapd,
					const u8 *buf, size_t len);
u16 hostapd_set_mscs(struct hostapd_data *hapd, const u8 *addr,
		     const u8 *pos, size_t len);
int hostapd_mtk_mscs_daemon_init(struct hapd_interfaces *ifaces);
void hostapd_mtk_mscs_daemon_deinit(struct hapd_interfaces *ifaces);
void hostapd_del_mscs(struct hostapd_data *hapd, u8 *mac);
#endif

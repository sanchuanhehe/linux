/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * SparkLink (NearLink) ioctl interface definitions.
 *
 * Canonical UAPI header for the /dev/sparklink character device.
 * All ioctl constants, data structures, and event types used by
 * userspace programs are defined here.
 *
 * Copyright (C) 2025 SparkLink for Linux Contributors
 */
#ifndef _UAPI_LINUX_SPARKLINK_IOCTL_H
#define _UAPI_LINUX_SPARKLINK_IOCTL_H

#include <linux/types.h>
#include <linux/ioctl.h>

/* =========================================================================
 * Data structures
 * =========================================================================
 */

/* --- Device management -------------------------------------------------- */

struct sci_dev_info {
	__u16 index;
	__u8  state;
	__u8  bus;
	__u8  addr[6];
	__u8  name[32];
	__u8  _reserved[24];
} __attribute__((packed));

/* --- Advertising / scanning --------------------------------------------- */

struct sle_adv_params {
	__u16 dev_index;
	__u16 interval_ms;
	__u8  discovery_level;
	__u8  _reserved[11];
};

struct sle_scan_params {
	__u16 dev_index;
	__u16 window_ms;
	__u16 interval_ms;
	__u8  filter_discovery_level;
	__u8  _reserved[9];
} __attribute__((packed));

/* Extended scan filter for service UUID matching (T/XS 20001-2025 §6.4).
 * Up to 4 standard 16-bit service UUIDs; a result passes if its
 * advertising TLV data (types 0x05/0x07) contains at least one match.
 * uuid_count == 0 disables UUID filtering.
 */
struct sle_scan_filter {
	__u8  uuid_count;
	__u8  _reserved[3];
	__u16 uuids[4];
} __attribute__((packed));

struct sle_ext_adv_config {
	__u8  handle;
	__u8  discovery_level;
	__u8  sid;
	__u8  broadcast_type;
	__u8  primary_phy;
	__u8  secondary_phy;
	__s8  tx_power_dbm;
	__u8  include_tx_power;
	__u16 interval_ms;
	__u8  ext_adv_timing;
	__u8  _reserved[5];
} __attribute__((packed));

struct sle_ext_adv_data {
	__u8  handle;
	__u8  _pad;
	__u16 data_len;
	__u8  data[252];
} __attribute__((packed));

struct sle_ext_adv_info {
	__u8  handle;
	__u8  state;
	__u8  sid;
	__u8  primary_phy;
	__u16 data_len;
	__u8  ext_adv_timing;
	__u8  max_adv_events;
	__u64 tx_count;
	__u32 events_sent;
	__u8  _pad[4];
} __attribute__((packed));

struct sle_ext_adv_enable_params {
	__u8  handle;
	__u8  max_adv_events;
	__u16 duration_10ms;
	__u8  _reserved[4];
} __attribute__((packed));

struct sle_inject_adv {
	__u8  addr[6];
	__s8  rssi;
	__u8  discovery_level;
	__u8  name[32];
	__u8  name_len;
	__u8  _reserved[7];
} __attribute__((packed));

struct sle_inject_raw_adv {
	__s8  rssi;
	__u8  _pad;
	__u16 pdu_len;
	__u8  pdu_data[264];
} __attribute__((packed));

/* --- Connection management ---------------------------------------------- */

struct sle_connect_params {
	__u8  peer_addr[6];
	__u8  gt_role;
	__u8  bandwidth;
	__u8  mcs_index;
	__u8  _pad;
	__u16 timeout_10ms;
	__u8  _reserved[4];
} __attribute__((packed));

struct sle_conn_info {
	__u64 tx_bytes;
	__u64 rx_bytes;
	__u16 handle;
	__u16 event_group_period;
	__u16 supervision_timeout;
	__u16 tx_pending;
	__u16 rx_pending;
	__u8  state;
	__u8  peer_addr[6];
	__u8  local_role;
	__u8  bandwidth_mhz;
	__u8  mcs_index;
	__u8  tx_seq;
	__u8  rx_seq;
	__u16 data_mtu;
	__u16 data_mps;
	__u16 svc_mtu;
	__u8  data_mode;
	__u8  ssap_info_exchanged;
	__u16 ssap_mtu;
	__u16 smtc_tx_credits;
	__u16 smtc_rx_credits;
	__u16 dudtc_tx_credits;
	__u16 dudtc_rx_credits;
} __attribute__((packed));

struct sle_conn_data {
	__u16 handle;
	__u16 length;
	__u8  data[255];
	__u8  _reserved;
} __attribute__((packed));

struct sle_inject_conn_resp {
	__u16 handle;
	__u8  response_type;
	__u8  bandwidth_mhz;
	__u8  mcs_index;
	__u8  _pad;
	__u16 supervision_timeout;
	__u16 data_mtu;
	__u16 data_mps;
} __attribute__((packed));

struct sle_conn_list {
	__u16 count;
	__u16 _pad;
	__u16 handles[8];
	__u8  _reserved[4];
} __attribute__((packed));

struct sle_conn_mtu_params {
	__u16 handle;
	__u16 mtu;
	__u16 mps;
	__u16 _pad;
} __attribute__((packed));

/* --- AFH (Adaptive Frequency Hopping) ----------------------------------- */

struct sle_afh_map_params {
	__u16 handle;
	__u8  min_channels;
	__u8  _pad;
	__u8  map[10];
	__u8  used_count;
	__u8  _pad2;
} __attribute__((packed));

struct sle_afh_rssi_report {
	__u16 handle;
	__u8  channel;
	__s8  rssi_dbm;
} __attribute__((packed));

struct sle_afh_classify_params {
	__u16 handle;
	__s8  threshold_dbm;
	__u8  min_channels;
	__u8  map_out[10];
	__u8  used_count;
	__u8  _pad;
} __attribute__((packed));

struct sle_afh_hop_info {
	__u16 handle;
	__u8  channel;
	__u8  _pad;
	__u16 freq_mhz;
	__u16 event_counter;
} __attribute__((packed));

struct sle_afh_retx_report {
	__u16 handle;
	__u8  channel;
	__u8  retransmitted;
} __attribute__((packed));

/* --- Security management ------------------------------------------------ */

struct sle_psk_params {
	__u8 psk[16];
} __attribute__((packed));

struct sle_pair_params {
	__u8 method;
	__u8 _reserved[3];
} __attribute__((packed));

struct sle_sec_info {
	__u8 state;
	__u8 method;
	__u8 mode;
	__u8 enc_enabled;
	__u8 enc_key_fingerprint[4];
	__u8 _reserved[8];
} __attribute__((packed));

struct sle_hash_test {
	__u16 in_len;
	__u16 _pad;
	__u8  data[220];
	__u8  digest[32];
} __attribute__((packed));

struct sle_sm4_block_test {
	__u8  key[16];
	__u8  input[16];
	__u8  output[16];
	__u8  decrypt;
	__u8  _pad[15];
};

struct sle_hmac_test {
	__u16 key_len;
	__u16 data_len;
	__u8  key[64];
	__u8  data[160];
	__u8  digest[32];
};

struct sle_oob_data {
	__u8 data[64];
} __attribute__((packed));

struct sle_passkey_input {
	__u32 passkey;
} __attribute__((packed));

struct sle_password_params {
	__u8  len;
	__u8  _reserved[3];
	__u8  data[32];
} __attribute__((packed));

/* --- RAL / RPA management ----------------------------------------------- */

struct sle_ral_add_params {
	__u8  resolve_algo;
	__u8  peer_id_type;
	__u8  peer_irkid;
	__u8  local_irkid;
	__u8  peer_id[6];
	__u8  _reserved[2];
	__u8  peer_irk[16];
	__u8  local_irk[16];
} __attribute__((packed));

struct sle_ral_remove_params {
	__u8  peer_id_type;
	__u8  _reserved;
	__u8  peer_id[6];
} __attribute__((packed));

struct sle_ral_query_params {
	__u8  id_type;
	__u8  _reserved;
	__u8  id[6];
	__u8  rpa[6];
	__u8  _pad[2];
} __attribute__((packed));

/* --- Narrowband AFH measurement (T/XS 10003-2025 §8.7) ----------------- */

struct sle_meas_cap {
	__u8  meas_types;
	__u8  max_instances;
	__u8  antenna_count;
	__u8  _reserved;
} __attribute__((packed));

struct sle_meas_link_param {
	__u16 handle;
	__u8  meas_type;
	__u8  config_index;
	__u16 interval;
	__u16 duration;
} __attribute__((packed));

struct sle_meas_action {
	__u16 handle;
	__u8  action;
	__u8  config_index;
} __attribute__((packed));

/* --- SSAP service layer ------------------------------------------------- */

struct ssap_summary {
	__u16 service_count;
	__u16 property_count;
	__u16 total_entries;
	__u16 mtu;
	__u16 notification_count;
	__u8  _reserved[6];
} __attribute__((packed));

struct ssap_read_write {
	__u16 handle;
	__u16 length;
	__u8  data[252];
} __attribute__((packed));

struct ssap_service_entry {
	__u16 start_handle;
	__u16 end_handle;
	__u16 uuid16;
	__u8  primary;
	__u8  _pad;
} __attribute__((packed));

struct ssap_service_list {
	__u16 count;
	__u8  _pad[2];
	struct ssap_service_entry services[15];
} __attribute__((packed));

struct ssap_notification {
	__u16 handle;
	__u8  indication;
	__u8  length;
	__u8  data[252];
} __attribute__((packed));

struct ssap_add_service {
	__u16 uuid16;
	__u8  primary;
	__u8  _pad;
	__u8  uuid128[16];
	__u16 start_handle;
	__u8  _reserved[6];
} __attribute__((packed));

struct ssap_add_property {
	__u16 uuid16;
	__u8  ops;
	__u8  value_len;
	__u8  value[248];
	__u16 handle;
	__u8  _reserved[2];
} __attribute__((packed));

/* --- Power management --------------------------------------------------- */

struct sle_pm_info {
	__u8  state;
	__u8  force_active;
	__u8  power_pct;
	__u8  _pad;
	__u16 current_interval;
	__u16 supervision_timeout;
	__u16 latency;
	__u16 idle_count;
	__u32 transitions;
	__u64 active_events;
	__u64 sniff_events;
	__u64 idle_events;
	__u8  _reserved[8];
} __attribute__((packed));

struct sle_pm_state_cmd {
	__u8 target_state;
	__u8 _reserved[3];
} __attribute__((packed));

struct sle_pm_interval {
	__u16 min_interval;
	__u16 max_interval;
	__u16 latency;
	__u16 supervision_timeout;
} __attribute__((packed));

/* --- Sync link management ----------------------------------------------- */

struct sle_sync_cig_config {
	__u8  cig_id;
	__u8  link_count;
	__u8  adapt_mode;
	__u8  _pad;
	__u32 sdu_interval_g2t;
	__u32 sdu_interval_t2g;
	__u16 max_sdu_g2t;
	__u16 max_sdu_t2g;
	__u16 max_latency_g2t;
	__u16 max_latency_t2g;
	__u8  retransmit_g2t;
	__u8  retransmit_t2g;
	__u16 handles_out[8];
};

struct sle_sync_big_config {
	__u8  big_id;
	__u8  link_count;
	__u8  adapt_mode;
	__u8  _pad;
	__u32 sdu_interval_g2t;
	__u32 sdu_interval_t2g;
	__u16 max_sdu_g2t;
	__u16 max_sdu_t2g;
	__u16 max_latency_g2t;
	__u16 max_latency_t2g;
	__u8  retransmit_g2t;
	__u8  retransmit_t2g;
	__u16 handles_out[8];
};

struct sle_sync_create_cmd {
	__u8  group_id;
	__u8  link_count;
	__u8  _pad[2];
	__u16 acl_handles[8];
};

struct sle_sync_datapath_cmd {
	__u16 sync_handle;
	__u8  direction;
	__u8  path_id;
	__u8  codec_id;
	__u8  _pad[3];
};

struct sle_sync_link_info {
	__u16 sync_handle;
	__u16 acl_handle;
	__u8  group_id;
	__u8  stream_id;
	__u8  link_type;
	__u8  state;
	__u32 sdu_interval_g2t;
	__u32 sdu_interval_t2g;
	__u16 max_sdu_g2t;
	__u16 max_sdu_t2g;
	__u8  datapath_configured;
	__u8  _pad2[3];
};

/* --- DLI controller ----------------------------------------------------- */

struct sle_dli_info {
	__u8  bus;
	__u8  _pad[3];
	__u32 firmware_version;
	__u64 features;
	__u8  max_connections;
	__u8  max_adv_sets;
	__u8  transport_modes;
	__u8  measurement_cap;
	__u16 max_mtu;
	__u16 max_mps;
	__u16 security_cap;
	__u16 features_ext;
	__u8  name[32];
	__u8  _reserved[4];
} __attribute__((packed));

struct sle_dli_event {
	__u8  event_type;
	__u8  status;
	__u16 handle;
	__u16 opcode;
	__u16 data_len;
	__u8  data[240];
	__u8  addr[6];
	__u8  _pad[2];
};

/* --- PHY layer ---------------------------------------------------------- */

struct sle_phy_info {
	__u8  mcs_index;
	__u8  bandwidth_mhz;
	__u8  pilot_density;
	__s8  tx_power_dbm;
	__u8  mimo_mode;
	__u8  num_tx_ant;
	__u8  num_rx_ant;
	__u8  ofdm;
	__u32 data_rate_kbps;
	__u8  hop_channel;
	__u8  hop_increment;
	__u8  hop_used_channels;
	__u8  _pad;
	__u8  modulation;
	__u8  code_rate_num;
	__u8  code_rate_den;
	__u8  _reserved[5];
} __attribute__((packed));

struct sle_phy_mcs_cmd {
	__u8  mcs_index;
	__u8  _reserved[3];
} __attribute__((packed));

struct sle_phy_txpower_cmd {
	__s8  tx_power_dbm;
	__u8  _reserved[3];
} __attribute__((packed));

struct sle_phy_mcs_select {
	__u32 min_kbps;
	__u32 effective_kbps;
	__s16 sinr_db_x10;
	__u8  bandwidth_mhz;
	__u8  selected_mcs;
} __attribute__((packed));

struct sle_phy_hop_info {
	__u8  channel;
	__u8  _pad;
	__u16 freq_mhz;
	__u16 event_counter;
	__u8  _reserved[2];
} __attribute__((packed));

struct sle_phy_bw_cmd {
	__u8  bandwidth_mhz;
	__u8  _reserved[3];
} __attribute__((packed));

struct sle_sinr_thresholds {
	__s16 thresholds[13];
	__u8  _pad[2];
} __attribute__((packed));

/* --- Subsystem statistics ----------------------------------------------- */

struct sle_subsys_stats {
	__u16 dev_count;
	__u8  proto_count;
	__u8  binding_count;
	__u16 active_connections;
	__u16 mgmt_pending;
	__u32 total_conn_created;
	__u32 total_conn_completed;
	__u32 total_mgmt_submitted;
	__u32 total_mgmt_timeouts;
	__u8  power_state;
	__u8  _pad2[3];
	__u32 power_transitions;
	__u32 crc_errors;
} __attribute__((packed));

/* --- Event wire format -------------------------------------------------- */

struct sle_wire_event {
	__u8  event_type;
	__u8  payload_len;
	__u8  payload[40];
	__u8  _pad[2];
} __attribute__((packed));

struct sle_event_stats {
	__u32 pending;
	__u32 _pad;
	__u64 total_enqueued;
	__u64 total_dropped;
	__u64 total_delivered;
};

/* =========================================================================
 * IOCTL magic and command definitions
 * =========================================================================
 */

#define SL_MAGIC	'S'

/* --- Device management -------------------------------------------------- */

#define SL_IOCTL_DEV_REGISTER		_IO(SL_MAGIC, 0x01)
#define SL_IOCTL_DEV_UNREGISTER		_IOW(SL_MAGIC, 0x02, __u16)
#define SL_IOCTL_DEV_COUNT		_IOR(SL_MAGIC, 0x03, __u32)
#define SL_IOCTL_DEV_INFO		_IOR(SL_MAGIC, 0x04, struct sci_dev_info)
#define SL_IOCTL_DEV_SWITCH		_IOW(SL_MAGIC, 0x05, __u16)
#define SL_IOCTL_DEV_LIST		_IOR(SL_MAGIC, 0x06, __u16)

/**
 * SL_IOCTL_DEV_SELECT - Set per-fd device affinity.
 *
 * Unlike DEV_SWITCH (which changes the global active controller),
 * DEV_SELECT only affects the calling fd.  Subsequent ioctls on this
 * fd auto-switch to the bound device.
 *
 * @arg: __s16  -1 = follow global active, >= 0 = bind to device id.
 */
#define SL_IOCTL_DEV_SELECT		_IOW(SL_MAGIC, 0x07, __s16)

/**
 * SL_IOCTL_DEV_GET_ACTIVE - Get the effective device for this fd.
 *
 * Returns the per-fd target if set, otherwise the global active_dev_id.
 * 0xFFFF means no device is active.
 *
 * @arg: __u16 (output)
 */
#define SL_IOCTL_DEV_GET_ACTIVE		_IOR(SL_MAGIC, 0x08, __u16)

/* --- Advertising / scanning --------------------------------------------- */

#define SL_IOCTL_START_ADV		_IOW(SL_MAGIC, 0x10, struct sle_adv_params)
#define SL_IOCTL_STOP_ADV		_IO(SL_MAGIC, 0x11)
#define SL_IOCTL_START_SCAN		_IOW(SL_MAGIC, 0x12, struct sle_scan_params)
#define SL_IOCTL_STOP_SCAN		_IO(SL_MAGIC, 0x13)

/* --- Extended advertising ----------------------------------------------- */

#define SL_IOCTL_EXT_ADV_CONFIGURE	_IOW(SL_MAGIC, 0x14, struct sle_ext_adv_config)
#define SL_IOCTL_EXT_ADV_SET_DATA	_IOW(SL_MAGIC, 0x15, struct sle_ext_adv_data)
#define SL_IOCTL_EXT_ADV_ENABLE		_IOW(SL_MAGIC, 0x16, __u8)
#define SL_IOCTL_EXT_ADV_DISABLE	_IOW(SL_MAGIC, 0x17, __u8)
#define SL_IOCTL_EXT_ADV_REMOVE		_IOW(SL_MAGIC, 0x18, __u8)
#define SL_IOCTL_EXT_ADV_INFO		_IOWR(SL_MAGIC, 0x19, struct sle_ext_adv_info)
#define SL_IOCTL_EXT_ADV_ENABLE_EX	_IOW(SL_MAGIC, 0x1A, struct sle_ext_adv_enable_params)
#define SL_IOCTL_EXT_ADV_TICK		_IO(SL_MAGIC, 0x1B)

/* --- Advertising injection / scan results ------------------------------- */

#define SL_IOCTL_INJECT_ADV		_IOW(SL_MAGIC, 0x20, struct sle_inject_adv)
#define SL_IOCTL_SCAN_RESULT_COUNT	_IO(SL_MAGIC, 0x21)
#define SL_IOCTL_INJECT_RAW_ADV		_IOW(SL_MAGIC, 0x22, struct sle_inject_raw_adv)

/* --- Extended scan filter (T/XS 20001-2025 §6.4) ------------------------ */

#define SL_IOCTL_SET_SCAN_FILTER	_IOW(SL_MAGIC, 0x23, struct sle_scan_filter)
#define SL_IOCTL_CLEAR_SCAN_FILTER	_IO(SL_MAGIC, 0x24)

/* --- Connection management ---------------------------------------------- */

#define SL_IOCTL_CONNECT		_IOW(SL_MAGIC, 0x30, struct sle_connect_params)
#define SL_IOCTL_DISCONNECT		_IOW(SL_MAGIC, 0x31, __u16)
#define SL_IOCTL_CONN_INFO		_IOWR(SL_MAGIC, 0x32, struct sle_conn_info)
#define SL_IOCTL_CONN_SEND		_IOW(SL_MAGIC, 0x33, struct sle_conn_data)
#define SL_IOCTL_CONN_RECV		_IOWR(SL_MAGIC, 0x34, struct sle_conn_data)
#define SL_IOCTL_INJECT_CONN_RESP	_IOW(SL_MAGIC, 0x35, struct sle_inject_conn_resp)
#define SL_IOCTL_INJECT_CONN_DATA	_IOW(SL_MAGIC, 0x36, struct sle_conn_data)
#define SL_IOCTL_CONN_COUNT		_IO(SL_MAGIC, 0x37)
#define SL_IOCTL_CONN_LIST		_IOR(SL_MAGIC, 0x38, struct sle_conn_list)
#define SL_IOCTL_SET_CONN_MTU		_IOW(SL_MAGIC, 0x39, struct sle_conn_mtu_params)

/* --- AFH (Adaptive Frequency Hopping) ----------------------------------- */

#define SL_IOCTL_AFH_SET_MAP		_IOW(SL_MAGIC, 0x3A, struct sle_afh_map_params)
#define SL_IOCTL_AFH_GET_MAP		_IOWR(SL_MAGIC, 0x3B, struct sle_afh_map_params)
#define SL_IOCTL_AFH_REPORT_RSSI	_IOW(SL_MAGIC, 0x3C, struct sle_afh_rssi_report)
#define SL_IOCTL_AFH_CLASSIFY		_IOWR(SL_MAGIC, 0x3D, struct sle_afh_classify_params)
#define SL_IOCTL_AFH_HOP_NEXT		_IOWR(SL_MAGIC, 0x3E, struct sle_afh_hop_info)
#define SL_IOCTL_AFH_REPORT_RETX	_IOW(SL_MAGIC, 0x3F, struct sle_afh_retx_report)

/* --- Security management ------------------------------------------------ */

#define SL_IOCTL_SEC_SET_PSK		_IOW(SL_MAGIC, 0x40, struct sle_psk_params)
#define SL_IOCTL_SEC_PAIR		_IOW(SL_MAGIC, 0x41, struct sle_pair_params)
#define SL_IOCTL_SEC_INFO		_IOR(SL_MAGIC, 0x42, struct sle_sec_info)
#define SL_IOCTL_SEC_ENCRYPT_ON		_IO(SL_MAGIC, 0x43)
#define SL_IOCTL_SEC_SM3_TEST		_IOW(SL_MAGIC, 0x44, struct sle_hash_test)
#define SL_IOCTL_SEC_SM4_ENC_TEST	_IOW(SL_MAGIC, 0x45, struct sle_conn_data)
#define SL_IOCTL_SEC_SM4_DEC_TEST	_IOW(SL_MAGIC, 0x46, struct sle_conn_data)
#define SL_IOCTL_SEC_SM4_BLOCK_TEST	_IOWR(SL_MAGIC, 0x47, struct sle_sm4_block_test)
#define SL_IOCTL_SEC_HMAC_TEST		_IOWR(SL_MAGIC, 0x48, struct sle_hmac_test)
#define SL_IOCTL_SEC_RESET		_IO(SL_MAGIC, 0x49)
#define SL_IOCTL_SEC_GET_PASSKEY	_IOR(SL_MAGIC, 0x4A, __u32)
#define SL_IOCTL_SEC_CONFIRM_PASSKEY	_IO(SL_MAGIC, 0x4B)
#define SL_IOCTL_SEC_REJECT_PASSKEY	_IO(SL_MAGIC, 0x4C)
#define SL_IOCTL_SEC_SET_OOB		_IOW(SL_MAGIC, 0x4D, struct sle_oob_data)
#define SL_IOCTL_SEC_INPUT_PASSKEY	_IOW(SL_MAGIC, 0x4E, struct sle_passkey_input)
#define SL_IOCTL_SEC_SET_PASSWORD	_IOW(SL_MAGIC, 0x4F, struct sle_password_params)

/* --- SSAP service layer ------------------------------------------------- */

#define SL_IOCTL_SSAP_REGISTER_SVC	_IO(SL_MAGIC, 0x50)
#define SL_IOCTL_SSAP_INFO		_IOR(SL_MAGIC, 0x51, struct ssap_summary)
#define SL_IOCTL_SSAP_READ		_IOWR(SL_MAGIC, 0x52, struct ssap_read_write)
#define SL_IOCTL_SSAP_WRITE		_IOW(SL_MAGIC, 0x53, struct ssap_read_write)
#define SL_IOCTL_SSAP_FIND_SVC		_IOR(SL_MAGIC, 0x54, struct ssap_service_list)
#define SL_IOCTL_SSAP_NOTIFY		_IOW(SL_MAGIC, 0x55, __u16)
#define SL_IOCTL_SSAP_DEQUEUE_NTF	_IOR(SL_MAGIC, 0x56, struct ssap_notification)
#define SL_IOCTL_SSAP_ADD_SVC		_IOWR(SL_MAGIC, 0x57, struct ssap_add_service)
#define SL_IOCTL_SSAP_ADD_PROP		_IOWR(SL_MAGIC, 0x58, struct ssap_add_property)
#define SL_IOCTL_SSAP_REMOVE_SVC	_IOW(SL_MAGIC, 0x59, __u16)

/* --- Remote SSAP client-side operations --------------------------------- */

struct ssap_remote_cmd {
	__u16 conn_handle;
	__u8  _reserved[2];
};

struct ssap_remote_discover {
	__u16 conn_handle;
	__u16 start_handle;
	__u16 end_handle;
	__u16 count;		/* output: number of entries discovered */
};

struct ssap_remote_read_write {
	__u16 conn_handle;
	__u16 handle;
	__u16 length;
	__u8  _pad[2];
	__u8  data[248];
};

#define SL_IOCTL_SSAP_EXCHANGE_INFO	_IOW(SL_MAGIC, 0x5A, struct ssap_remote_cmd)
#define SL_IOCTL_SSAP_REMOTE_DISCOVER	_IOWR(SL_MAGIC, 0x5B, struct ssap_remote_discover)
#define SL_IOCTL_SSAP_REMOTE_READ	_IOWR(SL_MAGIC, 0x5C, struct ssap_remote_read_write)
#define SL_IOCTL_SSAP_REMOTE_WRITE	_IOW(SL_MAGIC, 0x5D, struct ssap_remote_read_write)
#define SL_IOCTL_SSAP_REMOTE_EVENT	_IOR(SL_MAGIC, 0x5E, struct ssap_notification)

/* --- Power management --------------------------------------------------- */

#define SL_IOCTL_PM_INFO		_IOR(SL_MAGIC, 0x60, struct sle_pm_info)
#define SL_IOCTL_PM_SET_STATE		_IOW(SL_MAGIC, 0x61, struct sle_pm_state_cmd)
#define SL_IOCTL_PM_SET_INTERVAL	_IOW(SL_MAGIC, 0x62, struct sle_pm_interval)
#define SL_IOCTL_PM_FORCE_ACTIVE	_IOW(SL_MAGIC, 0x63, __u8)
#define SL_IOCTL_PM_TICK		_IO(SL_MAGIC, 0x64)
#define SL_IOCTL_PM_ACTIVITY		_IO(SL_MAGIC, 0x65)

/* --- Sync link management ----------------------------------------------- */

#define SL_IOCTL_SYNC_UCAST_PARAM	_IOWR(SL_MAGIC, 0x66, struct sle_sync_cig_config)
#define SL_IOCTL_SYNC_UCAST_CREATE	_IOW(SL_MAGIC, 0x67, struct sle_sync_create_cmd)
#define SL_IOCTL_SYNC_UCAST_REMOVE	_IOW(SL_MAGIC, 0x68, __u8)
#define SL_IOCTL_SYNC_MCAST_PARAM	_IOWR(SL_MAGIC, 0x69, struct sle_sync_big_config)
#define SL_IOCTL_SYNC_MCAST_CREATE	_IOW(SL_MAGIC, 0x6A, struct sle_sync_create_cmd)
#define SL_IOCTL_SYNC_MCAST_REMOVE	_IOW(SL_MAGIC, 0x6B, __u8)
#define SL_IOCTL_SYNC_DATAPATH_CFG	_IOW(SL_MAGIC, 0x6C, struct sle_sync_datapath_cmd)
#define SL_IOCTL_SYNC_DATAPATH_REMOVE	_IOW(SL_MAGIC, 0x6D, __u16)
#define SL_IOCTL_SYNC_INFO		_IOWR(SL_MAGIC, 0x6E, struct sle_sync_link_info)

/* --- Event notification ------------------------------------------------- */

#define SL_IOCTL_EVENT_COUNT		_IO(SL_MAGIC, 0x70)
#define SL_IOCTL_EVENT_STATS		_IOR(SL_MAGIC, 0x71, struct sle_event_stats)

/* --- DLI controller ----------------------------------------------------- */

#define SL_IOCTL_DLI_INFO		_IOR(SL_MAGIC, 0x80, struct sle_dli_info)
#define SL_IOCTL_USB_DEV_COUNT		_IO(SL_MAGIC, 0x81)
#define SL_IOCTL_DLI_POLL_EVENT		_IOR(SL_MAGIC, 0x82, struct sle_dli_event)
#define SL_IOCTL_DLI_RESET		_IO(SL_MAGIC, 0x83)

/* --- Subsystem statistics ----------------------------------------------- */

#define SL_IOCTL_SUBSYS_STATS		_IOR(SL_MAGIC, 0x86, struct sle_subsys_stats)

/* --- PHY layer ---------------------------------------------------------- */

#define SL_IOCTL_PHY_INFO		_IOR(SL_MAGIC, 0x90, struct sle_phy_info)
#define SL_IOCTL_PHY_SET_MCS		_IOW(SL_MAGIC, 0x91, struct sle_phy_mcs_cmd)
#define SL_IOCTL_PHY_SET_TXPOWER	_IOW(SL_MAGIC, 0x92, struct sle_phy_txpower_cmd)
#define SL_IOCTL_PHY_MCS_SELECT		_IOWR(SL_MAGIC, 0x93, struct sle_phy_mcs_select)
#define SL_IOCTL_PHY_HOP_NEXT		_IOR(SL_MAGIC, 0x94, struct sle_phy_hop_info)
#define SL_IOCTL_PHY_SET_BW		_IOW(SL_MAGIC, 0x95, struct sle_phy_bw_cmd)
#define SL_IOCTL_PHY_GET_SINR		_IOR(SL_MAGIC, 0x96, struct sle_sinr_thresholds)
#define SL_IOCTL_PHY_SET_SINR		_IOW(SL_MAGIC, 0x97, struct sle_sinr_thresholds)

/* --- Capability / channel negotiation ----------------------------------- */

struct sle_conn_peer_cap {
	__u16	handle;
	__u8	features[10];
	__u8	features_valid;
	__u8	version;
	__u16	manufacturer;
	__u16	subversion;
	__u8	version_valid;
	__u8	_reserved[3];
};

struct sle_conn_param_update {
	__u16	handle;
	__u16	interval_min;
	__u16	interval_max;
	__u16	latency;
	__u16	supervision_timeout;
	__u8	_reserved[2];
};

struct sle_conn_phy_update {
	__u16	handle;
	__u8	mcs_index;
	__u8	bandwidth_mhz;
};

#define SL_IOCTL_CONN_READ_PEER_FEATURES _IOWR(SL_MAGIC, 0x98, struct sle_conn_peer_cap)
#define SL_IOCTL_CONN_READ_PEER_VERSION	 _IOWR(SL_MAGIC, 0x99, struct sle_conn_peer_cap)
#define SL_IOCTL_CONN_UPDATE_PARAMS	 _IOW(SL_MAGIC, 0x9A, struct sle_conn_param_update)
#define SL_IOCTL_CONN_PHY_UPDATE	 _IOW(SL_MAGIC, 0x9B, struct sle_conn_phy_update)

/* --- Role management ---------------------------------------------------- */

#define SL_IOCTL_SET_ROLE		_IOW(SL_MAGIC, 0xA0, __u8)
#define SL_IOCTL_GET_ROLE		_IOR(SL_MAGIC, 0xA1, __u8)

/* --- RAL / RPA management ----------------------------------------------- */

#define SL_IOCTL_RAL_ADD		_IOW(SL_MAGIC, 0xB0, struct sle_ral_add_params)
#define SL_IOCTL_RAL_REMOVE		_IOW(SL_MAGIC, 0xB1, struct sle_ral_remove_params)
#define SL_IOCTL_RAL_CLEAR		_IO(SL_MAGIC, 0xB2)
#define SL_IOCTL_RAL_SIZE		_IOR(SL_MAGIC, 0xB3, __u8)
#define SL_IOCTL_RAL_READ_PEER_RPA	_IOWR(SL_MAGIC, 0xB4, struct sle_ral_query_params)
#define SL_IOCTL_RAL_READ_LOCAL_RPA	_IOWR(SL_MAGIC, 0xB5, struct sle_ral_query_params)
#define SL_IOCTL_RPA_ENABLE		_IOW(SL_MAGIC, 0xB6, __u8)
#define SL_IOCTL_RPA_SET_TIMEOUT	_IOW(SL_MAGIC, 0xB7, __u16)

/* --- Narrowband AFH measurement (T/XS 10003-2025 §8.7) ----------------- */

#define SL_IOCTL_MEAS_READ_CAP		_IOR(SL_MAGIC, 0xC0, struct sle_meas_cap)
#define SL_IOCTL_MEAS_SET_LINK_PARAM	_IOW(SL_MAGIC, 0xC1, struct sle_meas_link_param)
#define SL_IOCTL_MEAS_ACTION		_IOW(SL_MAGIC, 0xC2, struct sle_meas_action)
#define SL_IOCTL_MEAS_ENABLE		_IOW(SL_MAGIC, 0xC3, __u8)

/* =========================================================================
 * Event type constants
 * =========================================================================
 */

#define SLE_EVT_CONN_STATE	0x01
#define SLE_EVT_ADV_REPORT	0x02
#define SLE_EVT_DATA_RECV	0x03
#define SLE_EVT_SEC_CHANGED	0x04
#define SLE_EVT_PWR_CHANGED	0x05
#define SLE_EVT_HW_ERROR	0x06

/* Narrowband / measurement events (§9.1.33–§9.1.39) */
#define SLE_EVT_NB_MEAS_INFO		0x22
#define SLE_EVT_NB_MEAS_STATE		0x23
#define SLE_EVT_NB_MEAS_PARAM		0x24
#define SLE_EVT_LOCAL_NB_MEAS_CAP	0x25
#define SLE_EVT_PEER_NB_MEAS_CAP	0x26
#define SLE_EVT_MEAS_STATE_CHANGE	0x27
#define SLE_EVT_MEAS_QUANTITY		0x28

#endif /* _UAPI_LINUX_SPARKLINK_IOCTL_H */

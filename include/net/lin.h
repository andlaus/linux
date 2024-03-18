/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (C) 2024 hexDEV GmbH - https://hexdev.de */

#ifndef _NET_LIN_H_
#define _NET_LIN_H_

#include <linux/can/dev.h>
#include <linux/device.h>

#define LIN_NUM_IDS		64
#define LIN_HEADER_SIZE		3
#define LIN_MAX_DLEN		8

#define LIN_MAX_BAUDRATE	20000
#define LIN_MIN_BAUDRATE	1000
#define LIN_DEFAULT_BAUDRATE	9600
#define LIN_SYNC_BYTE		0x55

#define LIN_ID_MASK		0x0000003FU
/* special ID descriptions for LIN */
#define LIN_RXOFFLOAD_DATA_FLAG	0x00000200U
#define LIN_ENHANCED_CKSUM_FLAG	0x00000100U

static const unsigned char lin_id_parity_tbl[] = {
	0x80, 0xc0, 0x40, 0x00, 0xc0, 0x80, 0x00, 0x40,
	0x00, 0x40, 0xc0, 0x80, 0x40, 0x00, 0x80, 0xc0,
	0x40, 0x00, 0x80, 0xc0, 0x00, 0x40, 0xc0, 0x80,
	0xc0, 0x80, 0x00, 0x40, 0x80, 0xc0, 0x40, 0x00,
	0x00, 0x40, 0xc0, 0x80, 0x40, 0x00, 0x80, 0xc0,
	0x80, 0xc0, 0x40, 0x00, 0xc0, 0x80, 0x00, 0x40,
	0xc0, 0x80, 0x00, 0x40, 0x80, 0xc0, 0x40, 0x00,
	0x40, 0x00, 0x80, 0xc0, 0x00, 0x40, 0xc0, 0x80,
};

#define LIN_GET_ID(PID)		((PID) & LIN_ID_MASK)
#define LIN_FORM_PID(ID)	(LIN_GET_ID(ID) | \
					lin_id_parity_tbl[LIN_GET_ID(ID)])
#define LIN_GET_PARITY(PID)	((PID) & ~LIN_ID_MASK)
#define LIN_CHECK_PID(PID)	(LIN_GET_PARITY(PID) == \
					LIN_GET_PARITY(LIN_FORM_PID(PID)))

enum lin_mode {
	LINBUS_RESPONDER = 0,
	LINBUS_COMMANDER,
};

struct lin_device {
	struct can_priv can;  /* must be the first member */
	struct net_device *ndev;
	struct device *dev;
	const struct lin_device_ops *ldev_ops;
	struct workqueue_struct *wq;
	struct work_struct tx_work;
	bool tx_busy;
	struct sk_buff *tx_skb;
	enum lin_mode lmode;
};

enum lin_checksum_mode {
	LINBUS_CLASSIC = 0,
	LINBUS_ENHANCED,
};

struct lin_frame {
	u8 lin_id;
	u8 len;
	u8 data[LIN_MAX_DLEN];
	u8 checksum;
	enum lin_checksum_mode checksum_mode;
};

struct lin_responder_answer {
	bool is_active;
	bool is_event_frame;
	u8 event_associated_id;
	struct lin_frame lf;
};

struct lin_device_ops {
	int (*ldo_tx)(struct lin_device *ldev, const struct lin_frame *frame);
	int (*update_lin_mode)(struct lin_device *ldev, enum lin_mode lm);
	int (*update_bitrate)(struct lin_device *ldev, u16 bitrate);
	int (*update_responder_answer)(struct lin_device *ldev,
				       const struct lin_responder_answer *answ);
	int (*get_responder_answer)(struct lin_device *ldev, u8 id,
				    struct lin_responder_answer *answ);
};

int lin_rx(struct lin_device *ldev, const struct lin_frame *lf);

u8 lin_get_checksum(u8 pid, u8 n_of_bytes, const u8 *bytes,
		    enum lin_checksum_mode cm);

struct lin_device *register_lin(struct device *dev,
				const struct lin_device_ops *ldops);
void unregister_lin(struct lin_device *ldev);

#endif /* _NET_LIN_H_ */

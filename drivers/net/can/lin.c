// SPDX-License-Identifier: GPL-2.0+
/* Copyright (C) 2024 hexDEV GmbH - https://hexdev.de */

#include <linux/can/core.h>
#include <linux/can/dev.h>
#include <linux/can/error.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <net/lin.h>

static ssize_t lin_responder_cfg_show(struct device *dev,
				      struct device_attribute *attr, char *buf)
{
	struct net_device *ndev = to_net_dev(dev);
	struct lin_device *ldev = netdev_priv(ndev);
	ssize_t count = 0;
	struct lin_responder_answer answ;
	int i, k, ret;

	if (!ldev->ldev_ops->get_responder_answer)
		return 0;

	count += scnprintf(buf + count, PAGE_SIZE - count,
			   "%-3s %-6s %-11s %-9s %-9s %-2s %-23s %-6s\n",
			   "id", "state", "cksum-mode", "is_event", "event_id",
			   "n", "data", "cksum");

	for (i = 0; i < LIN_NUM_IDS && count < PAGE_SIZE; i++) {
		ret = ldev->ldev_ops->get_responder_answer(ldev, i, &answ);
		if (ret)
			continue;

		count += scnprintf(buf + count, PAGE_SIZE - count,
				   "%-3u %-6s %-11s %-9s %-9u %-2u ", i,
				   answ.is_active ? "active" : "off",
				   answ.lf.checksum_mode ? "enhanced" : "",
				   answ.is_event_frame ? "yes" : "no",
				   answ.event_associated_id,
				   answ.lf.len);

		for (k = 0; k < answ.lf.len; k++)
			count += scnprintf(buf + count, PAGE_SIZE - count,
					   "%02x ", answ.lf.data[k]);
		for (; k < 8; k++)
			count += scnprintf(buf + count, PAGE_SIZE - count,
					   "   ");
		if (answ.lf.len)
			count += scnprintf(buf + count, PAGE_SIZE - count,
					   " %02x", answ.lf.checksum);

		count += scnprintf(buf + count, PAGE_SIZE - count, "\n");
	}

	return count;
}

static const char *parse_and_advance(const char *buf, long *result, uint base)
{
	char num_str[5] = {0};
	int num_len = 0;

	while (*buf && isspace(*buf))
		buf++;
	while (*buf && isalnum(*buf) && num_len < sizeof(num_str) - 1)
		num_str[num_len++] = *buf++;
	if (kstrtol(num_str, base, result))
		return NULL;

	return buf;
}

static ssize_t lin_responder_cfg_store(struct device *dev,
				       struct device_attribute *attr,
				       const char *buf, size_t count)
{
	struct net_device *ndev = to_net_dev(dev);
	struct lin_device *ldev = netdev_priv(ndev);
	struct lin_responder_answer answ = { 0 };
	const char *ptr = buf;
	int ret;
	long v;

	if (!ldev->ldev_ops->update_responder_answer)
		return -EOPNOTSUPP;

	ptr = parse_and_advance(ptr, &v, 10);
	if (!ptr || v > LIN_ID_MASK)
		return -EINVAL;
	answ.lf.lin_id = v;

	ptr = parse_and_advance(ptr, &v, 2);
	if (!ptr)
		return -EINVAL;
	answ.is_active = v != 0;

	ptr = parse_and_advance(ptr, &v, 2);
	if (!ptr)
		return -EINVAL;
	answ.lf.checksum_mode = v != 0;

	ptr = parse_and_advance(ptr, &v, 2);
	if (!ptr)
		return -EINVAL;
	answ.is_event_frame = v != 0;

	ptr = parse_and_advance(ptr, &v, 10);
	if (!ptr || v > LIN_ID_MASK)
		return -EINVAL;
	answ.event_associated_id = v;

	ptr = parse_and_advance(ptr, &v, 10);
	if (!ptr || v > LIN_MAX_DLEN)
		return -EINVAL;
	answ.lf.len = v;

	for (int i = 0; i < answ.lf.len; i++) {
		ptr = parse_and_advance(ptr, &v, 16);
		if (!ptr)
			return -EINVAL;
		answ.lf.data[i] = v;
	}

	ret = ldev->ldev_ops->update_responder_answer(ldev, &answ);
	if (ret)
		return ret;

	return count;
}

static DEVICE_ATTR_RW(lin_responder_cfg);

static void lin_tx_work_handler(struct work_struct *ws)
{
	struct lin_device *ldev = container_of(ws, struct lin_device,
					       tx_work);
	struct net_device *ndev = ldev->ndev;
	struct canfd_frame *cfd;
	struct lin_frame lf;

	ldev->tx_busy = true;

	cfd = (struct canfd_frame *)ldev->tx_skb->data;
	lf.checksum_mode = (cfd->can_id & LIN_ENHANCED_CKSUM_FLAG) ?
			   LINBUS_ENHANCED : LINBUS_CLASSIC;
	lf.lin_id = (u8)(cfd->can_id & LIN_ID_MASK);
	lf.len = min(cfd->len, LIN_MAX_DLEN);
	memcpy(lf.data, cfd->data, lf.len);

	ret = ldev->ldev_ops->ldo_tx(ldev, &lf);
	if (ret) {
		DEV_STATS_INC(ndev, tx_dropped);
		netdev_err_once(ndev, "transmission failure %d\n", ret);
		goto lin_tx_out;
	}

	DEV_STATS_INC(ndev, tx_packets);
	DEV_STATS_ADD(ndev, tx_bytes, lf.len);
	ldev->tx_busy = false;
	netif_wake_queue(ndev);
}

static netdev_tx_t lin_start_xmit(struct sk_buff *skb,
				  struct net_device *ndev)
{
	struct lin_device *ldev = netdev_priv(ndev);

	if (ldev->tx_busy)
		return NETDEV_TX_BUSY;

	netif_stop_queue(ndev);
	ldev->tx_skb = skb;
	queue_work(ldev->wq, &ldev->tx_work);

	return NETDEV_TX_OK;
}

static int lin_open(struct net_device *ndev)
{
	struct lin_device *ldev = netdev_priv(ndev);
	int ret;

	ldev->tx_busy = false;

	ret = open_candev(ndev);
	if (ret)
		return ret;

	netif_wake_queue(ndev);

	ldev->can.state = CAN_STATE_ERROR_ACTIVE;
	ndev->mtu = CANFD_MTU;

	return 0;
}

static int lin_stop(struct net_device *ndev)
{
	struct lin_device *ldev = netdev_priv(ndev);

	close_candev(ndev);

	flush_work(&ldev->tx_work);

	ldev->can.state = CAN_STATE_STOPPED;

	return 0;
}

static const struct net_device_ops lin_netdev_ops = {
	.ndo_open = lin_open,
	.ndo_stop = lin_stop,
	.ndo_start_xmit = lin_start_xmit,
	.ndo_change_mtu = can_change_mtu,
};

u8 lin_get_checksum(u8 pid, u8 n_of_bytes, const u8 *bytes,
		    enum lin_checksum_mode cm)
{
	uint csum = 0;
	int i;

	if (cm == LINBUS_ENHANCED)
		csum += pid;

	for (i = 0; i < n_of_bytes; i++) {
		csum += bytes[i];
		if (csum > 255)
			csum -= 255;
	}

	return (u8)(~csum & 0xff);
}
EXPORT_SYMBOL_GPL(lin_get_checksum);

static int lin_bump_rx_err(struct lin_device *ldev, const struct lin_frame *lf)
{
	struct net_device *ndev = ldev->ndev;
	struct can_frame cf = {0 };

	if (lf->lin_id > LIN_ID_MASK) {
		netdev_dbg(ndev, "id exceeds LIN max id\n");
		cf.can_id = CAN_ERR_FLAG | CAN_ERR_PROT;
		cf.data[3] = CAN_ERR_PROT_LOC_ID12_05;
	}

	if (lf->len > LIN_MAX_DLEN) {
		netdev_dbg(ndev, "frame exceeds number of bytes\n");
		cf.can_id = CAN_ERR_FLAG | CAN_ERR_PROT;
		cf.data[3] = CAN_ERR_PROT_LOC_DLC;
	}

	if (lf->len) {
		u8 checksum = lin_get_checksum(LIN_FORM_PID(lf->lin_id),
					       lf->len, lf->data,
					       lf->checksum_mode);

		if (checksum != lf->checksum) {
			netdev_dbg(ndev, "expected cksm: 0x%02x got: 0x%02x\n",
				   checksum, lf->checksum);
			cf.can_id = CAN_ERR_FLAG | CAN_ERR_PROT;
			cf.data[2] = CAN_ERR_PROT_FORM;
		}
	}

	if (cf.can_id & CAN_ERR_FLAG) {
		struct can_frame *err_cf;
		struct sk_buff *skb = alloc_can_err_skb(ndev, &err_cf);

		if (unlikely(!skb))
			return -ENOMEM;

		err_cf->can_id |= cf.can_id;
		memcpy(err_cf->data, cf.data, CAN_MAX_DLEN);

		netif_rx(skb);

		return -EREMOTEIO;
	}

	return 0;
}

int lin_rx(struct lin_device *ldev, const struct lin_frame *lf)
{
	struct net_device *ndev = ldev->ndev;
	struct can_frame *cf;
	struct sk_buff *skb;
	int ret;

	if (!ndev)
		return -ENODEV;

	ret = lin_bump_rx_err(ldev, lf);
	if (ret) {
		DEV_STATS_INC(ndev, rx_dropped);
		return ret;
	}

	skb = alloc_can_skb(ndev, &cf);
	if (unlikely(!skb)) {
		DEV_STATS_INC(ndev, rx_dropped);
		return -ENOMEM;
	}

	cf->can_id = lf->lin_id;
	cf->len = min(lf->len, LIN_MAX_DLEN);
	memcpy(cf->data, lf->data, cf->len);

	DEV_STATS_INC(ndev, rx_packets);
	DEV_STATS_ADD(ndev, rx_bytes, cf->len);

	netif_receive_skb(skb);

	return 0;
}
EXPORT_SYMBOL_GPL(lin_rx);

static int lin_set_bittiming(struct net_device *ndev)
{
	struct lin_device *ldev = netdev_priv(ndev);
	unsigned int bitrate;
	int ret;

	bitrate = ldev->can.bittiming.bitrate;
	ret = ldev->ldev_ops->update_bitrate(ldev, bitrate);

	return ret;
}

static const u32 lin_bitrate[] = { 1200, 2400, 4800, 9600, 19200 };

struct lin_device *register_lin(struct device *dev,
				const struct lin_device_ops *ldops)
{
	struct net_device *ndev;
	struct lin_device *ldev;
	int ret;

	if (!ldops || !ldops->ldo_tx || !ldops->update_bitrate) {
		netdev_err(ndev, "missing mandatory lin_device_ops\n");
		return ERR_PTR(-EOPNOTSUPP);
	}

	ndev = alloc_candev(sizeof(struct lin_device), 1);
	if (!ndev)
		return ERR_PTR(-ENOMEM);

	ldev = netdev_priv(ndev);

	ldev->ldev_ops = ldops;
	ndev->netdev_ops = &lin_netdev_ops;
	ndev->flags |= IFF_ECHO;
	ndev->mtu = CANFD_MTU;
	ldev->can.bittiming.bitrate = LIN_DEFAULT_BAUDRATE;
	ldev->can.ctrlmode = CAN_CTRLMODE_LIN;
	ldev->can.ctrlmode_supported = 0;
	ldev->can.bitrate_const = lin_bitrate;
	ldev->can.bitrate_const_cnt = ARRAY_SIZE(lin_bitrate);
	ldev->can.do_set_bittiming = lin_set_bittiming;
	ldev->ndev = ndev;
	ldev->dev = dev;

	SET_NETDEV_DEV(ndev, dev);

	ret = lin_set_bittiming(ndev);
	if (ret) {
		netdev_err(ndev, "set bittiming failed\n");
		goto exit_candev;
	}

	ret = register_candev(ndev);
	if (ret)
		goto exit_candev;

	ret = device_create_file(&ndev->dev, &dev_attr_lin_responder_cfg);
	if (ret) {
		netdev_err(ndev, "Failed to create sysfs entry: %d\n", ret);
		goto exit_unreg;
	}

	ldev->wq = alloc_workqueue(dev_name(dev), WQ_FREEZABLE | WQ_MEM_RECLAIM,
				   0);
	if (!ldev->wq)
		goto exit_rm_file;

	INIT_WORK(&ldev->tx_work, lin_tx_work_handler);

	netdev_info(ndev, "LIN initialized.\n");

	return ldev;

exit_rm_file:
	device_remove_file(dev, &dev_attr_lin_responder_cfg);
exit_unreg:
	unregister_candev(ndev);
exit_candev:
	free_candev(ndev);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(register_lin);

void unregister_lin(struct lin_device *ldev)
{
	struct net_device *ndev = ldev->ndev;

	unregister_candev(ndev);
	device_remove_file(ldev->dev, &dev_attr_lin_responder_cfg);
	destroy_workqueue(ldev->wq);
	free_candev(ndev);
}
EXPORT_SYMBOL_GPL(unregister_lin);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Christoph Fritz <christoph.fritz@hexdev.de>");
MODULE_DESCRIPTION("LIN bus to CAN glue driver");

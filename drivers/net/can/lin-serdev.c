// SPDX-License-Identifier: GPL-2.0+
/* Copyright (C) 2024 hexDEV GmbH - https://hexdev.de */

#include <linux/module.h>
#include <linux/wait.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <net/lin.h>
#include <linux/of.h>
#include <linux/serdev.h>
#include <linux/slab.h>
#include <linux/kfifo.h>
#include <linux/workqueue.h>
#include <linux/tty.h>

#define LINSER_SAMPLES_PER_CHAR		10
#define LINSER_TX_BUFFER_SIZE		11
#define LINSER_RX_FIFO_SIZE		256
#define LINSER_PRASEBUFFER		24

struct linser_rx {
	u8 data;
	u8 flag;
};

enum linser_rx_status {
	NEED_MORE = -1,
	MODE_OK = 0,
	NEED_FORCE,
};

struct linser_priv {
	struct lin_device *lin_dev;
	struct serdev_device *serdev;
	DECLARE_KFIFO_PTR(rx_fifo, struct linser_rx);
	struct delayed_work rx_work;
	ulong break_usleep_min;
	ulong break_usleep_max;
	ulong post_break_usleep_min;
	ulong post_break_usleep_max;
	ulong force_timeout_jfs;
	struct lin_responder_answer respond_answ[LIN_NUM_IDS];
	struct mutex resp_lock; /* protects respond_answ */
};

static int linser_get_responder_answer(struct lin_device *ldev, u8 id,
				       struct lin_responder_answer *answ)
{
	struct serdev_device *serdev = to_serdev_device(ldev->dev);
	struct linser_priv *priv = serdev_device_get_drvdata(serdev);
	struct lin_responder_answer *r = &priv->respond_answ[id];

	if (!answ)
		return -EINVAL;

	memcpy(answ, r, sizeof(struct lin_responder_answer));

	return 0;
}

static int linser_update_resp_answer(struct lin_device *ldev,
				     const struct lin_responder_answer *answ)
{
	struct serdev_device *serdev = to_serdev_device(ldev->dev);
	struct linser_priv *priv = serdev_device_get_drvdata(serdev);
	struct lin_responder_answer *r = &priv->respond_answ[answ->lf.lin_id];

	if (!answ)
		return -EINVAL;

	mutex_lock(&priv->resp_lock);
	memcpy(r, answ, sizeof(struct lin_responder_answer));
	r->lf.checksum = lin_get_checksum(LIN_FORM_PID(answ->lf.lin_id),
					  answ->lf.len,
					  answ->lf.data,
					  answ->lf.checksum_mode);
	mutex_unlock(&priv->resp_lock);

	return 0;
}

static int linser_send_break(struct linser_priv *priv)
{
	struct serdev_device *serdev = priv->serdev;
	int ret;

	ret = serdev_device_break_ctl(serdev, -1);
	if (ret)
		return ret;
	usleep_range(priv->break_usleep_min, priv->break_usleep_max);

	ret = serdev_device_break_ctl(serdev, 0);
	if (ret)
		return ret;
	usleep_range(priv->post_break_usleep_min, priv->post_break_usleep_max);

	return 0;
}

static int linser_ldo_tx(struct lin_device *ldev, const struct lin_frame *lf)
{
	struct serdev_device *serdev = to_serdev_device(ldev->dev);
	struct linser_priv *priv = serdev_device_get_drvdata(serdev);
	u8 buf[LINSER_TX_BUFFER_SIZE];
	u8 pid = LIN_FORM_PID(lf->lin_id);
	u8 checksum;
	int i, ret;
	ssize_t write_len;

	buf[0] = LIN_SYNC_BYTE;
	buf[1] = pid;
	for (i = 0; i < lf->len; i++)
		buf[i + 2] = lf->data[i];

	checksum = lin_get_checksum(pid, lf->len, lf->data,
				    lf->checksum_mode);
	if (lf->len > 0)
		buf[i + 2] = checksum;

	ret = linser_send_break(priv);
	if (ret)
		return ret;

	write_len = serdev_device_write(serdev, buf, lf->len + 3, 0);
	if (write_len < lf->len + 3)
		return write_len < 0 ? (int)write_len : -EIO;

	serdev_device_wait_until_sent(serdev, 0);

	dev_dbg(&serdev->dev, "TX: ID=%d, n=%d, cnt=%ld, bytes=%*ph, cksm=%x\n",
		lf->lin_id, lf->len, write_len, lf->len,
		lf->data, checksum);

	return 0;
}

static void linser_derive_timings(struct linser_priv *priv, u16 bitrate)
{
	unsigned long break_baud = (bitrate * 2) / 3;
	unsigned long timeout_us;

	priv->break_usleep_min = (1000000UL * LINSER_SAMPLES_PER_CHAR) /
					break_baud;
	priv->break_usleep_max = priv->break_usleep_min + 50;
	priv->post_break_usleep_min = (1000000UL * 1 /* 1 bit */) / break_baud;
	priv->post_break_usleep_max = priv->post_break_usleep_min + 30;

	timeout_us = DIV_ROUND_CLOSEST(1000000UL * 256 /* bit */, bitrate);
	priv->force_timeout_jfs = usecs_to_jiffies(timeout_us);
}

static int linser_update_bitrate(struct lin_device *ldev, u16 bitrate)
{
	struct serdev_device *serdev = to_serdev_device(ldev->dev);
	struct linser_priv *priv = serdev_device_get_drvdata(serdev);
	unsigned int speed;

	speed = serdev_device_set_baudrate(serdev, bitrate);
	if (!bitrate || speed != bitrate)
		return -EINVAL;

	linser_derive_timings(priv, bitrate);

	return 0;
}

static struct lin_device_ops linser_lindev_ops = {
	.ldo_tx = linser_ldo_tx,
	.update_bitrate = linser_update_bitrate,
	.get_responder_answer = linser_get_responder_answer,
	.update_responder_answer = linser_update_resp_answer,
};

static bool linser_tx_frame_as_responder(struct linser_priv *priv, u8 id)
{
	struct lin_responder_answer *answ = &priv->respond_answ[id];
	struct serdev_device *serdev = priv->serdev;
	u8 buf[LINSER_TX_BUFFER_SIZE];
	u8 checksum, count, n;
	ssize_t write_len;

	mutex_lock(&priv->resp_lock);

	if (!answ->is_active)
		goto unlock_and_exit_false;

	if (answ->is_event_frame) {
		struct lin_responder_answer *e_answ;

		e_answ = &priv->respond_answ[answ->event_associated_id];
		n = min(e_answ->lf.len, LIN_MAX_DLEN);
		if (memcmp(answ->lf.data, e_answ->lf.data, n) != 0) {
			memcpy(answ->lf.data, e_answ->lf.data, n);
			checksum = lin_get_checksum(LIN_FORM_PID(answ->lf.lin_id),
						    n, e_answ->lf.data,
						    answ->lf.checksum_mode);
			answ = e_answ;
		} else {
			goto unlock_and_exit_false;
		}
	} else {
		checksum = answ->lf.checksum;
	}

	count = min(answ->lf.len, LIN_MAX_DLEN);
	memcpy(&buf[0], answ->lf.data, count);
	buf[count] = checksum;

	mutex_unlock(&priv->resp_lock);

	write_len = serdev_device_write(serdev, buf, count + 1, 0);
	if (write_len < count + 1)
		return false;

	serdev_device_wait_until_sent(serdev, 0);

	return true;

unlock_and_exit_false:
	mutex_unlock(&priv->resp_lock);
	return false;
}

static void linser_pop_fifo(struct linser_priv *priv, size_t n)
{
	struct serdev_device *serdev = priv->serdev;
	struct linser_rx dummy;
	size_t ret, i;

	for (i = 0; i < n; i++) {
		ret = kfifo_out(&priv->rx_fifo, &dummy, 1);
		if (ret != 1) {
			dev_err(&serdev->dev, "Failed to pop from FIFO\n");
			break;
		}
	}
}

static int linser_fill_frame(struct linser_priv *priv, struct lin_frame *lf)
{
	struct serdev_device *serdev = priv->serdev;
	struct linser_rx buf[LINSER_PRASEBUFFER];
	uint count = kfifo_out_peek(&priv->rx_fifo, buf, LINSER_PRASEBUFFER);
	uint i, b, brk = 0;

	memset(lf, 0, sizeof(struct lin_frame));

	if (count < 3)
		return NEED_MORE;

	if (buf[0].flag != TTY_BREAK || buf[1].data != LIN_SYNC_BYTE) {
		linser_pop_fifo(priv, 1); /* pop incorrect start */
		return NEED_MORE;
	} else if (!LIN_CHECK_PID(buf[2].data)) {
		linser_pop_fifo(priv, 3); /* pop incorrect header */
		return NEED_MORE;
	}

	lf->lin_id = LIN_GET_ID(buf[2].data);

	/* from here on we do have a correct LIN header */

	if (count == 3)
		return linser_tx_frame_as_responder(priv, lf->lin_id) ?
		       NEED_MORE : NEED_FORCE;

	for (b = 3; b < count && b < LINSER_PRASEBUFFER && b < 12; b++) {
		if (buf[b].flag == TTY_BREAK) {
			brk = b;
			break;
		}
		lf->len++;
	}
	if (lf->len)
		lf->len -= 1; /* account for checksum */

	if (brk == 3)
		return MODE_OK;

	if (brk == 4) {
		/* suppress wrong answer data-byte in between PID and break
		 * because checksum is missing
		 */
		return MODE_OK;
	}

	for (i = 0; i < lf->len; i++)
		lf->data[i] = buf[3 + i].data;
	lf->checksum = buf[2 + lf->len + 1].data;
	lf->checksum_mode = priv->respond_answ[lf->lin_id].lf.checksum_mode;

	dev_dbg(&serdev->dev, "frame: brk:%i, n:%u, bytes:%*ph, cksm:%x\n",
		brk, lf->len, lf->len, lf->data,
		lf->checksum);

	if (brk > 4)
		return MODE_OK;	/* frame in between two breaks: so complete */

	if (lf->len == 8)
		return MODE_OK;

	return NEED_FORCE;
}

static int linser_process_frame(struct linser_priv *priv, bool force)
{
	struct serdev_device *serdev = priv->serdev;
	struct lin_frame lf;
	size_t bytes_to_pop;
	int ret = NEED_MORE;

	while (kfifo_len(&priv->rx_fifo) >= LIN_HEADER_SIZE) {
		ret = linser_fill_frame(priv, &lf);

		if (ret == MODE_OK || (ret == NEED_FORCE && force)) {
			dev_dbg(&serdev->dev, "lin_rx: %s\n",
				force ? "force" : "normal");
			lin_rx(priv->lin_dev, &lf);
			bytes_to_pop = LIN_HEADER_SIZE + lf.len +
				       (lf.len ? 1 : 0);
			linser_pop_fifo(priv, bytes_to_pop);
			force = false;
			ret = MODE_OK;
		} else {
			return ret;
		}
	}

	return ret;
}

static void linser_process_delayed(struct work_struct *work)
{
	struct linser_priv *priv = container_of(work, struct linser_priv,
						rx_work.work);

	linser_process_frame(priv, true);
}

static ssize_t linser_receive_buf_fp(struct serdev_device *serdev,
				     const u8 *data, const u8 *fp,
				     size_t count)
{
	struct linser_priv *priv = serdev_device_get_drvdata(serdev);
	enum linser_rx_status rx_status;
	ssize_t n = 0;
	int i;

	cancel_delayed_work_sync(&priv->rx_work);

	for (i = 0; i < count; i++) {
		struct linser_rx rx;

		rx.data = data[i];
		rx.flag = (fp ? fp[i] : 0);
		n += kfifo_in(&priv->rx_fifo, &rx, 1);
		dev_dbg(&serdev->dev, "%s: n:%zd, flag:0x%02x, data:0x%02x\n",
			__func__, n, rx.flag, data[i]);
	}

	rx_status = linser_process_frame(priv, false);

	if (rx_status == NEED_FORCE)
		schedule_delayed_work(&priv->rx_work, priv->force_timeout_jfs);

	return n;
}

static const struct serdev_device_ops linser_ops = {
	.receive_buf_fp = linser_receive_buf_fp,
	.write_wakeup = serdev_device_write_wakeup,
};

static int linser_probe(struct serdev_device *serdev)
{
	struct linser_priv *priv;
	int ret;

	priv = devm_kzalloc(&serdev->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	ret = kfifo_alloc(&priv->rx_fifo, LINSER_RX_FIFO_SIZE, GFP_KERNEL);
	if (ret)
		return ret;

	INIT_DELAYED_WORK(&priv->rx_work, linser_process_delayed);

	priv->serdev = serdev;
	serdev_device_set_drvdata(serdev, priv);
	serdev_device_set_client_ops(serdev, &linser_ops);

	ret = serdev_device_open(serdev);
	if (ret) {
		dev_err(&serdev->dev, "Unable to open device\n");
		goto err_open;
	}

	serdev_device_set_flow_control(serdev, false);
	serdev_device_set_break_detection(serdev, true);
	linser_derive_timings(priv, LIN_DEFAULT_BAUDRATE);

	mutex_init(&priv->resp_lock);

	priv->lin_dev = register_lin(&serdev->dev, &linser_lindev_ops);
	if (IS_ERR_OR_NULL(priv->lin_dev)) {
		ret = PTR_ERR(priv->lin_dev);
		goto err_register_lin;
	}

	return 0;

err_register_lin:
	serdev_device_close(serdev);
err_open:
	kfifo_free(&priv->rx_fifo);
	return ret;
}

static void linser_remove(struct serdev_device *serdev)
{
	struct linser_priv *priv = serdev_device_get_drvdata(serdev);

	if (priv && priv->lin_dev)
		unregister_lin(priv->lin_dev);

	serdev_device_close(serdev);

	dev_dbg(&serdev->dev, "lin-serdev driver removed\n");
}

static const struct of_device_id linser_of_match[] = {
	{
		.compatible = "linux,lin-serdev",
	},
	{}
};
MODULE_DEVICE_TABLE(of, linser_of_match);

static struct serdev_device_driver linser_driver = {
	.probe = linser_probe,
	.remove = linser_remove,
	.driver = {
		.name = KBUILD_MODNAME,
		.of_match_table = linser_of_match,
	}
};

module_serdev_device_driver(linser_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Christoph Fritz <christoph.fritz@hexdev.de>");
MODULE_DESCRIPTION("LIN-Bus serdev driver");

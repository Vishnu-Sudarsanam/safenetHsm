/*
 * Copyright (c) 2013-2018 Safenet.  All rights reserved.
 *
 * bloader.c
 */
#include "headers.h"

void k7_mcpu_reset_completed (struct k7_dev *dev)
{
	SPIN_LOCK_REQUIRED(&dev->lock);
	dev->insertion_count++;
	k7_reinit_mcpu_channel_after_reset(dev);
	dev->mcpu_reset_completed = 1;
	wake_up(&dev->reset_wq);
}

void k7_update_hsm_state (struct k7_dev *dev, u32 new_state)
{
	u32 old_state = dev->hsm_state;

	SPIN_LOCK_REQUIRED(&dev->lock);
	if (new_state == K7_HSM_STATE_BL_READY && !dev->disable_autoboot) {
		if (!dev->failed)
			new_state = K7_HSM_STATE_BOOTING;
	}
	if (new_state == old_state && new_state != K7_HSM_STATE_BL_STARTED)
		return;
	dev->hsm_state = new_state;
	if (new_state == K7_HSM_STATE_READY) {
		dev->icd_enabled = 1;
	} else {
		dev->icd_enabled = 0;
		dev->channels[K7_DMA_TARGET_SKU].enabled = 0;
		dev->channels[K7_DMA_TARGET_PKU].enabled = 0;
		if (new_state == K7_HSM_STATE_BL_STARTED) {
			if (dev->is_pf && dev->reset_ioctl_in_progress)
				k7_mcpu_reset_completed(dev);
			else
				k7_dev_failure_locked(dev, "Re-entered bootloader", "Unexpected reset");
		} else if (new_state == K7_HSM_STATE_BOOTING) {
			k7_async_send_to_mcpu(dev, "gofw", K7_HRB_TYPE_DEFAULT, 0, "gofw\n", 5);
		}
	}
	kdlog(dev->name, "HSM_STATE changed: old=0x%08x new=0x%08x", old_state, new_state);
}

static int k7_handle_m2h_state (struct k7_dev *dev, u64 cmd)
{
	u64 state = cmd & 0x00ffffffffffffffull;

	kdebug(dev->name, "MBX STATE received: 0x%08x", state);
	switch (state) {
	case MBX_BL1_STATE_STARTED:
		k7_update_hsm_state(dev, K7_HSM_STATE_BL_STARTED);
		break;
	case MBX_BL2_STATE_READY:
		k7_update_hsm_state(dev, K7_HSM_STATE_BL_READY);
		break;
	case MBX_BL2_STATE_COMMANDS:
		k7_update_hsm_state(dev, K7_HSM_STATE_BL_COMMANDS);
		break;
	case MBX_BL2_STATE_FATAL_ERROR:
		k7_update_hsm_state(dev, K7_HSM_STATE_BL2_FATAL);
		break;
	case MBX_BL2_STATE_ERASING:
		k7_update_hsm_state(dev, K7_HSM_STATE_BL_ERASING);
		break;
	case MBX_BL1_STATE_READY:
	case MBX_BL1_STATE_FATAL_ERROR:
	case MBX_BL1_STATE_COMMANDS:     //if debug mode in BL1
		k7_update_hsm_state(dev, K7_HSM_STATE_BL1_FATAL);
		break;
	case MBX_FTE_STATE_READY:
		k7_update_hsm_state(dev, K7_HSM_STATE_READY);
		dev->icd_enabled = 0;  /* FTE wants raw DMA commands, not ICD commands */
		dev->channels[K7_DMA_TARGET_SKU].enabled = 1;  /* enable fastpath */
		dev->channels[K7_DMA_TARGET_PKU].enabled = 1;  /* enable fastpath */
		break;
	case MBX_FTE_STATE_FATAL_ERROR:
	case MBX_BL1_STATE_CRIT_ERROR:
	case MBX_BL2_STATE_CRIT_ERROR:
	case MBX_FTE_STATE_CRIT_ERROR:
		k7_update_hsm_state(dev, K7_HSM_STATE_HW_ERROR);
		break;
	default:
		kdwarn(dev->name, "Invalid state %016llx\n", state);
		break;
	}
	return 0;
}

static const char *k7_strip_printk_level (const char *buf)
{
	/* Crash logs from MCPU sometimes have the printk "level" strings, which need to be stripped here */
	if (buf[0] == '<' && buf[1] >= '0' && buf[1] <= '9' && buf[2] == '>' && buf[3] == '[')
		buf += 3;
	return buf;
}

static int k7_handle_m2h_msg (struct k7_dev *dev, u64 cmd)
{
	int eol;

	/* The seven bytes after the command code are zero-terminated ASCII */
	eol = (cmd & 0x00000000000000ff) == 0;
	for (cmd <<= 8; cmd; cmd <<= 8) {
		u8 c = cmd >> 56;
		/*
		 * Handle '\n' chars embedded within the message:
		 */
		if (c != '\n') {
			dev->mbx_buffer[dev->mbx_bufferx++] = c;
		} else if (!eol || cmd << 8) {
			dev->mbx_buffer[dev->mbx_bufferx] = 0;
			kdlog(dev->name, "[hsm] %s", k7_strip_printk_level(dev->mbx_buffer));
			dev->mbx_bufferx = 0;
		}
	}
	dev->mbx_buffer[dev->mbx_bufferx] = 0;
	if (eol || dev->mbx_bufferx >= (sizeof(dev->mbx_buffer) - 8)) {
		kdlog(dev->name, "[hsm] %s", k7_strip_printk_level(dev->mbx_buffer));
		dev->mbx_bufferx = 0;
	}
	return 0;
}

static int k7_handle_m2h_not_pf_err (struct k7_dev *dev, u64 reply)
{
	const u64 error = 0x0001000000000000ull;

	reply |= error;
	kderr(dev->name, "PF-only command received by VF");
	K7_WRITE64(K7_H2M_MBX, reply);
	return 0;
}

static int k7_handle_m2h_read_reg (struct k7_dev *dev, u64 cmd)
{
	u64 reply = cmd & 0xffffffff00000000ull;
	u32 data;
	u16 offset;

	if (!dev->is_pf)
		return k7_handle_m2h_not_pf_err(dev, reply);
	offset = (u16)(cmd >> 32);
	data   = K7_READ32(offset);
	reply |= data;
	kdebug(dev->name, "read 0x%08x from offset 0x%04x", data, offset);
	K7_WRITE64(K7_H2M_MBX, reply);
	return 0;
}

static int k7_handle_m2h_write_reg (struct k7_dev *dev, u64 cmd)
{
	u64 reply = cmd & 0xffffffff00000000ull;
	u32 data;
	u16 offset;

	if (!dev->is_pf)
		return k7_handle_m2h_not_pf_err(dev, reply);
	offset = (u16)(cmd >> 32);
	data   = (u32)cmd;
	kdebug(dev->name, "write 0x%08x to offset 0x%04x", data, offset);
	K7_WRITE32(offset, data);
	K7_WRITE64(K7_H2M_MBX, reply);
	return 0;
}

int k7_handle_m2h_mbx (struct k7_dev *dev, u64 cmd)
{
	switch (cmd >> 56) {
		case HD_MBX_PASS:
			dev->m2h_mbx_rx_flag = 1;
			return 0;  /* no writeback for passthru data */
		case HD_MBX_READ:	/* read register */
			return k7_handle_m2h_read_reg(dev, cmd);
		case HD_MBX_WRITE:	/* write register */
			return k7_handle_m2h_write_reg(dev, cmd);
		case HD_MBX_MESSAGE:
			return k7_handle_m2h_msg(dev, cmd);
		case HD_MBX_BL_STATE:
		case HD_MBX_FTE_STATE:
			return k7_handle_m2h_state(dev, cmd);
		default:
			// Unknown command.
			return -1;
	}
}

/*
 * This gets called from the two RESET ioctl()'s,
 * to wait for HSM_READY after the reset itself has completed.
 */
int k7_wait_for_hsm_ready (struct k7_dev *dev, unsigned int timeout_secs)
{
	unsigned long timeout = jiffies + (timeout_secs * HZ);
	if (!dev->is_pf) {
		/*
		 * FIXME: Need HSM to send ready state to this VF.
		 * FIXME: Meanwhile, just pretend all is well.
		 */
		return 0;
	}
	while (1) {
		unsigned int hsm_state = dev->hsm_state;
		switch (hsm_state) {
			case K7_HSM_STATE_BL_COMMANDS:  /* bootloader command mode */
			case K7_HSM_STATE_BL_READY:	/* bootloader restricted command mode */
			case K7_HSM_STATE_READY:	/* HSM/FTE ready for ICD commands */
				kdinfo(dev->name, "Ready (hsm_state=0x%x)", hsm_state);
				return 0;
			case K7_HSM_STATE_BL1_FATAL:
			case K7_HSM_STATE_BL2_FATAL:
			case K7_HSM_STATE_HW_ERROR:
			case K7_HSM_STATE_TAMPER_RESET:
				kdwarn(dev->name, "HSM failure(0x%08x), returning -EIO", hsm_state);
				return -EIO;
			default:
				break;
		}
		if (dev->failed)
			return -EIO;
		if (signal_pending(current)) {
			kdfinfo(dev->name, "interrupted");
			return -EINTR;
		}
		if (time_after(jiffies, timeout)) {
			kdwarn(dev->name, "timed-out (timeout_secs=%u)", timeout_secs);
			return -ETIMEDOUT;
		}
		msleep(250);
	}
}

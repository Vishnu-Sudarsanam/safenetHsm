/*
 * Copyright (c) 2013-2018 Safenet.  All rights reserved.
 *
 * log.c
 */
#include "headers.h"

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0))
unsigned long get_seconds(void) {
	return ktime_get_real_seconds();
}
#endif

/*
 * If we overflow the log buffer, by overwriting unread messages(s),
 * then afterwards we must zero the remainder of the next unread message
 * and adjust the read index to point just beyond it.
 */
static void k7_log_overflow_adjust (struct k7_log_fifo *log)
{
	char *log_buf = log->buf;
	unsigned int rx = log->wx;
	char c;

	do {
		c = log_buf[rx];
		if (!c)  /* paranoia */
			break;
		log_buf[rx++] = 0;
		if (rx >= log->size)
			rx = 0;
	} while (c != '\n');
	log->rx = rx;
}

static int k7_log_append (struct k7_log_fifo *log, const char *msg, unsigned int len)
{
	unsigned int wx, size;

	/* Copy as much as we can up to the log_buf wraparound point */
	wx   = log->wx;
	size = log->size - wx;
	if (size > 0) {
		if (size > len)
			size = len;
		len -= size;
		memcpy(log->buf + wx, msg, size);
		msg += size;
		wx  += size;
		if (wx >= log->size)
			wx = 0;
	}
	/* If first step didn't copy everything, copy the rest of msg here */
	if (len > 0) {
		memcpy(log->buf + wx, msg, len);
		wx += len;
	}
	log->wx = wx;  /* Save new write index for next time */
	return (log->buf[wx] != 0);  /* return 1 if overflowed into rx area */
}

static void k7_log_append_msg (struct k7_log_fifo *log, const char *msg, unsigned int len)
{
	unsigned long flags;
	int tmplen;
	char *tmp;

	if (!log->buf || !msg || !*msg)
		return;
	spin_lock_irqsave(&log->wq.lock, flags);
	tmp    = log->tmpbuf;
	tmplen = sprintf(tmp, "%llu ", (u64)get_seconds());
	if (k7_log_append(log, tmp, tmplen) | k7_log_append(log, msg, len)) /* Yes, single '|' here */
		k7_log_overflow_adjust(log);
	log->activity++;
	spin_unlock_irqrestore(&log->wq.lock, flags);
	wake_up(&log->wq);
}

void k7_log (struct k7_dev *dev, const char *name, const char *fn, const char *level, const char *fmt, ...)
{
	const char  *prefix = name ? name : DRV_NAME;
	char        *buf, *msg, *msg_start;
	int          len, bufsize = 512;
	va_list      ap;

	if (dev && !dev->dlog.enabled)
		return;
	va_start(ap, fmt);
	buf = kmalloc(bufsize, GFP_ATOMIC);
	if (buf) {
		/* Prepare a simple format string at the beginning of buf[], for use with printk() */
		strcpy(buf, level);
		strcat(buf, "%s");
		len = strlen(buf) + 1;  /* len includes the '\0' here */

		/* Use the remainder of buf[] for the fully formatted message */
		msg = buf + len;
		--bufsize;  /* Reserve one byte for appending '\n' later on */
		len += scnprintf(buf+len, bufsize-len, "%s: ", prefix);
		/* For dlog, save space by skipping the device name when used as prefix */
		if (dev && 0 == strcmp(prefix, dev->name))
			msg_start = buf + len;  /* skip over "prefix: " */
		else
			msg_start = msg;  /* include "prefix: " */
		if (fn)
			len += scnprintf(buf+len, bufsize-len, "%s: ", fn);
		len += vscnprintf(buf+len, bufsize-len, fmt, ap);
		/* Ensure message has a newline character at the end */
		if (buf[len-1] != '\n') {
			buf[len++] = '\n';  /* We reserved space for this earlier */
			buf[len]   = '\0';
		}
		/*
		 * Send formatted message via printk(),
		 * using previously prepared simple format string.
		 */
		if (!dev || !dev->dlog.no_syslog)
			printk(buf, msg);
		/*
		 * If "dev" was supplied, then also send message to DLOG.
		 * But omit the device name prefix (waste of space here).
		 */
		if (dev)
			k7_log_append_msg(&dev->dlog, msg_start, len - (msg_start - buf));
		kfree(buf);
	} else {
		/* kmalloc/dlog failed, send message the ugly way via printk() */
		printk(level);
		printk(KERN_CONT "%s: ", prefix);
		if (fn)
			printk(KERN_CONT "%s: ", fn);
		vprintk(fmt, ap);
		if (!*fmt || fmt[strlen(fmt)-1] != '\n')
			printk("\n");
	}
	va_end(ap);
}

void k7_clog (struct k7_dev *dev, const char *prefix, const char *fmt, ...)
{
	char      *buf;
	va_list    ap;
	int        len, bufsize = 512;

	if (!dev->clog.enabled || (dev->clog.no_syslog && !dev->clog.buf))
		return;
	va_start(ap, fmt);
	buf = kmalloc(bufsize, GFP_ATOMIC);
	if (buf) {
		--bufsize;  /* Reserve one byte for appending '\n' later on */
		len  = prefix ? scnprintf(buf, bufsize, "%s: ", prefix) : 0;
		len += vscnprintf(buf+len, bufsize-len, fmt, ap);
		/* Ensure message has a newline character at the end */
		if (buf[len-1] != '\n') {
			buf[len++] = '\n';  /* We reserved space for this earlier */
			buf[len]   = '\0';
		}
		if (dev->clog.buf)
			k7_log_append_msg(&dev->clog, buf, len);
		if (!dev->clog.no_syslog)
			kinfo(dev->name, "%s", buf);
		kfree(buf);
	}
	va_end(ap);
}

/*
 * The K7 version of the DLOG/CLOG ioctl() returns only complete lines, never partial lines.
 * This complicates reading while also handling buffer wraparound.
 *
 * Each line begins with a base10 timestamp (time_t, seconds since the epoch),
 * followed by a space, followed by the log message, with a '\n' at the end of each line.
 */
static int k7_log_read (struct k7_dev *dev, struct k7_log_fifo *log,
				void __user *dst, unsigned int dst_max, int erase_on_read)
{
	char        *log_buf, *tmp;
	unsigned int log_size, i, rx, rx1, len1 = 0, len2 = 0;
	int ret = 0;

	tmp = kmalloc(dst_max + 1, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	spin_lock_irq(&log->wq.lock);

	log_buf = log->buf;
	if (!log_buf) {
		ret = -EEXIST;
		goto done;
	}

	/* Get bytecount (ret) up to the end of the final line that will fit into dst[] */
	log_size = log->size;
	rx1 = rx = log->rx;
	for (i = 0; i < dst_max; ++i) {
		char c = log_buf[rx];
		if (!c)
			break;
		if (c == '\n')
			ret = i;  /* Remember bytecount up to this point */
		if (++rx >= log_size)
			rx = 0;
	}
	if (ret == 0) {
		if (log_buf[rx])
			ret = -ENOSPC;  /* Caller's buffer is too small for first line */
		goto done;
	}

	/* Copy first part of log_buf[] (up to the wraparound point) to dst[] */
	len1 = log_size - rx1;
	if (len1 > ret)
		len1 = ret;
	memcpy(tmp, log_buf + rx1, len1);
	rx = rx1 + len1;
	if (rx >= log_size)
		rx = 0;

	/* If we wrapped around log_buf[], we can now copy the second part to dst[] */
	len2 = ret - len1;
	if (len2) {
		memcpy(tmp + len1, log_buf + rx, len2);
		if (erase_on_read)
			memset(log_buf + rx, 0, len2);
		rx += len2;  /* wraparound is impossible here */
	}
	/* We can safely erase messages now that both copies were successful */
	if (erase_on_read) {
		memset(log_buf + rx1, 0, len1);
		log->rx = rx;
	}
done:
	spin_unlock_irq(&log->wq.lock);
	if (tmp) {
		if (ret >= 0 && len1 && copy_to_user(dst, tmp, len1 + len2))
			ret = -EFAULT;
		kfree(tmp);
	}
	return ret;
}

/*
 * k7_wait_for_log: return 0 if new activity, otherwise return -ERESTARTSYS (woken by signal).
 */
static int k7_wait_for_log (struct k7_log_fifo *log, unsigned int last_activity)
{
	return wait_event_interruptible(log->wq, log->activity != last_activity);
}

static void k7_log_free (struct k7_dev *dev, struct k7_log_fifo *log)
{
	char *log_buf;
	unsigned int size, buf_vmalloc;
	unsigned long flags;

	/* Remove log->buf from log */
	spin_lock_irqsave(&log->wq.lock, flags);
	log_buf = log->buf;
	if (log_buf) {
		log->buf    = NULL;
		buf_vmalloc = log->buf_vmalloc;
		size        = log->size;
		log->size   = 0;
		log->activity++;
	}
	spin_unlock_irqrestore(&log->wq.lock, flags);

	/* Free memory for the old log_buf */
	if (log_buf) {
		memset(log_buf, 0, size);
		buf_vmalloc ? vfree(log_buf) : kfree(log_buf);
		wake_up(&log->wq);
	}
}

static int k7_log_alloc (struct k7_dev *dev, struct k7_log_fifo *log)
{
	char *buf;
	const char *logname = (log == &dev->dlog) ? "DLOG" : "CLOG";
	unsigned long flags;
	unsigned int size, buf_vmalloc = 0;

	if (log->buf)
		return 0;
	/* Try and get as large a log buffer as possible */
	size = (log == &dev->dlog) ? K7_DLOG_FIFO_BYTES : K7_CLOG_FIFO_BYTES;
	for (buf = NULL; size >= PAGE_SIZE; size /= 2) {
		buf = kzalloc(size, GFP_KERNEL);
		if (buf)
			break;
		buf = vmalloc(size);
		if (buf) {
			buf_vmalloc = 1;
			memset(buf, 0, size);
			break;
		}
	}
	if (!buf) {
		kerr("k7", "%s: alloc failed", __func__, logname);
		return -ENOMEM;
	}
	spin_lock_irqsave(&log->wq.lock, flags);
	if (log->buf) {
		buf_vmalloc ? vfree(buf) : kfree(buf);
	} else {
		kdebug(dev->name, "%s: allocated %u bytes", logname, size);
		log->buf = buf;
		log->size = size;
		log->buf_vmalloc = buf_vmalloc;
		log->rx = log->wx = 0;
		log->activity++;
	}
	spin_unlock_irqrestore(&log->wq.lock, flags);
	wake_up(&log->wq);
	return 0;
}

int k7_ioctl_log (struct k7_dev *dev, struct k7_log_fifo *log, void __user *uargp, int compat)
{
	void __user *ubufp;
	vip_ioctl64_dlog_parms_t p;
	unsigned int last_activity;
	int ret, wait_for_msgs, erase_on_read;

	if (copy_from_user(&p, uargp, sizeof(p)))
		return -EFAULT;
#ifdef CONFIG_COMPAT
	if (compat)
		p.buf.addr = K7_PTR_TO_U64(compat_ptr(p.buf.addr));
#endif
	ubufp = (void __user *)(unsigned long)p.buf.addr;
	if ((p.buf.len && !ubufp) || (ubufp && !p.buf.len) || (!p.buf.len && !p.flags)) {
		kwarn(dev->name, "buf.len=%u buf.addr=%p flags=0x%u", p.buf.len, ubufp, p.flags);
		return -EINVAL;
	}
	if (p.flags & K7_LOG_FLAG_DISABLE)
		log->enabled = 0;
	if (p.flags & K7_LOG_FLAG_ENABLE)
		log->enabled = 1;
	if (p.flags & K7_LOG_FLAG_FREE) {
		if (p.buf.len || p.flags & ((K7_LOG_FLAG_DISABLE | K7_LOG_FLAG_ENABLE) ^ ~K7_LOG_FLAG_FREE))
			return -EINVAL;
		k7_log_free(dev, log);
		return 0;
	}
	if (p.flags & K7_LOG_FLAG_ALLOC) {
		ret = k7_log_alloc(dev, log);
		if (ret)
			return ret;
	}
	wait_for_msgs = (p.flags & K7_LOG_FLAG_WAIT            ) != 0;
	erase_on_read = (p.flags & K7_LOG_FLAG_NO_ERASE_ON_READ) == 0;
	if (wait_for_msgs && !erase_on_read) {
		kwarn(dev->name, "wait=%u erase=%u", wait_for_msgs, erase_on_read);
		return -EINVAL;
	}
	if (p.flags & K7_LOG_FLAG_SYSLOG_SET)
		log->no_syslog = (p.flags & K7_LOG_FLAG_SYSLOG_VAL) ? 0 : 1;
	if (!p.buf.len)
		return 0;
	if (!log->buf) {
		p.buf.len = ~0;
	} else {
		do {
			last_activity = log->activity;
			ret = k7_log_read(dev, log, ubufp, p.buf.len, erase_on_read);
		} while (ret == 0 && wait_for_msgs && !(ret = k7_wait_for_log(log, last_activity)));
		if (ret == -EEXIST)
			p.buf.len = ~0;  /* log->buf got freed from underneath us */
		else if (ret < 0)
			return ret;
		else
			p.buf.len = ret;
	}
	if (copy_to_user(uargp, &p, sizeof(p)))
		return -EFAULT;
	return 0;
}

void k7_log_deinit (struct k7_dev *dev)
{
	k7_log_free(dev, &dev->clog);
	k7_log_free(dev, &dev->dlog);
}

int k7_log_init (struct k7_dev *dev)
{
	int ret;

	init_waitqueue_head(&dev->dlog.wq);
	init_waitqueue_head(&dev->clog.wq);
	dev->dlog.enabled   = 1;
	dev->clog.no_syslog = 1;
	ret = k7_log_alloc(dev, &dev->dlog);
	if (ret == 0 && k7_debug) {
		/* Exercise the various logging macros, to ensure they are working correctly */
		int saved = k7_debug;
		k7_debug = 3;
		kdebug (dev->name, "KDEBUG");
		kdebug1(dev->name, "KDEBUG1");
		kdebug2(dev->name, "KDEBUG2");
		kdebug3(dev->name, "KDEBUG3");
		k7_debug = saved;
		kinfo  (dev->name, "KINFO");
		kfinfo (dev->name, "KFINFO");
		kwarn  (dev->name, "KWARN");
		kerr   (dev->name, "KERR");
		kdlog  (dev->name, "KDLOG");
		kdinfo (dev->name, "KDINFO");
		kdfinfo(dev->name, "KDFINFO");
		kdwarn (dev->name, "KDWARN");
		kderr  (dev->name, "KDERR");
	}
	return ret;
}

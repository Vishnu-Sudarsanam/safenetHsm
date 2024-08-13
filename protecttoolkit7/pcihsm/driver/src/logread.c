/*
 * Copyright (c) 2013-2018 Safenet.  All rights reserved.
 *
 * logread.c
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#include <linux/types.h>  /* for __u32, __u64, etc.. */
#include "uhd_ioctl.h"

static const char *myname;

static char *dev_path = "/dev/k7pf0";
static int dev_fd = -1;

static int MAX_LOG_READ_BYTES = K7_CLOG_FIFO_BYTES;  // Use largest size: CLOG is larger than DLOG

static int alarms_only = 0;
static int do_alloc = 0;
static int do_free  = 0;
static int clog     = 0;
static int enable   = 0;
static int disable  = 0;
static int erase    = 0;
static int noerase  = 0;
static int readlog  = 0;
static int syslog   = -1;
static int tail     = 0;
static int wait     = 0;

static struct option longopts[] = {
	/*	name		has_arg			*flag	val	*/
	{	"alarms",	no_argument,		NULL,	'a'	},
	{	"alloc",	no_argument,		NULL,	'A'	},
	{	"clog",		no_argument,		NULL,	'c'	},
	{	"device",	required_argument,	NULL,	'd'	},
	{	"disable",	no_argument,		NULL,	'D'	},
	{	"enable",	no_argument,		NULL,	'E'	},
	{	"erase",	no_argument,		NULL,	'e'	},
	{	"free",		no_argument,		NULL,	'F'	},
	{	"help",		no_argument,		NULL,	'h'	},
	{	"noerase",	no_argument,		NULL,	'n'	},
	{	"read",		optional_argument,	NULL,	'r'	},
	{	"syslog",	required_argument,	NULL,	's'	},
	{	"tail",		no_argument,		NULL,	't'	},
	{	"wait",		no_argument,		NULL,	'w'	},
	{	NULL,		no_argument,		NULL,	0	}
};

static char shortopts[128];

static void build_shortops (void)
{
	struct option *lo;
	char *so = shortopts;

	*so++ = ':';  /* Cause getopt_long() to return ':' rather than '?' for missing arg */
	for (lo = longopts; lo->name; lo++) {
		*so++ = (char)(lo->val);
		if (lo->has_arg != no_argument) {
			*so++ = ':';
			if (lo->has_arg == optional_argument)
				*so++ = ':';
		}
	}
	*so = '\0';
}

static void show_help (FILE *out)
{
	struct option *opt = longopts;

	fprintf(out, "Usage: %s:", myname);
	for (opt = longopts; opt->name; opt++) {
		fprintf(out, " [-%c|--%s", opt->val, opt->name);
		if (opt->has_arg == required_argument)
			fprintf(out, " <arg>");
		else if (opt->has_arg == optional_argument)
			fprintf(out, " [<arg>]");
		fprintf(out, "]");
	}
	fprintf(out, "\nDefault when at least one other compatible flag is given: --read %u\n", MAX_LOG_READ_BYTES);
}

static void set_myname (int argc, char *argv[])
{
	if (argc < 1) {
		myname = "????";
	} else {
		char *last_slash = strrchr(argv[0], '/');
		if (last_slash)
			myname = last_slash + 1;
		else
			myname = argv[0];
	}
}

static int getnum (const char *arg, int min, int max)
{
	long	val;
	char	*endptr = NULL;

	errno = 0;
	val = strtol(arg, &endptr, 0);
	if (errno || val < (long)min || (max >= min && val > (unsigned long)max)) {
		fprintf(stderr, "%s: value out of range (%d --> %d)\n", arg, min, max);
		exit(EINVAL);
	}
	return val;
}

static char *get_optional_arg (int argc, char **argv)
{
	if (optarg)
		return optarg;
	if (optind < argc && argv[optind] && argv[optind][0] && argv[optind][0] != '-')
		return argv[optind++];
	return NULL;
}

static const char *get_optname (int opt, int idx)
{
	static char optname[32];
	if (idx != -1)
		sprintf(optname, "--%s", longopts[idx].name);
	else if (opt >= ' ' && opt <= '~')
		sprintf(optname, "-%c", opt);
	else
		strcpy(optname, "??");
	return optname;
}

static void parse_args (int argc, char *argv[])
{
	int opt, prev_idx = 0, idx = -1, saw_device = 0;
	char *tmp;

	errno = 0;
	opterr = 0;	/* suppress stderr message on invalid arg inside getopt_long() */
	while ((opt = getopt_long(argc, argv, shortopts, longopts, &idx)) != -1) {
		switch (opt) {
		case 'a':
			alarms_only = 1;
			break;
		case 'A':
			do_alloc = 1;
			break;
		case 'c':
			clog = 1;
			break;
		case 'd':
			if (saw_device)
				fprintf(stderr, "%s: specified multiple times, only the final value is used.\n",
						get_optname(opt, idx));
			saw_device = 1;
			dev_path = optarg;
			break;
		case 'D':
			enable  = 0;
			disable = 1;
			break;
		case 'e':
			if (noerase) {
				fprintf(stderr, "%s: not compatible with --noerase\n", get_optname(opt, idx));
				exit(1);
			}
			erase = 1;
			if (!readlog)
				readlog = MAX_LOG_READ_BYTES;
			break;
		case 'E':
			disable = 0;
			enable  = 1;
			break;
		case 'F':
			do_free = 1;
			break;
		case 'h':
			show_help(stdout);
			exit(0);
		case 'n':
			if (erase) {
				fprintf(stderr, "%s: not compatible with --erase\n", get_optname(opt, idx));
				exit(1);
			}
			if (tail) {
				fprintf(stderr, "%s: not compatible with --tail\n", get_optname(opt, idx));
				exit(1);
			}
			if (wait) {
				fprintf(stderr, "%s: not compatible with --wait\n", get_optname(opt, idx));
				exit(1);
			}
			noerase = 1;
			erase = 0;
			break;
		case 'r':
			tmp = get_optional_arg(argc, argv);
			readlog = tmp ? getnum(tmp, 1, MAX_LOG_READ_BYTES) : MAX_LOG_READ_BYTES;
			break;
		case 's':
			syslog = getnum(optarg, 0, 1);
			break;
		case 't':
			if (noerase) {
				fprintf(stderr, "%s: not compatible with --noerase\n", get_optname(opt, idx));
				exit(1);
			}
			tail = wait = erase = 1;
			if (!readlog)
				readlog = MAX_LOG_READ_BYTES;
			break;
		case 'w':
			if (noerase) {
				fprintf(stderr, "%s: not compatible with --noerase\n", get_optname(opt, idx));
				exit(1);
			}
			if (!readlog)
				readlog = MAX_LOG_READ_BYTES;
			wait = erase = 1;
			break;
		case ':':
			if (prev_idx == -1)
				fprintf(stderr, "-%c: missing <arg>\n", optopt);
			else
				fprintf(stderr, "%s: missing <arg>\n", argv[prev_idx + 1]);
			exit(EINVAL);
		case '?':
			if (prev_idx == -1)
				fprintf(stderr, "-%c: bad flag\n", optopt);
			else
				fprintf(stderr, "%s: bad option\n", argv[prev_idx + 1]);
			exit(EINVAL);
		default:
			fprintf(stderr, "-%c: unknown flag\n", opt);
			exit(EINVAL);
		}
		prev_idx = idx;
		idx = -1;
	}
	if (optind < argc) {
		fprintf(stderr, "optind=%d argc=%d\n", optind, argc);
		fprintf(stderr, "%s: unknown/unexpected parameter\n", argv[optind]);
		exit(EINVAL);
	} else if (optind == 1) {
		show_help(stderr);
		exit(EINVAL);
	}
}

/*
 * The K7 version of the DLOG ioctl() returns (zero or more) full/complete lines of text.
 * Each line begins with a base10 timestamp (seconds since the epoch),
 * followed by a space, followed by the log message, with a '\n' at the end of each line.
 * Here, we pick the returned buffer apart, reformatting the timestamps to localtime,
 * and sending the results to stdout.
 */
static void dlog_print (char *buf)
{
	const char a1[] = " ALM", a2[] = " [hsm] ALM", a3[] = " [HSM] ALM";

	while (*buf) {
		struct tm tm;
		char *end = buf;
		time_t secs = strtoull(buf, &end, 10);
		buf = end;
		end = index(buf, '\n');
		if (end)
			*end = '\0';
		if (!alarms_only
		 || 0 == strncmp(buf, a1, strlen(a1))
		 || 0 == strncmp(buf, a2, strlen(a2))
		 || 0 == strncmp(buf, a3, strlen(a3)))
		{
			localtime_r(&secs, &tm);
			printf("%04u-%02u-%02u %02u:%02u:%02u:%s\n",
				tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, buf);
		}
		if (end)
			buf = end + 1;
		else
			*buf = '\0';
	}
}

int main (int argc, char *argv[])
{
	char *buf = NULL;
	vip_ioctl64_dlog_parms_t args;
	int ret;

	set_myname(argc, argv);
	build_shortops();
	parse_args(argc, argv);

	memset(&args, 0, sizeof(args));
	if (do_alloc)
		args.flags |= K7_LOG_FLAG_ALLOC;
	if (do_free)
		args.flags |= K7_LOG_FLAG_FREE;
	if (enable)
		args.flags |= K7_LOG_FLAG_ENABLE;
	if (disable)
		args.flags |= K7_LOG_FLAG_DISABLE;
	if (syslog != -1) {
		if (syslog)
			args.flags |= K7_LOG_FLAGS_SYSLOG_ON;
		else
			args.flags |= K7_LOG_FLAGS_SYSLOG_OFF;
	}

	/* Default action if at least one arg was given but no action was specified: */
	if (!args.flags && !readlog)
		readlog = MAX_LOG_READ_BYTES;

	if (readlog) {
		if (!erase)
			args.flags |= K7_LOG_FLAG_NO_ERASE_ON_READ;
		if (wait)
			args.flags |= K7_LOG_FLAG_WAIT;
		buf = calloc(readlog + 1, 1);  /* one byte extra for '\0' at end */
		if (!buf) {
			fprintf(stderr, "%s: calloc(%d) failed\n", myname, readlog);
			return 1;
		}
	}
	dev_fd = open(dev_path, O_RDWR);
	if (dev_fd == -1) {
		int err = errno;
		perror(dev_path);
		exit(err);
	}
	do {
		args.buf.addr = (unsigned long)buf;
		args.buf.len = readlog;
		ret = ioctl(dev_fd, clog ? K7_CLOG_READ : K7_DLOG_READ, &args);
		if (ret == -1) {
			perror(clog ? "K7_CLOG_READ" : "K7_DLOG_READ");
			return 1;
		}
		if (args.buf.len == ~0) {
			fprintf(stderr, "%s: driver reported %cLOG not present\n", myname, clog ? 'C' : 'D');
			return 1;
		}
		if (readlog && args.buf.len) {
			buf[args.buf.len] = '\0';
			dlog_print(buf);
		}
	} while (tail);
	return 0;
}

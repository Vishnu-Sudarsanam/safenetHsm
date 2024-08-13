/*
 * Copyright (c) 2013-2018 Safenet.  All rights reserved.
 *
 * lunareset.c
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
#include <sys/mman.h>
#include <linux/limits.h>
#include <fcntl.h>

#include <linux/types.h>  /* for __u32, __u64, etc.. */
#include "ioctl.h"

/* This program can now also reset K6/G5 devices, using this ioctl code: */
#ifndef UHD_IOCTL_RESET_DEVICE
#define UHD_IOCTL_RESET_DEVICE _IO('L', 0x02)
#endif

static const char *myname;

static char *dev_path      = NULL;
static int do_flr_reset    = 0;
static int verbose         = 0;

static struct option longopts[] = {
	/*	name			has_arg			*flag	val	*/
	{	"function-level-reset",	no_argument,		NULL,	'F'	},
	{	"help",			no_argument,		NULL,	'h'	},
	{	"verbose",		no_argument,		NULL,	'v'	},
	{	NULL,			no_argument,		NULL,	0	}
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
	fprintf(out, " <dev_path>\n");
}

static const char *strip_leading_path (const char *path)
{
	char *last_slash = strrchr(path, '/');
	if (last_slash)
		return last_slash + 1;
	return path;
}

static void set_myname (int argc, char *argv[])
{
	myname = (argc < 1) ? "????" : strip_leading_path(argv[0]);
}

static void parse_args (int argc, char *argv[])
{
	int opt, prev_idx = 0, idx = -1;

	errno = 0;
	opterr = 0;	/* suppress stderr message on invalid arg inside getopt_long() */
	while ((opt = getopt_long(argc, argv, shortopts, longopts, &idx)) != -1) {
		switch (opt) {
		case 'F':
			do_flr_reset = 1;
			break;
		case 'v':
			verbose++;
			break;
		case 'h':
			show_help(stdout);
			exit(0);
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
		if (!dev_path) {
			dev_path = argv[optind];
		} else {
			//fprintf(stderr, "optind=%d argc=%d\n", optind, argc);
			fprintf(stderr, "%s: unknown/unexpected parameter\n", argv[optind]);
			exit(EINVAL);
		}
	} else if (optind == 1) {
		show_help(stderr);
		exit(EINVAL);
	}
	if (!dev_path) {
		fprintf(stderr, "%s: missing <dev_path>\n", myname);
		exit(EINVAL);
	}
}

static int get_reset_ioctl_code (int *ioctl_code)
{
	const char *card_name = strip_leading_path(dev_path);

	if (0 == strncmp(card_name, "k7vf", 4)) {
		do_flr_reset = 1;
		*ioctl_code = K7_FLR_RESET;
		return 0;
	}
	if (0 == strncmp(card_name, "k7pf", 4)) {
		*ioctl_code = do_flr_reset ? K7_FLR_RESET : K7_HOST_RESET;
		return 0;
	}
	if (do_flr_reset) {
		fprintf(stderr, "This operation is only valid for K7 virtual functions (eg. /dev/k7vf0)\n");
		return EINVAL;
	}
	if (0 == strncmp(card_name, "viper", 5)) {
		*ioctl_code = UHD_IOCTL_RESET_DEVICE;
		return 0;
	}
	if (0 == strncmp(card_name, "lunauhd", 7)) {
		*ioctl_code = UHD_IOCTL_RESET_DEVICE;
		return 0;
	}
	fprintf(stderr, "Unable to determine device type for \"%s\"\n", dev_path);
	return EINVAL;
}

int main (int argc, char *argv[])
{
	int fd, err, ioctl_code = -1;

	set_myname(argc, argv);
	build_shortops();
	parse_args(argc, argv);

	fd = open(dev_path, O_RDWR);
	if (fd == -1) {
		int err = errno;
		perror(dev_path);
		return err;
	}
	err = get_reset_ioctl_code(&ioctl_code);
	if (err)
		return err;
	if (verbose) {
		printf("ioctl=");
		switch (ioctl_code) {
			case UHD_IOCTL_RESET_DEVICE: printf("UHD_IOCTL_RESET_DEVICE\n"); break;
			case K7_HOST_RESET:          printf("K7_HOST_RESET\n"); break;
			case K7_FLR_RESET:           printf("K7_FLR_RESET\n"); break;
			default:                     printf("0x%x\n", ioctl_code); break;
		}
	}
	if (ioctl(fd, ioctl_code, 0) < 0) {
		int err = errno;
		perror("RESET");
		return err;
	}
	close(fd);
	return 0;
}

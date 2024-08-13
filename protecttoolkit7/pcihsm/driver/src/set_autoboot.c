/*
 * Copyright (c) 2013-2018 Safenet.  All rights reserved.
 *
 * set_autoboot.c
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
#include <fcntl.h>

#include <linux/types.h>  /* for __u32, __u64, etc.. */
#include "ioctl.h"

static const char *myname;

static void show_help (void)
{
	fprintf(stderr, "Usage: %s: /dev/k7XXX [0|1]\n", myname);
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

int main (int argc, char *argv[])
{
	char *dev_path;
	int fd;

	set_myname(argc, argv);
	if (argc != 3) {
		show_help();
		return EINVAL;
	}
	dev_path = argv[1];
	fd = open(dev_path, O_RDWR);
	if (fd == -1) {
		int err = errno;
		perror(dev_path);
		return err;
	}
	if (ioctl(fd, K7_SET_AUTOBOOT, atoi(argv[2])) < 0) {
		int err = errno;
		perror("K7_SET_AUTOBOOT");
		return err;
	}
	close(fd);
	return 0;
}

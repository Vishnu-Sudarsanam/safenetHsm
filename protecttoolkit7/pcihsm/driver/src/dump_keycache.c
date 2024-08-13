/*
 * Copyright (c) 2013-2018 Safenet.  All rights reserved.
 *
 * dump_keycache.c
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
	const char *dev_path;
	int fd;

	set_myname(argc, argv);
	if (argc != 2) {
		fprintf(stderr, "%s: expected <dev_path> as sole parameter\n", myname);
		exit(1);
	}
	dev_path = argv[1];
	fd = open(dev_path, O_RDWR);
	if (fd == -1) {
		int err = errno;
		perror(dev_path);
		return err;
	} else {
#ifndef K7_DUMP_KEYCACHE
		fprintf(stderr, "%s: ioctl(K7_DUMP_KEYCACHE) doesn't exist\n", myname);
		return 1;
#else
		const int BUF_SIZE = 64 * 1024;  /* up to 64KBytes */
		char *buf = malloc(BUF_SIZE);
		if (!buf) {
			perror("malloc() failed");
			return 1;
		} else {
			struct k7_dump_keycache_parms p;
			p.outbuf = (unsigned long long)(unsigned long)buf;
			p.outbuf_size = BUF_SIZE;
			if (ioctl(fd, K7_DUMP_KEYCACHE, &p) == -1) {
				perror("ioctl(K7_DUMP_KEYCACHE) failed");
					return 1;
			}
			printf("%s", buf);
			return 0;
		}
#endif
	}
}

/*
 * Copyright (c) 2013-2018 Safenet.  All rights reserved.
 *
 * mmio.c
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

static unsigned short bswap16 (unsigned short val)
{
	return (val << 8) | (val >> 8);
}

static unsigned int bswap32 (unsigned int val)
{
	unsigned int v;

	v  = (val & 0xff000000) >> 24;
	v |= (val & 0x00ff0000) >>  8;
	v |= (val & 0x0000ff00) <<  8;
	v |= (val & 0x000000ff) << 24;
	return v;
}

static unsigned long long bswap64 (unsigned long long val)
{
	unsigned long long v;
	v  = (val & 0xff00000000000000ull) >> 56;
	v |= (val & 0x00ff000000000000ull) >> 40;
	v |= (val & 0x0000ff0000000000ull) >> 24;
	v |= (val & 0x000000ff00000000ull) >>  8;
	v |= (val & 0x00000000ff000000ull) <<  8;
	v |= (val & 0x0000000000ff0000ull) << 24;
	v |= (val & 0x000000000000ff00ull) << 40;
	v |= (val & 0x00000000000000ffull) << 56;
	return v;
}

static unsigned int round_up_to_power_of_two (unsigned int offset)
{
	unsigned int pwr2 = 4096;

	while (offset >= pwr2)
		pwr2 *= 2;
	return pwr2;
}

static int do_write (void *mmio, unsigned int offset, unsigned int size, unsigned long long v64)
{
	switch (size) {
	case  8:
		{
			unsigned char val = v64;
			*(unsigned char *)(mmio + offset) = val;
			break;
		}
	case 16:
		{
			unsigned short val = v64;
			val = bswap16(val);
			*(unsigned short *)(mmio + offset) = val;
			break;
		}
	case 32:
		{
			unsigned int val = v64;
			val = bswap32(val);
			*(unsigned int *)(mmio + offset) = val;
			break;
		}
	case 64:
		{
			unsigned long long val = v64;
			val = bswap64(val);
			*(unsigned long long *)(mmio + offset) = val;
			break;
		}
	default:
		return 1;
	}
	return 0;
}

static int do_read (void *mmio, unsigned int offset, unsigned int size)
{
	switch (size) {
	case  8:
		{
			unsigned char val = *(unsigned char *)(mmio + offset);
			printf("mmio+%04x: %02x\n", offset, (unsigned int)val);
			break;
		}
	case 16:
		{
			unsigned short val = *(unsigned short *)(mmio + offset);
			val = bswap16(val);
			printf("mmio+%04x: %04x\n", offset, (unsigned int)val);
			break;
		}
	case 32:
		{
			unsigned int val = *(unsigned int *)(mmio + offset);
			val = bswap32(val);
			printf("mmio+%04x: %08x\n", offset, val);
			break;
		}
	case 64:
		{
			unsigned long long val = *(unsigned long long *)(mmio + offset);
			val = bswap64(val);
			printf("mmio+%04x: %016llx\n", offset, val);
			break;
		}
	default:
		return 1;
	}
	return 0;
}

int main (int argc, char *argv[])
{
	const char *dev = "/dev/k7pf0";
	int i, dev_fd, writing = 0, size = 32;
	unsigned long offset = 0;
	unsigned int map_size, have_offset = 0, have_val = 0;
	unsigned long long val = 0;
	void *mmio;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s [-d <devpath>] [-8|-16|-32|-64] [-r|-w] <addr> [<data>]\n", argv[0]);
		exit(0);
	}

	for (i = 1; i < argc; ++i) {
		if (*argv[i] == '/') {
			dev = argv[i];
		} else if (0 == strcmp(argv[i], "-8")) {
			size = 8;
		} else if (0 == strcmp(argv[i], "-16")) {
			size = 16;
		} else if (0 == strcmp(argv[i], "-32")) {
			size = 32;
		} else if (0 == strcmp(argv[i], "-64")) {
			size = 64;
		} else if (0 == strcmp(argv[i], "-r")) {
			writing = 0;
		} else if (0 == strcmp(argv[i], "-w")) {
			writing = 1;
		} else if (0 == strcmp(argv[i], "-d")) {
			if (++i >= argc) {
				fprintf(stderr, "-d: missing <device_path>\n");
				return 1;
			}
			dev = argv[i];
		} else if (!have_offset) {
			errno = 0;
			offset = strtol(argv[i], NULL, 0);
			if (errno) {
				perror(argv[i]);
				return 1;
			}
			if (offset >= 0x10000) {
				fprintf(stderr, "%s: bad offset\n", argv[i]);
				return 1;
			}
			have_offset = 1;
		} else if (writing && !have_val) {
			errno = 0;
			val = strtoull(argv[i], NULL, 0);
			if (errno) {
				perror(argv[i]);
				return 1;
			}
			have_val = 1;
		} else {
			fprintf(stderr, "%s: huh?\n", argv[i]);
			return 1;
		}
	}
	if (!have_offset) {
		fprintf(stderr, "missing offset\n");
		return 1;
	}
	if (writing && !have_val) {
		fprintf(stderr, "missing value\n");
		return 1;
	}

	dev_fd = open(dev, O_RDWR);
	if (dev_fd == -1) {
		int err = errno;
		perror(dev);
		exit(err);
	}

	map_size = round_up_to_power_of_two(offset);
	if (writing)
		mmio = mmap(NULL, map_size, PROT_READ|PROT_WRITE, MAP_SHARED, dev_fd, 0);
	else
		mmio = mmap(NULL, map_size, PROT_READ, MAP_SHARED, dev_fd, 0);
	if (mmio == MAP_FAILED) {
		int err = errno;
		perror("mmap()");
		return err;
	}
	close(dev_fd);
	if (writing)
		return do_write(mmio, offset, size, val);
	else
		return do_read(mmio, offset, size);
}

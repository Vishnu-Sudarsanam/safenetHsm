/*
 * Copyright (c) 2013-2018 Safenet.  All rights reserved.
 *
 * send.c
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

#include <linux/types.h>  /* for __u32, __u64, etc.. */
#include "ioctl.h"

#define USE_MMAP_FOR_FILE_READ  /* undef for MSWin */
#ifdef USE_MMAP_FOR_FILE_READ
#include <sys/mman.h>
#endif

static const char *myname;

#define MAX_TIMEOUT_SECS (1000 * 60 * 60)	/* 1000 hours */

static int	target = -1;
static char	*dev_path = "/dev/k7pf0";
static int	dev_fd = -1;
static int	out_fd = -1;

typedef enum {inpath_file, inpath_stream, inpath_text} inpath_type;

struct inpath_s {
	struct inpath_s	*next;
	char		*val;
	inpath_type	type;
	int		fd;
	unsigned int	size;
	char		*buf;
};

static struct inpath_s	*inpaths = NULL;
static const char	*out_path = NULL;
static int		maxwait  = 2;  /* seconds */
static int		verbose  = 0;
static int		outbuf_size = 0x1000;
static int		mrb = 0;
static int		notx = 0;
static int		noreply = 0;
static int		loops = 0;
static int		fte_reload = 0;
static int		no_result_data = 0;
static int		strip_output = 0;
static int		no_pad8 = 0;
static int		is_icd = 0;

static struct option longopts[] = {
	/*	name		has_arg			*flag	val	*/
	{	"device",	required_argument,	NULL,	'd'	},
	{	"fte-reload",	no_argument,		NULL,	'F'	},
	{	"help",		no_argument,		NULL,	'h'	},
	{	"icd",		no_argument,		NULL,	'I'	},
	{	"inpath",	required_argument,	NULL,	'i'	},
	{	"loops",	required_argument,	NULL,	'l'	},
	{	"maxwait",	required_argument,	NULL,	'w'	},
	{	"mrb",		required_argument,	NULL,	'm'	},
	{	"notx",		no_argument,		NULL,	'n'	},
	{	"noreply",	no_argument,		NULL,	'N'	},
	{	"outpath",	required_argument,	NULL,	'o'	},
	{	"no-pad8",	no_argument,		NULL,	'p'	},
	{	"response-max",	required_argument,	NULL,	'r'	},
	{	"no-result-data", no_argument,		NULL,	'R'	},
	{	"strip-output", no_argument,		NULL,	'S'	},
	{	"target",	required_argument,	NULL,	't'	},
	{	"text",		required_argument,	NULL,	'T'	},
	{	"verbose",	no_argument,		NULL,	'v'	},
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
	fprintf(out, "\n");
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

static void *zalloc (unsigned int bytecount)
{
	void *p = calloc(1, bytecount);
	if (p == NULL) {
		int err = errno;
		perror("calloc");
		exit(err);
	}
	return p;
}

static void dumpmem (const char *prefix, void *addr, int len)
{
	char *hex, ascii[17];
	unsigned char *data = addr;
	unsigned count = 0, offset;

	printf("%s: addr=0x%p len=%d:\n", prefix, addr, len);
	hex = malloc(strlen(prefix) + (3 + 5 + (16 * 3) + 1));
	for (offset = 0; offset < len; ) {
		unsigned int mod16 = offset % 16;
		unsigned char c;
		if (mod16 == 0)
			count = sprintf(hex, "%s: %04x:", prefix, offset);
		c = data[offset];
		count += sprintf(hex + count, " %02x", c);
		ascii[mod16] = (c >= ' ' && c < 0x7f) ? c : '.';
		if (++offset == len || mod16 == 15) {
			ascii[mod16 + 1] = '\0';
			printf("%-53s %s\n", hex, ascii);
			fflush(stdout); usleep(4000);
		}
	}
	free(hex);
}

static void set_target (char *dest)
{
	if (target != -1) {
		fprintf(stderr, "error: only one DMA target allowed\n");
		exit(EINVAL);
	} else if (0 == strcmp(dest, "pku"))  {
		target = K7_DMA_TARGET_PKU;
	} else if (0 == strcmp(dest, "sku"))  {
		target = K7_DMA_TARGET_SKU;
	} else if (0 == strcmp(dest, "mcpu")) {
		target = K7_DMA_TARGET_MCPU;
	} else {
		fprintf(stderr, "error: %s: not a valid DMA target (expected one of pku,sku,mcpu)\n", dest);
		exit(EINVAL);
	}
}

static void add_inpath (inpath_type type, char *val)
{
	static int saw_stdin = 0;	/* non-reentrant */
	struct inpath_s	*new;
	int fd = -1;

	if (type == inpath_file) {
		if (0 == strcmp(val, "-")) {
			if (saw_stdin) {
				fprintf(stderr, "error: stdin specified multiple times\n");
				exit(EINVAL);
			}
			type = inpath_stream;
			val = "stdin";
			saw_stdin = 1;
			fd = fileno(stdin);
		} else {
			fd = open(val, O_RDONLY);
			if (fd == -1) {
				int err = errno;
				perror(val);
				exit(err);
			}
		}
	}
	new       = zalloc(sizeof(struct inpath_s));
	new->next = NULL;
	new->type = type;
	new->val  = val;
	new->fd   = fd;

	if (inpaths == NULL) {
		inpaths = new;
	} else {  /* append to tail of list */
		struct inpath_s *prev = inpaths;
		while (prev->next)
			prev = prev->next;
		prev->next = new;
	}
}

static void prebuffer_stream (struct inpath_s *inpath)
{
	ssize_t		ret, bufsize = 0, offset  = 0;
	unsigned int	bufincr = 0x40000;  /* 256KB */

	inpath->buf = NULL;
	do {
		inpath->buf = realloc(inpath->buf, bufsize + bufincr);
		if (inpath->buf == NULL) {
			int err = errno;
			perror("realloc() failed for stream buffer");
			exit(err);
		}
		bufsize += bufincr;
		ret = read(inpath->fd, inpath->buf + offset, bufincr);
		if (ret < 0) {
			int err = errno;
			perror(inpath->val);
			exit(err);
		}
		offset += ret;
	} while (ret != 0);
	inpath->size = offset;
}

static void prebuffer_file (struct inpath_s *inpath)
{
	struct stat st;

	if (-1 == fstat(inpath->fd, &st)) {
		int err = errno;
		perror(inpath->val);
		exit(err);
	}
	inpath->size = st.st_size;
	if (inpath->size) {
#ifdef USE_MMAP_FOR_FILE_READ
		inpath->buf = mmap(NULL, inpath->size, PROT_READ, MAP_SHARED, inpath->fd, 0);
			if (inpath->buf == MAP_FAILED) {
				int err = errno;
			perror(inpath->val);
			exit(err);
		}
#else
		prebuffer_stream(inpath);
		return;
#endif
	}
	close(inpath->fd);
}

static void prebuffer_inpath (struct inpath_s *inpath)
{
	if (inpath->buf)
		return;
	switch (inpath->type) {
		case inpath_stream:
			prebuffer_stream(inpath);
			break;
		case inpath_file:
			prebuffer_file(inpath);
			break;
		case inpath_text:
			inpath->buf  = zalloc(strlen(inpath->val) + 2);
			strcpy(inpath->buf, inpath->val);
			strcat(inpath->buf, "\n");
			inpath->size = strlen(inpath->buf);
			break;
		default:
			break;
	}
}

static unsigned int read_inpaths (void **inbuf_p)
{
	struct inpath_s *inpath;
	unsigned int bytecount = 0, offset = 0;

	for (inpath = inpaths; inpath != NULL; inpath = inpath->next) {
		prebuffer_inpath(inpath);
		bytecount += inpath->size;
	}

	if (!bytecount) {
		*inbuf_p = NULL;
	} else {
		if (!no_pad8)
			bytecount = (bytecount + 7) & ~7;
		*inbuf_p = malloc(bytecount);
		if (!*inbuf_p) {
			int err = errno;
			perror("malloc");
			exit(err);
		}
	}

	for (inpath = inpaths; inpath != NULL; inpath = inpath->next) {
		memcpy(*inbuf_p + offset, inpath->buf, inpath->size);
		offset += inpath->size;
	}
	return bytecount;
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
	int opt, prev_idx = 0, idx = -1, saw_maxwait = 0, saw_device = 0, saw_response_max = 0;

	errno = 0;
	opterr = 0;	/* suppress stderr message on invalid arg inside getopt_long() */
	while ((opt = getopt_long(argc, argv, shortopts, longopts, &idx)) != -1) {
		switch (opt) {
		case 'd':
			if (saw_device)
				fprintf(stderr, "%s: specified multiple times, only the final value is used.\n",
						get_optname(opt, idx));
			saw_device = 1;
			dev_path = optarg;
			break;
		case 'v':
			++verbose;
			break;
		case 'h':
			show_help(stdout);
			exit(0);
		case 't':
			set_target(optarg);
			break;
		case 'i':
			add_inpath(inpath_file, optarg);
			break;
		case 'I':
			is_icd = 1;
			break;
		case 'l':
			loops = getnum(optarg, 0, -1);
			break;
		case 'm':
			mrb = getnum(optarg, 0, 1);
			break;
		case 'n':
			notx = 1;
			break;
		case 'N':
			noreply = 1;
			break;
		case 'F':
			fte_reload = 1;
			break;
		case 'T':
			add_inpath(inpath_text, optarg);
			break;
		case 'o':
			if (out_path != NULL) {
				fprintf(stderr, "error: only one output file permitted\n");
				exit(EINVAL);
			}
			out_path = optarg;
			break;
		case 'p':
			no_pad8 = 1;
			break;
		case 'r':
			if (saw_response_max)
				fprintf(stderr, "%s: specified multiple times, only the final value is used\n",
						get_optname(opt, idx));
			saw_response_max = 1;
			outbuf_size = getnum(optarg, 0, 0x1fffffff);
			if (!outbuf_size || outbuf_size & 7) {
				fprintf(stderr, "-r: must be a multiple of 8 bytes\n");
				exit(EINVAL);
			}
			break;
		case 'R':
			no_result_data = 1;
			break;
		case 'S':
			strip_output = 1;
			break;
		case 'w':
			if (saw_maxwait)
				fprintf(stderr, "%s: specified multiple times, only the final value is used\n",
						get_optname(opt, idx));
			saw_maxwait = 1;
			maxwait = getnum(optarg, 0, MAX_TIMEOUT_SECS);
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

static int open_output_path (const char *path)
{
	int fd;

	if (0 == strcmp(path, "-")) {
		fd = fileno(stdout);
	} else if (0 == strcmp(path, "/dev/null")) {
		return -1;  /* no output file at all */
	} else if (0 == strncmp(path, "/dev/", 5)) {
		fd = open(path, O_WRONLY);
	} else {
		fd = creat(path, S_IRUSR|S_IWUSR);
	}
	if (fd == -1) {
		int err = errno;
		perror(path);
		exit(err);
	}
	return fd;
}

static void send_output (char *buf, unsigned int size)
{
	int	ret;

	if (out_fd == -1)
		return;
	if (strip_output && size >= 8) {
		buf  += 8;
		size -= 8;
	}
	while (size > 0) {
		ret = write(out_fd, buf, size);
		if (ret == -1) {
			int err = errno;
			perror(out_path);
			exit(err);
		}
		buf += ret;
		size -= ret;
	}
}

static void prep_dma_transaction (struct k7_dma_ioctl *d, void *inbuf, unsigned int inbuf_size, void *outbuf, unsigned int outbuf_size)
{
	memset(d, 0, sizeof(*d));
	d->outbuf	= (unsigned long long)(unsigned long)outbuf;
	d->outbuf_size	= outbuf_size;
	d->timeout_msecs= maxwait * 1000;
	d->target	= (target != -1) ? target : K7_DMA_TARGET_MCPU;
	d->inbuf_size	= inbuf_size;
	d->inbuf	= (unsigned long long)(unsigned long)inbuf;
	if (mrb)
		d->flags |= K7_DMA_FLAG_MRB1;
	if (notx)
		d->flags |= K7_DMA_FLAG_NOTX;
	if (noreply)
		d->flags |= K7_DMA_FLAG_NO_REPLY;
	if (fte_reload)
		d->flags |= K7_DMA_FLAG_FTE_RELOAD | K7_DMA_FLAG_NO_REPLY;
	if (d->flags & K7_DMA_FLAG_NO_REPLY) {
		d->outbuf      = 0;
		d->outbuf_size = 0;
	}
	if (verbose)
		dumpmem("inbuf", inbuf, d->inbuf_size);
}


static int do_dma_transaction (struct k7_dma_ioctl *d)
{
	int ret = ioctl(dev_fd, K7_DMA_IOCTL, d);

	if (ret == -1) {
		perror(dev_path);
		exit(ret);
	}
	if (ret & K7_DMA_OUTPUT_TRUNCATED) {
		ret &= ~K7_DMA_OUTPUT_TRUNCATED;
		fprintf(stderr, "Output buffer was too small; results truncated to %u bytes\n", ret);
	}
	return ret;
}

int main (int argc, char *argv[])
{
	void *outbuf, *inbuf;
	struct k7_dma_ioctl ioc;
	unsigned int i = 0, out_size, inbuf_size;

	set_myname(argc, argv);
	build_shortops();
	parse_args(argc, argv);

	if (out_path == NULL)
		out_path = "-";

	out_fd = open_output_path(out_path);

	dev_fd = open(dev_path, O_RDWR);
	if (dev_fd == -1) {
		int err = errno;
		perror(dev_path);
		exit(err);
	}

	inbuf_size = read_inpaths(&inbuf);	/* allocates/updates "inbuf" */
	outbuf     = zalloc(outbuf_size);
	prep_dma_transaction(&ioc, inbuf, inbuf_size, outbuf, outbuf_size);
	if (no_result_data)
		ioc.flags |= K7_DMA_FLAG_NO_RESULT_DATA;
	if (is_icd)
		ioc.flags |= K7_DMA_FLAG_ICD_CMD;
	do {
		out_size = do_dma_transaction(&ioc);
	} while (++i < loops);
	if (!loops)
		send_output(outbuf, out_size);
	free(inbuf);
	free(outbuf);
	return 0;
}

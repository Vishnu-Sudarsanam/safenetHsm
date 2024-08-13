KVER		:= $(shell uname -r)
KDIR		:= /lib/modules/$(KVER)/build
KMOD		:= k7
MODPARMS	:= k7_num_irqs=4
EXTRA_CFLAGS	+= -Wall

obj-m += k7.o

## When updating this list, also update ../makefile !!!
k7-objs := \
	log.o \
	kek_fastpath.o \
	sessions.o \
	req.o \
	regs.o \
	mem.o \
	bloader.o \
	irq.o \
	proc.o \
	htb.o \
	callback.o \
	main.o

## When updating this list, also update ../makefile and ../specs/* !!!
UTILAPS := \
	send \
	mmio \
	set_autoboot \
	lunareset \
	logread \
	dump_keycache

all:	modules utilaps

## Customer install packages do not include the eth.c file.
## So if eth.c exists here, then this is a development build,
##   and we can build eth.o and set k7_procfs=1 as well.
K7ETH := $(shell [ -e eth.c ] && echo '-DK7ETH' || exit 0)
ifneq ($(K7ETH),)
EXTRA_CFLAGS	+= $(K7ETH)
k7-objs		+= eth.o
MODPARMS	+= k7_procfs=1
endif

## Customer install packages do not include the errinj files.
## So if errinj.c exists here, then this is a development build,
##   and we can include support for error-injection.
K7EI  := $(shell [ -e errinj.c ] && echo '-DK7EI' || exit 0)
ifneq ($(K7EI),)
EXTRA_CFLAGS	+= $(K7EI)
k7-objs		+= errinj.o
UTILAPS		+= seterrinj

seterrinj:	seterrinj.c ioctl.h errinj.h
	gcc -Wall -O2 -o $@ $<

endif

utilaps:
	@for f in $(UTILAPS) ; do			\
		if [ -e "$${f}.c" ]; then		\
			$(MAKE) "$${f}" || exit ;	\
		fi ;					\
	done ;						\
	exit 0

modules:
	$(MAKE) -C $(KDIR) M=`pwd` K7ETH=$(K7ETH) K7EI=$(K7EI) -j modules

modules_install: modules
	$(MAKE) -C $(KDIR) M=`pwd` K7ETH=$(K7ETH) K7EI=$(K7EI) -j modules_install
	depmod -A

install: all
	@lsmod | grep --quiet k7 >/dev/null 2>&1 && (echo "rmmod $(KMOD)" ; rmmod $(KMOD)) || exit 0
	insmod $(KMOD).ko $(MODPARMS)
	@[ -x ./set_smp_affinity.sh ] && ./set_smp_affinity.sh || exit 0

dump_keycache:	dump_keycache.c ioctl.h
	gcc -Wall -O2 -o $@ $<

send:	send.c ioctl.h
	gcc -Wall -O2 -o $@ $<

mmio:	mmio.c ioctl.h
	gcc -Wall -O2 -o $@ $<

lunareset:	lunareset.c ioctl.h
	gcc -Wall -O2 -o $@ $<
	ln -sf $@ vfreset
	ln -sf $@ vreset

set_autoboot:	set_autoboot.c
	gcc -Wall -O2 -o $@ $<

logread:	logread.c uhd_ioctl.h
	gcc -Wall -O2 -o $@ $<

clean:
	$(MAKE) -C $(KDIR) M=`pwd` clean
	@[ -e Module.[Mm]arkers ] && rm -f Module.[Mm]arkers || exit 0
	@[ -e modules.order ] && rm -f modules.order || exit 0
	@[ -e $(KMOD).ko ] && rm -f $(KMOD.ko) || exit 0
	-@rm $(UTILAPS) vfreset vreset *.o *.mod.* .*.cmd $(KMOD).ko 2>/dev/null || exit 0

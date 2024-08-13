# Default configuration for  fm toolchain makefile variables

override ARCH:=ppcfm
export ARCH

export PATH:=/opt/eldk-5.6/powerpc-4xx/sysroots/i686-eldk-linux/usr/bin/powerpc-linux:$(PATH)

export TARGET_PREFIX:=powerpc-linux-
export CC:=powerpc-linux-gcc
export LD:=powerpc-linux-ld
export AR:=powerpc-linux-ar
export STRIP:=powerpc-linux-strip
export OBJCOPY:=powerpc-linux-objcopy

LN:=$(LD)
AR += -crs

CFLAGS += -mcpu=440fp -DIS_BIG_ENDIAN

LFLAGS += -shared
# ensure fmcsa8k.a:_fm_init_ is linked in for all non-emul FM builds
LFLAGS += -u _fm_init_

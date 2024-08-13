#############################################################################
#
#  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
#
#  (c) Copyright 1997-2014 SafeNet, Inc. All rights reserved.
#  This file is protected by laws protecting trade secrets and confidential
#  information, as well as copyright laws and international treaties.
#
# Filename: cfgbuild.mak
# $Date: 2015/10/19 14:30:58GMT-05:00 $
#
#############################################################################
#
# Set up global build platform constants
# The constants defined are:
# - ARCH: The architecture for which the build is being performed
# - OSTYPE: (Internal) The architecture under which the build is being performed
# - PS: Path separator character
# - CC: The C compiler
# - LN: Linker
# - AR: Librarian
# - OUT: Flag to specify the output of the linker
# - COUT: Flag to specify the output from the compiler
# - Optional/additional flags: These constants must be added to the CFLAGS
#   definition in individual makefiles to modify the default behavior.
#   - SHARED: Linker flag to build shared libraries.
#
# The following dynamic constants adjust the names of user-defined types:
# - ARCH_EXE: Modifies the constant $(NAME) to be an executable name under the
#        $(OBJDIR)
#   ARCH_BIN: Modifies the constant $(NAME) to be an FM object name under the
#        $(OBJDIR)
# - ARCH_IMP: Modifies $(ARCH_BIN) to be a linkable library name for use in emulation
#        builds.(-lfmname in Linux, the import lib in Windows) 
# - ARCH_OBJS: Modifies the object list, $(OBJS). It prefixes them with the object
#        directory, and postfixes them with the proper object extension.
# - ARCH_LIBS: Modifies the library list, $(LIBS). It postfixes entries with the
#        proper library extension.
#
# The following constants are expected to be set
# - NAME: then name of the FM or application
#
# The following constants modify the behavior of the environment:
# - DEBUG: If defined, debugging is enabled 
#          in emulation mode this enables FM debug symbols.
# - CONSOLE: If defined, application is linked as a console application under
#   windows build. Otherwise, it is linked as a WINDOWS program.
# - DLL: If defined, DLL switches will be specified in the link flags
# - FM: If defined, the FM is being built (real or emulation)
# - EMUL: If defined, an build assumes an emulation of the fm
#
# The following constants are optional and can override the default
#   GCCFMDIR: If defined overrides default location compiler for FM build
#
#By default, go to host mode.
MODE=HOST
ifneq ($(EMUL),)
    MODE=EMUL
else ifneq ($(FM),)
    MODE=FM
endif
# MODE=FM --> Use  FM (cross-)compiler
# MODE=(EMUL || !FM) --> Use host compiler


FMLIBDIR?=$(FMDIR)/lib/$(ARCH)
CPROVLIBDIR?=$(CPROVDIR)/lib

.default: all

ifneq ($(FM_NO_SETPRIVILEGELEVEL),$(NULL))
     CFLAGS+= -DFM_NO_SETPRIVILEGELEVEL
endif

NULL:=

# setup the name of the DLL to build or link against
# we expect 'NAME' to be defined
ifeq ($(FM),$(NULL))
    #Building the host binary only
    ARCH_EXE=$(OBJDIR)/$(NAME)
else
    ifeq ($(MODE),EMUL)
        #Building an emulation FM. (Append fm- to name)
        DLNAME=fm-$(NAME)
        #Use FM_NAME if defined.
        ifneq ($(FM_NAME),$(NULL))
            DLNAME=fm-$(FM_NAME)
        endif
        ARCH_EXE=$(OBJDIR)/$(DLNAME)
        ARCH_BIN=$(OBJDIR)/$(PRE_DLL)$(DLNAME)$(EXT_DLL)
        ARCH_IMP=-l$(DLNAME)
    else
        #Building the FM
        ARCH_EXE=$(OBJDIR)/$(NAME).elf
        ARCH_BIN=$(OBJDIR)/$(NAME).bin
    endif
endif



############################################################################
#         Platform running this script is Win32                            #
############################################################################
ifeq ($(OS),Windows_NT)

ifneq ($(MODE), FM)
$(error On the Windows platform, this makefile can only be used to build FM modules. For Emulation, please use nmake)
endif
CPROV_OSTYPE=win32
ifeq ($(DEBUG),1)
	LIBDIR=$(CPROVDIR)/libdbg/$(ARCH)
else
	LIBDIR=$(CPROVDIR)/lib/$(ARCH)
endif
endif

############################################################################
#                         Unix Variants - Common                           #
############################################################################

# Path separator character
PS:=/
# C compiler
# CC - use default/override below
# Librarian/Archiver - may override below
AR:=ar -r
# Linker
LN:=$(LD)
# create a directory
MKDIR:=mkdir -p
# delete a directory
RMDIR:=rm -rf
# delete a file
RM:=rm -f
# copy a file
CP:=cp
#Linker output
OUT:=-o
#Compiler output
COUT:=-c -o

# File extensions of generated files
EXT_OBJ:=.o
EXT_LIB:=.a
EXT_EXE:=
EXT_DLL:=.so
PRE_DLL:=lib

# Default values. The detected platforms may overwrite these definitions
override ARCH:=unknown

ARCH_OBJS=$(OBJS:%=$(OBJDIR)/%.o)

ARCH_CLEAN=\
 $(ARCH_OBJS)\
 $(ARCH_EXE)\
 $(ARCH_BIN)\

LFLAGS += -L$(CPROVLIBDIR) -L$(FMLIBDIR)

ifeq ($(FM),$(NULL))
#Not building an FM (i.e. host binary only)

ARCH_LIBS=$(LIBS:%=-l%)

else ifeq ($(MODE),EMUL)
#Building an emulation FM.

FMLIBS= \
	emufmbn \
	emufmemul \
	emufmsmfs \
	emufmcprov \
	emufmcsa8k \
	emufmserial \
	emufmciphobj

ARCH_LIBS= -Wl,--start-group $(LIBS:%=-l%) $(FMLIBS:%=-l%) -Wl,--end-group -ldl -lrt -lpthread

LFLAGS+= -L$(OBJDIR)

CFLAGS+= -DEMUL
LFLAGS+= -Wl,-rpath='$$ORIGIN'
VPATH += $(OBJDIR)

else
#Building the FM

FMLIBS= \
	fmbn \
	fmdebug \
	fmsmfs \
	fmcrt \
	fmcprov \
	fmcsa8k \
	fmserial \
	fmciphobj

ARCH_LIBS= --start-group $(LIBS:%=-l%) $(FMLIBS:%=-l%) --end-group

endif

CFLAGS+= \
	-fPIC \
	-std=c99 \
	-Wall
CFLAGS+= -I. -I"$(FMDIR)/include" -I"$(CPROVDIR)/include"

# define STOPONWARN to force compile to stop on warnings
ifneq ($(STOPONWARN), $(NULL))
CFLAGS+=-Werror
endif

ifneq ($(DEBUG),$(NULL))
# FM symbolic debugging is only available for EMUL builds
# if EMUL or Not FM and debug add symbolic debugging
ifneq ($(MODE),FM) 
    CFLAGS+= -g
endif
CFLAGS+=-DDEBUG
else
CFLAGS+=-O3
endif

# in case somebody declares a dependency on ARCH_LIBS
.PHONY: --start-group --end-group -lgcc
--start-group:
--end-group:
-lgcc:

# Detect the OS type
OSTYPE:=${shell OSTYPE=`uname -s`; case $$OSTYPE in [lL]inux*) OSTYPE=linux;; esac; echo $$OSTYPE }

ifeq ($(MODE),FM)
#For the FM binaries, the cross-compiler is configured in the fmconfig.mk
#$ARCH override and toolchain config come from fmconfig.mk
include $(FMDIR)/fmconfig.mk

#Configure host compiler for emul or non-fm

############################################################################
#                                Linux/i386                                #
############################################################################
else ifeq ($(OSTYPE),linux)

HWTYPE=${shell HWTYPE=`uname -m`; echo $$HWTYPE}
ifeq ($(HWTYPE),x86_64)
	override ARCH:=linux-x86_64
else
	override ARCH:=linux-i386
endif


LN:=$(CC)

CFLAGS += -DIS_LITTLE_ENDIAN
SHARED:=-shared

############################################################################
#                                Unixware 7                                #
############################################################################
else ifeq ($(OSTYPE),UnixWare)

override ARCH:=unixware-i386

CFLAGS += -DSCO_UW7=1 -DIS_LITTLE_ENDIAN=1
SHARED:=-G

############################################################################
#                             SCO Openserver 5                             #
############################################################################
else ifeq ($(OSTYPE),SCO_SV)

override ARCH:=openserver-i386

CFLAGS += -DSCO_OS5=1 -b elf -DIS_LITTLE_ENDIAN=1
SHARED:=-G
CC:=/udk/usr/ccs/bin/cc

############################################################################
#                                   AIX                                    #
############################################################################
else ifeq ($(OSTYPE),AIX)

override ARCH:=aix-ppc

CC:=xlc_r
LN:=$(CC)
SHARED:=
# Note: compiler provides _AIX43 but not unix!!
CFLAGS += -DIS_BIG_ENDIAN=1 -Dunix=1 -G
CFLAGS += -O -qmaxmem=8192
LFLAGS += -brtl -berok -L/usr/lib/threads -L/usr/lib/dce -lpthreads

############################################################################
#                                 Free BSD                                 #
############################################################################
else ifeq ($(OSTYPE),FreeBSD)

override ARCH:=freebsd-i386

CFLAGS += -DFreeBSD
CFLAGS += -DIS_LITTLE_ENDIAN

SHARED:=-shared

############################################################################
#                           Solaris (Sparc/i386)                           #
############################################################################
else ifeq ($(OSTYPE),SunOS)

LN:=cc

override ARCH:=${shell uname -p}

SHARED:=-G

# Enforce full warning and error checking
CFLAGS+=-v -errwarn

ifeq ($(ARCH),i386)
CFLAGS += -DIS_LITTLE_ENDIAN
else
CFLAGS += -DIS_BIG_ENDIAN
endif
ARCH_LIBS+=-lethsm

endif

###########################################################################
#       end of OS specific definitions
###########################################################################

###########################################################################
#                         Some Generic Rules                              #
###########################################################################

ifeq ($(OBJDIR),$(NULL))
OBJDIR:=obj-$(ARCH)
endif

ifneq ($(EMUL),$(NULL))
OBJDIR:=$(OBJDIR)e
endif

ifneq ($(DEBUG),$(NULL))
OBJDIR:=$(OBJDIR)d
endif

ifneq ($(DLL),$(NULL))
LFLAGS+=$(SHARED)
endif

VPATH+=$(CPROVLIBDIR) $(FMLIBDIR)

###########################################################################
#                    Some Generic Unix Build Rules                        #
###########################################################################
$(OBJDIR):
	@if [ ! -d $(OBJDIR) ] ; then $(MKDIR) $(OBJDIR) ; fi

$(OBJDIR)/%.o: %.c
	$(CC) $(CFLAGS) $(COUT) $@ $<

$(OBJDIR)/%.o: %.cpp
	$(CC) $(CFLAGS) $(COUT) $@ $<

$(OBJDIR)/%.o: %.s
	$(AS) $(AFLAGS) $(OUT) $@ $<

###########################################################################
#                    Power PC FM Build Rules (Linux hosted)               #
###########################################################################
ifeq ($(MODE),FM)     # if FM and not EMUL
# Special case to ignore the warning:
# 	"initialization discards qualifiers from pointer target type"
# which is caused by using a strings to populate char arrays
# in the macro DEFINE_FM_HEADER, which _should_ always be in hdr.c
# also force the header to be recompiled each time

$(OBJDIR)/hdr.o: hdr.c
	$(CC) $(CFLAGS) -Wno-error -c -o $@ $<

endif # powerpc

info:
	$(info --------------)
ifeq ($(MODE),EMUL)
	$(info Building Emulation FM)
else ifeq ($(MODE),FM)
	$(info Building FM)
else
	$(info $(MODE) mode)
endif
	$(info -- OSTYPE      = $(OSTYPE))
	$(info -- ARCH        = $(ARCH))
	$(info -- OBJDIR      = $(OBJDIR))
	$(info -- CPROVDIR    = $(CPROVDIR))
	$(info -- CPROVLIBDIR = $(CPROVLIBDIR))
	$(info -- FMDIR       = $(FMDIR))
	$(info -- FMLIBDIR    = $(FMLIBDIR))
	$(info -- CFLAGS      = $(CFLAGS))
	$(info -- LFLAGS      = $(LFLAGS))
	$(info --------------)

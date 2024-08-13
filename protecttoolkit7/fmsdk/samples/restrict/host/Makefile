#############################################################################
#
#  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
#
#  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
#  This file is protected by laws protecting trade secrets and confidential
#  information, as well as copyright laws and international treaties.
#
#
#############################################################################

all: build

# Build a console application
CONSOLE:=1

# Name of the application
NAME:=restricttest

# Name of the FM
FM_NAME:=restrict

# Directory where the FM is built from
FM_PATH:=../fm
FMDIR:=/opt/safenet/protecttoolkit7/fmsdk
#LDFLAGS += -L/path/to/libs -lmysharedlib
#ARCH_LIBS:=/opt/safenet/protecttoolkit7/cprt/lib/linux-x86_64

include $(FMDIR)/cfgbuild.mak 

$(info FMDIR variable value: $(FMDIR))
$(info  ARCH_LIBS value:$(ARCH_LIBS))

# if we are doing emulation build, copy test program to where the FM DLL is.
ifneq ($(EMUL),$(NULL))
FM_PATH:=..$(PS)fm
INSTALL_EXE=$(FM_PATH)$(PS)$(ARCH_EXE)
endif

build: $(ARCH_EXE) $(INSTALL_EXE)



OBJS:=\
	restricttest

LIBS:=\
	cryptoki

ifneq ($(EMUL), $(NULL))
	LFLAGS += -L$(FM_PATH)$(PS)$(OBJDIR) -Wl,-rpath $(FM_PATH)$(PS)$(OBJDIR),gcc -Wl,-rpath -I/opt/safenet/protecttoolkit7/fmsdk/include

# build the test program
#strace -e trace=open,openat,stat,stat64,access,readlink
#> strace_output1.txt 2>&1
$(ARCH_EXE): $(OBJDIR) $(ARCH_OBJS)
	$(LN) $(OUT)$(ARCH_EXE) $(LFLAGS)  $(ARCH_OBJS) $(ARCH_LIBS) -L/opt/safenet/protecttoolkit7/cprt/lib/linux-x86_64 
# strace -e trace=open,openat,stat,stat64,access,readlink 
#> strace_output1.txt 2>&1

# install the test program to another location (if specified)
$(INSTALL_EXE): $(ARCH_EXE)
	$(CP) $^ $@

clean :
	-$(RM) $(ARCH_CLEAN)
ifneq ($(INSTALL_EXE),$(NULL))
	-$(RM) $(INSTALL_EXE)
endif
	-$(RMDIR) $(subst /,$(PS),$(OBJDIR))
endif




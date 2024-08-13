#############################################################################
#
#  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
#
#  (c) Copyright 2023 SafeNet, Inc. All rights reserved.
#  This file is protected by laws protecting trade secrets and confidential
#  information, as well as copyright laws and international treaties.
#
#
#############################################################################

all: build

# Name of the application
NAME:=eccdemo

# Name of the FM
FM_NAME:=eccdemo

include $(FMDIR)/cfgbuild.mak

# Directory where the FM is built from
# Must use absolute path
FM_PATH:=$(FMDIR)/samples/$(FM_NAME)/fm

CFLAGS+=-I../include

# if we are doing emulation build, copy test program to where the FM DLL is.
ifneq ($(EMUL),$(NULL))
INSTALL_EXE=$(FM_PATH)/$(ARCH_EXE)
endif

build: $(ARCH_EXE) $(INSTALL_EXE)

OBJS:=\
	eccdemo

LIBS:=\
	cryptoki \
	ethsm

ifneq ($(EMUL), $(NULL))
	LFLAGS += -L$(FM_PATH)/$(OBJDIR) -Wl,-rpath $(FM_PATH)/$(OBJDIR)
endif

# build the test program
$(ARCH_EXE): $(OBJDIR) $(ARCH_OBJS)
	$(LN) $(OUT)$(ARCH_EXE) $(LFLAGS) $(ARCH_OBJS) $(ARCH_LIBS)

# install the test program to another location (if specified)
$(INSTALL_EXE): $(ARCH_EXE)
	$(CP) $^ $@

clean :
	-$(RM) $(ARCH_CLEAN)
ifneq ($(INSTALL_EXE),$(NULL))
	-$(RM) $(INSTALL_EXE)
endif
	-$(RMDIR) $(subst /,/,$(OBJDIR))


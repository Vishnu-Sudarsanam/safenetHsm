# Copyright (c) 2018 Safenet Inc.

all: build

FM:=1
NAME:=fmusb

include $(FMDIR)/cfgbuild.mak

CFLAGS+=-I../include
LIBS+=fmusb
LFLAGS+=-L$(FMDIR)/lib/ppcfm 

OBJS:=\
	usb \
	hdr

.phony: build
build: $(OBJDIR) $(ARCH_BIN)

ifeq ($(EMUL),$(NULL))

$(ARCH_EXE): $(ARCH_OBJS)
	$(LN) $(LFLAGS) $(OUT)$@ $(ARCH_OBJS) $(ARCH_LIBS)

$(ARCH_BIN): $(ARCH_EXE)
	$(OBJCOPY) $< $@


clean:
	-$(RM) $(ARCH_CLEAN)

else
#
# EMULATION Build
#
# Include rules to build the emulation Cryptoki and Access Provider wrappers
# Note path is slightly different in full source tree than in FMSDK tree
include $(FMDIR)/csa8k/fm/emul/common/emucommon.mak

.phony: build
build: $(OBJDIR) $(ARCH_BIN) $(EMUL_WRAPPERS)

# build the emulation FM
$(ARCH_BIN): $(ARCH_OBJS)
	$(LN) $(LFLAGS) $(OUT)$@ $(ARCH_OBJS) $(ARCH_LIBS)

# cleanup emulation build
clean: $(EMUL_CLEAN)
	-$(RM) $(ARCH_CLEAN)
	-$(RMDIR) $(subst /,$(PS),$(OBJDIR))

endif



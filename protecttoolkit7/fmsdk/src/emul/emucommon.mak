#############################################################################
#
#  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
#
#  (c) Copyright 2014 SafeNet, Inc. All rights reserved.
#  This file is protected by laws protecting trade secrets and confidential
#  information, as well as copyright laws and international treaties.
#
# Filename: emucommon.mak
#
#############################################################################
#
# This file contains common rules for building the emulation Cryptoki and ethsm
# Access Provider wrappers for accessing emulation FMs.  It is intended to be
# included in the FM makefile as part of the EMUL build section and depends.
# It assumes the FM's makefile is using the provided cfgbuild.mak.
#
# The following constants are expected to be set,and are typically inherited
# from dynamic constants created by cfgbuild.mak
#   OBJDIR :  Output directory for being used for the current FM build.
#   ARCH_BIN: Emulation FM library name
#   ARCH_IMP: Linkable library name, including link flag, of ARCH_BIN. This
#             is "-l<fmname>" in linux and the import library name in Windows.
#
# The following constants are provided back to the parent makefile
#  EMUL_WRAPPERS:  List of emulation wrapper libraries to add to build: dependency
#  EMUL_CLEAN:     Rule to clean the emulation wrappers. Add to clean for EMUL 
#                  builds.
#############################################################################
LFLAGS += -shared -Wl,-Bsymbolic

EMUL_WRAPPERS =  $(OBJDIR)/$(PRE_DLL)ethsm$(EXT_DLL) $(OBJDIR)/$(PRE_DLL)cryptoki$(EXT_DLL)
EMUL_CLEAN = emul_wrapper_clean

#Find common emul source path based on this makefile's path:
COMMON_EMUL_PATH := $(dir $(lastword $(MAKEFILE_LIST)))

EMUL_MD_OBJ = $(OBJDIR)/emumdapi$(EXT_OBJ)
EMUL_CPROV_OBJ = $(OBJDIR)/emucprov$(EXT_OBJ)

# Build the Cryptoki Emulation
$(OBJDIR)/$(PRE_DLL)cryptoki$(EXT_DLL): $(EMUL_CPROV_OBJ) $(EMUL_MD_OBJ) | $(ARCH_BIN)
	$(LN) $(LFLAGS) $(OUT) $@ $^ $(ARCH_IMP)

# Build the Access Provider Emulation
$(OBJDIR)/$(PRE_DLL)ethsm$(EXT_DLL): $(EMUL_MD_OBJ) | $(ARCH_BIN)
	$(LN) $(LFLAGS) $(OUT) $@ $^ $(ARCH_IMP)

$(EMUL_CPROV_OBJ): $(COMMON_EMUL_PATH)emucprov.c
	$(CC) $(CFLAGS) $(COUT) $@ $<

$(EMUL_MD_OBJ): $(COMMON_EMUL_PATH)emumdapi.c
	$(CC) $(CFLAGS) $(COUT) $@ $<

emul_wrapper_clean:
	-$(RM) $(EMUL_MD_OBJ) $(EMUL_CPROV_OBJ) $(EMUL_WRAPPERS)

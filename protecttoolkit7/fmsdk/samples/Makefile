#############################################################################
#
#  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
#
#  (c) Copyright 1997-2014 SafeNet, Inc. All rights reserved.
#  This file is protected by laws protecting trade secrets and confidential
#  information, as well as copyright laws and international treaties.
#
#
#############################################################################

# PTK 5.0.0 does not support FM crosscompiling from Windows
ifeq ($(OS),Windows_NT)
    export HOSTONLY=1
endif

%:
	$(MAKE) -C cipherobj $@
	$(MAKE) -C restrict $@
	$(MAKE) -C rsaenc $@
	$(MAKE) -C safedebug $@
	$(MAKE) -C smfs $@
	$(MAKE) -C xorsign $@
	$(MAKE) -C secfmenc $@
	$(MAKE) -C ssldemo $@

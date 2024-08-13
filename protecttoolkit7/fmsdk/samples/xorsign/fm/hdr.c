/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: samples/xorsign/fm/hdr.c
 */
#include <mkfmhdr.h>
#include <xorsign.h>

#define FM_VERSION FM_MAKE_VERSION(1,05)
#define FM_SER_NO  1234567890
#define FM_MANUFACTURER "SafeNet Inc"
#define FM_NAME "XorSign"

DEFINE_FM_HEADER(FM_NUMBER_CUSTOM_FM,
		FM_VERSION,
		FM_SER_NO,
		FM_MANUFACTURER,
		FM_NAME);


/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: samples/smfs/fm/hdr.c
 */
#include <mkfmhdr.h>

#define FM_VERSION FM_MAKE_VERSION(1,01) /* V1.01 */
#define FM_SER_NO  0
#define FM_MANUFACTURER "SafeNet Inc"
#define FM_NAME "SMFS_DEMO"
#define MY_FM_NUMBER 0x500

DEFINE_FM_HEADER(MY_FM_NUMBER,
		FM_VERSION,
		FM_SER_NO,
		FM_MANUFACTURER,
		FM_NAME);


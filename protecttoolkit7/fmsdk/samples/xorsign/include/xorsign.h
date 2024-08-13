/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: samples/xorsign/include/xorsign.h
 */

/**
 * @file
 * This header file contains the definitions of the constants required to use
 * the CKM_XOR mechanism.
 */
#ifndef INC_XORSIGN_H
#define INC_XORSIGN_H

#include <cryptoki.h>

/* The new hash machnism implemented by the XorSign FM.
 * Please note the addition of the constant 0x40000000uL to CKM_VENDOR_DEFINED
 * to ensure that no constant clash with eracom TECHNOLOGIES' vendor defined
 * mechanisms.
 */
#define CKM_XOR (CKM_VENDOR_DEFINED | (0x40000000uL + 0xA001))

#endif /* INC_XORSIGN_H */

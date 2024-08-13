/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 1997-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 */
#ifndef INC_CSA8FM_H
#define INC_CSA8FM_H

/* System Check Firmware (SCF). This is not a peer in HIFACE communication */
#define FM_NUMBER_HIFACE	0x0000

/* Manufacturing Firmware */
#define FM_NUMBER_MANUTEST	0x0001

/* PKISUPT/CSA8OS: The CSA800 operating system */
#define FM_NUMBER_PKISUPT	0x0002

/* Angel Debug Monitor firmware. This is not a peer in HIFACE communication. */
#define FM_NUMBER_ANGEL		0x0004

/* HSM Administration interface. */
#define FM_NUMBER_HSMADMIN  0x0008

/* Cprov: Eracom's PKCS #11 implementation in hardware. */
#define FM_NUMBER_CRYPTOKI	0x0009

/* FM: The FM number of the single FM allowed inside CSA8000 */
#define FM_NUMBER_CUSTOM_FM 0x0100

/* Cprov Flash upgrade utility. */
#define FM_NUMBER_WFLASH	0x000A

/* Host callback module */
#define FM_NUMBER_HOSTSRV   0x000B

/* Unused Flash ROM sector */
#define FM_NUMBER_EMPTY		0xFFFF


#endif /* INC_CSA8FM_H */

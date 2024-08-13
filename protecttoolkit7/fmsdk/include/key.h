/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 1997-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 */
#pragma once
#include <stdint.h>

typedef uint8_t byte;

#define MAX_MODULUS_SIZE   	4096
#define MIN_RSA_BITS        512
#define MAX_RSA_BITS        MAX_MODULUS_SIZE
#define MAX_RSA_MOD_BYTES   (MAX_RSA_BITS / 8)
#define MAX_RSA_PRIME_BYTES ((MAX_RSA_MOD_BYTES / 2) + 4)

#define RSA_MODE_X509		0
#define RSA_MODE_PKCS		1
#define RSA_MODE_9796		2
#define RSA_MODE_OAEP		3
#define RSA_MODE_KW_OAEP	4
typedef struct {
    byte bits[2];
    byte mod [MAX_RSA_MOD_BYTES];
    byte exp [MAX_RSA_MOD_BYTES];
}
RSA_PUBLIC_KEY;
typedef struct {
    byte bits[2];
    byte mod [MAX_RSA_MOD_BYTES];
    byte pub [MAX_RSA_MOD_BYTES];
    byte pri [MAX_RSA_MOD_BYTES];
    byte p   [MAX_RSA_PRIME_BYTES];
    byte q   [MAX_RSA_PRIME_BYTES];
    byte e1  [MAX_RSA_PRIME_BYTES];
    byte e2  [MAX_RSA_PRIME_BYTES];
    byte u   [MAX_RSA_PRIME_BYTES];
}
RSA_PRIVATE_KEY_XCRT;

typedef struct CtPubRsaKey {
	uint32_t isPub;		/* TRUE */
	uint32_t modSz;
	RSA_PUBLIC_KEY key;
} CtPubRsaKey;

typedef struct CtPriRsaKey {
	uint32_t isPub;		/* FALSE */
	uint32_t modSz;
	RSA_PRIVATE_KEY_XCRT key;
	uint32_t isXcrt;
} CtPriRsaKey;

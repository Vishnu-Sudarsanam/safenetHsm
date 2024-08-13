/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: samples/xorsign/host/xortest.c
 */

/**
 * @file
 * Host test program that uses the new mechanism CKM_XOR implemented in the FM
 * XorSign.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cryptoki.h>
#include <ctutil.h>

#include "xorsign.h"

void memdump(const char * txt, const unsigned char * buf, unsigned int len);

int main(int argc, char *argv[])
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hMacKey;
	CK_MECHANISM mech;
	CK_BYTE param[8] = "P a ram";	/* 8 bytes */
	CK_BYTE data[8] = "Message";	/* 8 byte message */
	CK_BYTE result[8];
	CK_SIZE resultLen = 8;

	static char label[] = "MAC";
	static unsigned char True = 1;
	CK_ATTRIBUTE attr[] =
	{
		{CKA_LABEL, label, sizeof(label)},
		{CKA_TOKEN, &True, sizeof(TRUE)},
		{CKA_SENSITIVE, &True, sizeof(TRUE)}
	};
	int doGen = 0;

	/* process command line arguments */
	for (argc--, argv++; argc; argc--, argv++) {
		char * arg = *argv;
		if ( *arg == '-' ) {
			arg++;
			switch(*arg) {
			case 'g':
				doGen = 1;
			}
		}
	}

	/* init PKCS11 subsystem */
	rv = C_Initialize(NULL);
	if (rv) rv = C_Initialize(NULL);
	if (rv != CKR_OK) {
		fprintf(stderr, "C_Initialize failed: 0x%08lx\n", rv);
		exit(EXIT_FAILURE);
	}

	/* get a session with the token for our operations */
	rv = C_OpenSession(0, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL, NULL, &hSession);
	if(rv != CKR_OK) {
		fprintf(stderr, "C_OpenSession failed: 0x%08lx\n", rv);
		exit(EXIT_FAILURE);
	}

	/* generate or locate signing key */
	if ( doGen ) {
		memset(&mech, 0, sizeof(CK_MECHANISM));
		mech.mechanism = CKM_DES_KEY_GEN;
		rv = C_GenerateKey(hSession, &mech, attr, NUMITEMS(attr), &hMacKey);
		if(rv != CKR_OK) {
			fprintf(stderr, "C_GenerateKey failed: 0x%08lx\n", rv);
			exit(EXIT_FAILURE);
		}
	}
	else {
		/* find it on the token */
		CK_COUNT found;
		rv = C_FindObjectsInit(hSession, attr, NUMITEMS(attr));
		if(rv != CKR_OK) {
			fprintf(stderr, "C_FindObjectsInit failed: 0x%08lx\n", rv);
			exit(EXIT_FAILURE);
		}
		rv = C_FindObjects(hSession, &hMacKey, 1, &found);
		if(rv != CKR_OK) {
			fprintf(stderr, "C_FindObjects failed: 0x%08lx\n", rv);
			exit(EXIT_FAILURE);
		}
		if ( found == 0 ) {
			fprintf(stderr, "Cannot find key\n");
			exit(EXIT_FAILURE);
		}
	}

	/* do the special MAC function */
	memset(&mech, 0, sizeof(CK_MECHANISM));
	mech.mechanism = CKM_XOR;
	mech.pParameter = param;
	mech.parameterLen = sizeof(param);

	rv = C_SignInit(hSession, &mech, hMacKey);
	if(rv != CKR_OK) {
		fprintf(stderr, "C_SignInit failed: 0x%08lx\n", rv);
		exit(EXIT_FAILURE);
	}

	resultLen = sizeof(result);
	rv = C_Sign(hSession, data, sizeof(data), result, &resultLen);
	if(rv != CKR_OK) {
		fprintf(stderr, "C_Sign failed: 0x%08lx\n", rv);
		exit(EXIT_FAILURE);
	}

	/* show the result */
	memdump("Signature", result, resultLen);
	
	/* clean up */
	rv = C_CloseSession(hSession);
	if (rv != CKR_OK) {
		fprintf(stderr, "C_CloseSession failed: 0x%08lx\n", rv);
		exit(EXIT_FAILURE);
	}

	rv = C_Finalize(NULL);
	if (rv != CKR_OK) {
		fprintf(stderr, "C_Finalize failed: 0x%08lx\n", rv);
		exit(EXIT_FAILURE);
	}

	return 0;
}

void memdump(const char * txt, const unsigned char * buf, unsigned int len)
{
	unsigned int i;
	printf( "%s", txt );
	for ( i = 0; i < len; i++ ) {
		if ( !(i%16) )
			printf("\n    ");
		printf("%02x", buf[i]);
	}
	printf( "\n" );
}

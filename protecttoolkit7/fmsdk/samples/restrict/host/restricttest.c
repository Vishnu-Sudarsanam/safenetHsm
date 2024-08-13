/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: samples/restrict/host/restricttest.c
 */

/**
 * @file
 * restricttest: Host test program that checks whether the FM Restrict is
 * working, or not. If the FM is active, openning sessions to slot 0 should be
 * refused, while access to other slots are still allowed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <cryptoki.h>


int main()
{
	CK_SESSION_HANDLE hSession;
	CK_SLOT_ID SlotID;
	CK_RV rv;

	rv = C_Initialize(NULL);
	if (rv != CKR_OK) {
		fprintf(stderr, "C_Initialize failed: 0x%08lx\n", rv);
		exit(EXIT_FAILURE);
	}

	SlotID = 0;
	rv = C_OpenSession(SlotID, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL, NULL, &hSession);
	if (rv != CKR_OK) {
		printf("GOOD: C_OpenSession fails for %ld, return value 0x%08lx\n", SlotID, rv);
	} else {
		printf("BAD: C_OpenSession succeeds for slot ID %ld\n", SlotID);
		rv = C_CloseSession(hSession);
		if (rv != CKR_OK) {
			fprintf(stderr, "C_CloseSession failed: 0x%08lx\n", rv);
			exit(EXIT_FAILURE);
		}
	}

	SlotID = 1;
	rv = C_OpenSession(SlotID, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL, NULL, &hSession);
	if (rv == CKR_OK) {
		printf("GOOD: C_OpenSession succeeds for slot ID %ld\n", SlotID);
		rv = C_CloseSession(hSession);
		if (rv != CKR_OK) {
			fprintf(stderr, "C_CloseSession failed: 0x%08lx\n", rv);
			exit(EXIT_FAILURE);
		}
	} else {
		printf("BAD: C_OpenSession fails for %ld, return value 0x%08lx\n", SlotID, rv);
	}

	rv = C_Finalize(NULL);
	if (rv != CKR_OK) {
		fprintf(stderr, "C_Finalize failed: 0x%08lx\n", rv);
		exit(EXIT_FAILURE);
	}
	
	 
	return 0;
}


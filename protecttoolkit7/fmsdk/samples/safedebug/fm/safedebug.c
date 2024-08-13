/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2007-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: samples/safedebug/fm/safedebug.c
 */

/**
 * @file
 *	SafeDebug:
 *	This FM demonstrates the use of an smfs file at the Startup() function to
 *	allow a safe FM environment.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <cryptoki.h>
#include <cprovtbl.h>
#include <cprovpch.h>
#include <fm.h>
#include <fmdebug.h>
#include <fmsmfs.h>

CK_RV CK_ENTRY FM_C_OpenSession(
	CK_SLOT_ID slotID,
	CK_FLAGS flags,
	CK_VOID_PTR pApplication,
	CK_NOTIFY Notify,
	CK_SESSION_HANDLE_PTR phSession
)
{
	if (slotID == 0) {
		return CKR_SLOT_ID_INVALID;
	} else {
		return C_OpenSession(slotID,flags,pApplication,Notify,phSession);
	}
}

#ifdef DEBUG

/* We need to be able to disable a FM in the case where the FM causes the 
 * HSM to crash or to be locked up or inaccessible.
 * This method uses a file in the SMFS as an indication that the HSM has been
 * tampered. If it is tampered then the FM should disable itself. 
 *
 * This function tests the existance of the file and cretes it if it is not 
 * present.
 * 
 * Return: zero if the file needed to be created i.e. device tampered
 */

#define SENTINAL_FILE_NAME  "/sentinal"
int isFmEnabled(void) 
{
	SmFsAttr a;
	int rv;

	rv = SmFsGetFileAttr( SENTINAL_FILE_NAME, &a );
    if (rv != 0)
    {
        /* File does not exist, create it */
        SmFsCreateFile(SENTINAL_FILE_NAME, 1);
        return 0;
    }
	return 1;
}

#endif

/* FM Startup function */
FM_RV Startup(void) 
{
	CprovFnTable_t *tbl = OS_GetCprovFuncTable();
	
#ifdef DEBUG
	dbg_init();

	if ( isFmEnabled() )
	{
		printf("FM started...");
	}
	else {
		printf("FM startup aborted!");
		/* return but do not patch Cprov table */
		return -1;
	}
#endif

	if (tbl != NULL) {
		/* put new entry point */
		tbl->C_OpenSession = FM_C_OpenSession;
	}
	
	return FM_OK;
}


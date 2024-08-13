/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: samples/restrict/fm/restrict.c
 */

/**
 * @file
 *	Restrict:
 *	This FM demonstrates the use of PKCS#11 function patching to restrict
 *	access to the adapter.
 */

#include <stdlib.h>
#include <stdio.h>
#include <cryptoki.h>
#include <cprovtbl.h>
#include <cprovpch.h>
#include <fm.h>
#include <fmdebug.h>

/* Patched version of function C_OpenSession().
 * If the Slot ID is 0, refuse to open the session. Otherwise, call the default
 * implementation of C_OpenSession().
 */
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

/* FM Startup function */
FM_RV Startup(void) 
{
    debug(printf("Patching cprov table ... ");)
	CprovFnTable_t *tbl = OS_GetCprovFuncTable();

	if (tbl != NULL) {
		/* put new entry point */
		tbl->C_OpenSession = FM_C_OpenSession;
        debug(printf("patched.");)
	}
	else {
        debug(printf("patching failed.");)
        return FM_UNSUCCESSFUL;
	}
	return FM_OK;
}

/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: samples/xorsign/fm/xorsign.c
 */

/**
 * @file
 * XOR_DIGEST:
 * This sample FM demonstrates patching the PKCS#11 functions to implement a
 * new mechanism.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <cryptoki.h>
#include <cprovtbl.h>
#include <cprovpch.h>
#include <fm.h>
#include <fmdebug.h>
#include <objstate.h>

#include "xorsign.h"

/* this structure gets appended to the session */
typedef struct {
	/* add items here that make the context for the function */
	CK_BYTE parameter[8];
	CK_SIZE len;
} Ctx_t;

/* Init the session for the subsequent operation */
CK_RV CK_ENTRY FM_C_SignInit(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey)
{
    Ctx_t *ctx;
    CK_RV rv;

	if ( pMechanism == NULL )
		return CKR_ARGUMENTS_BAD;

	/* memory leak check */
    rv = FM_GetSessionUserData(FM_NUMBER_CUSTOM_FM, hSession,
                               (CK_VOID_PTR_PTR)&ctx);
	if ( rv == 0 && ctx ) {
		/* Clear session state */
		FM_SetSessionUserData(FM_NUMBER_CUSTOM_FM, hSession, NULL, NULL);
	}

	if(pMechanism->mechanism != CKM_XOR) {
		/* pass through to firmware */
		rv = C_SignInit(hSession, pMechanism, hKey);
	}
	else {
		CK_MECHANISM mech;
		CK_SIZE len;
		ctx = (Ctx_t *)malloc(sizeof(Ctx_t));

		if (ctx == NULL) {
			rv = CKR_DEVICE_MEMORY;
			goto exit;
		}

		/* Set the session state. */
		rv = FM_SetSessionUserData(FM_NUMBER_CUSTOM_FM,
								   hSession,
								   ctx, free);

		/* save parameter in context data for next call */
		ctx->len = pMechanism->parameterLen;
		if ( ctx->len == 0 || ctx->len == 8 )
			memcpy(ctx->parameter, pMechanism->pParameter, ctx->len);
		else
			rv = CKR_ARGUMENTS_BAD;

		/* our base function is DES MAC so init for that function instead */
		mech.mechanism = CKM_DES_MAC_GENERAL;
		len = 8;
		mech.pParameter = &len;
		mech.parameterLen = sizeof(len);
		rv = C_SignInit(hSession, &mech, hKey);
	}

exit:
	return rv;
}

/* Perform our new function */
CK_RV CK_ENTRY FM_C_Sign(CK_SESSION_HANDLE hSession,
						 CK_BYTE_PTR pData,CK_SIZE dataLen,
						 CK_BYTE_PTR pSignature, CK_SIZE * pSignatureLen)
{
	CK_RV rv = 0;
    Ctx_t *ctx;

	if ( pSignatureLen == NULL )
		return CKR_ARGUMENTS_BAD;

	if ( pSignature == NULL ) {
		/* length prediction */
        rv = C_Sign(hSession, pData, dataLen, pSignature, pSignatureLen);
		goto exit;
	}

    rv = FM_GetSessionUserData(FM_NUMBER_CUSTOM_FM, hSession,
                               (CK_VOID_PTR_PTR)&ctx);
    if (rv != CKR_OK || ctx == NULL) {
		/* pass through to firmware */
        rv = C_Sign(hSession, pData, dataLen, pSignature, pSignatureLen);
    } else {
		CK_BYTE_PTR bp;
		CK_SIZE i, len;
		/* do the DES MAC */
		rv = C_Sign(hSession, pData, dataLen, pSignature, pSignatureLen);
		if ( rv ) goto exit;
		/* Xor in data for OWF */
		bp = pSignature;
		len = * pSignatureLen;
		if ( len > dataLen )
			len = dataLen;
		for(i=0; i < len; i ++) {
			bp[i] ^= pData[i];
		}
		/* Xor in parameter if supplied */
		if ( ctx->len ) {
			bp = pSignature;
			len = * pSignatureLen;
			if ( len > ctx->len )
				len = ctx->len;
			for(i=0; i < len; i ++) {
				bp[i] ^= ctx->parameter[i];
			}
		}
	}

exit:
	return rv;
}

/* Install filter for this function that is not valid for our new mechanism
*/
CK_RV CK_ENTRY FM_C_SignUpdate(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pData,CK_SIZE dataLen)
{
    CK_RV rv;

    Ctx_t *ctx;

    rv = FM_GetSessionUserData(FM_NUMBER_CUSTOM_FM, hSession,
                               (CK_VOID_PTR_PTR)&ctx);
    if (rv != CKR_OK || ctx == NULL) {
        /* No context. Allow the firmware to handle this. */
        rv = C_SignUpdate(hSession, pData, dataLen);
    } else {
        /* Context set. We must have initialized a digest. */
        rv = CKR_FUNCTION_NOT_SUPPORTED;
    }

	return rv;
}

/* Install filter for this function that is not valid for our new mechanism
*/
CK_RV CK_ENTRY FM_C_SignFinal(CK_SESSION_HANDLE hSession,CK_BYTE_PTR pData,CK_SIZE_PTR dataLen)
{
    CK_RV rv;

    Ctx_t *ctx;

    rv = FM_GetSessionUserData(FM_NUMBER_CUSTOM_FM, hSession,
                               (CK_VOID_PTR_PTR)&ctx);
    if (rv != CKR_OK || ctx == NULL) {
        /* No context. Allow the firmware to handle this. */
        rv = C_SignFinal(hSession, pData, dataLen);
    } else {
        /* Context set. We must have initialized a digest. */
        rv = CKR_FUNCTION_NOT_SUPPORTED;
    }

	return rv;
}

/* Install our function filters
*/
FM_RV Startup(void) 
{
	CprovFnTable_t *tbl;

    debug(printf("Patching cprov table ... ");)
	/* get pointer to FM API function table */
	tbl = OS_GetCprovFuncTable();

	/* patch it */
	if(tbl != NULL) {
		tbl->C_SignInit = FM_C_SignInit;
		tbl->C_Sign = FM_C_Sign;
		tbl->C_SignUpdate = FM_C_SignUpdate;
		tbl->C_SignFinal = FM_C_SignFinal;
		debug(printf("patched.");)
	}
	else{
	    debug(printf("patching failed.");)
	    return FM_UNSUCCESSFUL;
	}
	return FM_OK;
}

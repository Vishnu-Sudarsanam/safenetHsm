/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2016 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: samples/secfmenc/fm/secfmenc.c
 */

/**
 * @file
 * secfmenc program: This sample custom FM code works with secfmenctest host side application which demonstrates the working 
  of cryptoki extended API FMSC_SendReceive().
 */

#include <stdlib.h>
#include <stdio.h>
#include <cryptoki.h>
#include <cprovtbl.h>
#include <cprovpch.h>
#include <csa8hiface.h>
#include <string.h>
#include <fmsw.h>
#include <fm.h>
#include <fmdebug.h>

extern CprovFnTable_t *FM_GetCprovFuncs(void);

#define MY_FM_NUMBER        0x400		/* FM_ID */
#define FMCMD_RSA_ENC    	0x0C		/* Command to perform RSA encryption */
#define FMCMD_DES3_ENC	 	0x0D		/* Command to perform DES3 encryption */

int Custom_FM_Enc(unsigned char com, char *id, char *in, int inLen, char *out, int *outLen)
{
    CK_SESSION_HANDLE hSession;
    CK_OBJECT_HANDLE hKey;
    CK_OBJECT_HANDLE_PTR phKey = &hKey;
    CK_COUNT objectCount = 0;
    CK_MECHANISM mech;
	CK_OBJECT_CLASS keyClass;
	CK_BYTE iv[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	
	CK_ATTRIBUTE template[] = {
		{CKA_LABEL, NULL, 0},
		{CKA_CLASS, &keyClass , sizeof(keyClass )}
	};
	
	CK_SIZE outLen_short;
    CK_RV rv;
	
	if(com == FMCMD_RSA_ENC)keyClass = CKO_PUBLIC_KEY;
	else if(com == FMCMD_DES3_ENC) keyClass = CKO_SECRET_KEY;

    template[0].pValue = id;
    template[0].valueLen = (CK_SIZE)strlen((char *)id);
	
    rv = C_OpenSession(0, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL, NULL, &hSession);
    if ( rv ) return rv;
	
    rv = C_FindObjectsInit(hSession, template, 2);
    if ( rv ) return rv;

    rv = C_FindObjects(hSession, phKey, 1, &objectCount);
    if ( rv ) return rv;
    
    if(objectCount < 1) {
        *outLen = 0;
        return CKR_ARGUMENTS_BAD;
    }

    hKey = *phKey;
    memset(&mech, 0, sizeof(mech));
	if(com == FMCMD_RSA_ENC) 
	{
		mech.mechanism = CKM_RSA_PKCS;
	}
	else if(com == FMCMD_DES3_ENC) 
	{
		mech.mechanism = CKM_DES3_CBC_PAD;
		mech.pParameter = iv;
		mech.parameterLen = 8;
	}
	else
	{
		return CKR_MECHANISM_INVALID;
	}
	
    rv = C_EncryptInit(hSession, &mech, hKey);
    if ( rv ) return rv;

    outLen_short = (CK_SIZE)*outLen;
    rv = C_Encrypt(hSession, (unsigned char*)in, inLen, (unsigned char*)out, &outLen_short);
    *outLen = (int)outLen_short;

    if ( rv ) return rv;

    rv = C_CloseSession(hSession);
    
    if ( rv ) return rv;
    
    return rv;
}

/* command handler entry point */
static void CustomFM_HandleMessage(
    HI_MsgHandle token,            
    void *reqBuffer,            
    uint32_t reqLength)            
{
    char *id = NULL, 
          *in = NULL, 
          *out = NULL,
          *parg = NULL;
    unsigned char cmd;
    int inLen, idLen, bufLen;
    uint32_t outLen, outLen_user;
    int rv;
	
    /* Argument sanity check */
    if (reqLength < (3 * sizeof(unsigned short)) )
    {
        /* Ensure the request is long enough to contain at least the 
           cmd + length of id + length of buffer */ 
        return;
    }

    /* parse command */
	cmd = (*(unsigned char *)reqBuffer); 							/* Command */
    parg = (char*)reqBuffer + sizeof(unsigned char);
	
    /* command switch, only one command */
    switch(cmd) {
    case FMCMD_RSA_ENC:
	case FMCMD_DES3_ENC:
		idLen = *parg;
		id = calloc(1, idLen+1);
		memcpy(id, parg+1, idLen);									/* Key ID to use. */

		bufLen = *(parg + 1 + idLen);
		in = calloc(1, bufLen + 1);
		memcpy(in, parg + 1 + idLen + 1, bufLen);					/* Buffer to encrypt. */
		inLen=bufLen;
		
        outLen_user = SVC_GetUserReplyBufLen(token);

        /* Allocate the reply buffer. */
        out = SVC_GetReplyBuffer(token, outLen_user);

        /* call API fuction */
        outLen = outLen_user ;
        rv = Custom_FM_Enc(cmd, id, in, inLen , out, (int*)&outLen);

        /* shrink reply buffer is needed */
        if(rv == CKR_OK && outLen < outLen_user) { 
            if(SVC_ResizeReplyBuffer(token, outLen) == NULL) rv = CKR_DEVICE_MEMORY;
        }

        /* send reply back */

        SVC_SendReply(token, (uint32_t) rv);
        break;

    default:
        SVC_SendReply(token, (uint32_t) CKR_FUNCTION_NOT_SUPPORTED);
        break;
    }

    /* Free the memory if it has been allocated */
    if (id) 
    { 
        free(id);
        id =  NULL;
    }

    if (in) 
    {
        free(in);
        in = NULL;
    }
}

/* FM Startup function */
FM_RV Startup(void) 
{
    FM_RV rv;

    /* register handler for our new API */
    debug(printf("Registering dispatch function ... ");)
    rv = FMSW_RegisterDispatch(MY_FM_NUMBER, CustomFM_HandleMessage);
    debug(printf("registered. Return Code = 0x%x", rv);)

    return rv;
}

/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: samples/rsaenc/fm/rsaenc.c
 */

/**
 * @file
 * RSA_ENC program: Demonstrates the creation of a custom API using 
 * the FM SDK.
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

#define FMCMD_RSA_ENC    0x0001
#define MY_FM_NUMBER     0x300

int Custom_RSA_Enc(char *id, char *in, int inLen, char *out, int *outLen)
{

    CK_SESSION_HANDLE hSession;
    CK_OBJECT_HANDLE hKey;
    CK_OBJECT_HANDLE_PTR phKey = &hKey;
    CK_COUNT objectCount = 0;
    CK_MECHANISM mech;
    CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
    int alreadyWasInited= 0;

    CK_ATTRIBUTE template[] = {
        {CKA_LABEL, NULL, 0},
        {CKA_CLASS, &pubKeyClass , sizeof(pubKeyClass )}
    };
    CK_SIZE outLen_short;
    CK_RV rv;

    template[0].pValue = id;
    template[0].valueLen = (CK_SIZE)strlen((char *)id);

    rv = C_Initialize(NULL_PTR);
    if ( rv ) {
       if ( rv == CKR_CRYPTOKI_ALREADY_INITIALIZED ) {
           alreadyWasInited = 1;
           rv = CKR_OK;
       } else
           return rv;
    }

    rv = C_OpenSession(0, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL, NULL, &hSession);
    if ( rv ) goto error;

    rv = C_FindObjectsInit(hSession, template, 2);
    if ( rv ) goto error;

    rv = C_FindObjects(hSession, phKey, 1, &objectCount);
    if ( rv ) goto error;
    
    if(objectCount < 1) {
        *outLen = 0;
        rv = CKR_ARGUMENTS_BAD;
        goto error;
    }

    hKey = *phKey;
    memset(&mech, 0, sizeof(mech));
    mech.mechanism = CKM_RSA_PKCS;

    rv = C_EncryptInit(hSession, &mech, hKey);
    if ( rv ) goto error;

    outLen_short = (CK_SIZE)*outLen;
    rv = C_Encrypt(hSession, (unsigned char*)in, inLen, (unsigned char*)out, &outLen_short);
    *outLen = (int)outLen_short;

    if ( rv ) goto error;

    rv = C_CloseSession(hSession);
    
    if ( rv ) goto error;
    
error:
    if ( !alreadyWasInited )
        rv = C_Finalize(NULL_PTR);

    return rv;
}

/* command handler entry point */
static void RsaEncFM_HandleMessage(
    HI_MsgHandle token,            
    void *reqBuffer,            
    uint32_t reqLength)            
{
    char *id = NULL, 
          *in = NULL, 
          *out = NULL,
          *parg = NULL;
    unsigned short cmd, id_len;
    int inLen;
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
    cmd = (unsigned short) ntoh_short(*(unsigned short *)reqBuffer); 
    parg = (char*)reqBuffer + sizeof(unsigned short);

    /* command switch, only one command */
    switch(cmd) {
    case FMCMD_RSA_ENC:
        /* parse len of id */
        id_len = (unsigned short) ntoh_short(*(unsigned short *)parg); 
        parg += sizeof(unsigned short);

        /* parse id, it's zero terminated string */
        id = malloc(id_len+1);
        memcpy(id,parg,id_len);
        id[id_len] = 0;        
        parg += id_len;

        /* parse length of the buffer */
        inLen = ntoh_long(*(unsigned long *)parg); 
        parg += sizeof(unsigned long);

        /*  allocate buffer */
        in = malloc(inLen);
        memcpy(in,parg,inLen);

        /* get size of the user reply buffer */
        outLen_user = SVC_GetUserReplyBufLen(token);

        /* Allocate the reply buffer. */
        out = SVC_GetReplyBuffer(token, outLen_user);

        /* call API fuction */
        outLen = outLen_user ;
        rv = Custom_RSA_Enc(id, in, inLen , out, (int*)&outLen);

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
    rv = FMSW_RegisterDispatch(MY_FM_NUMBER, RsaEncFM_HandleMessage);
    debug(printf("registered. Return Code = 0x%x", rv);)

    return rv;
}

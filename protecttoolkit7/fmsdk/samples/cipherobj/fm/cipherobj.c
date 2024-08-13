/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: samples/cipherobj/fm/cipherobj.c
 */
/**
 * @file
 *    CIPHER_OBJ program : This FM demonstrates the use of cipher objects to
 *    perform cryptographic operations. This sample will produce a hash of 
 *    the given plaintext, then perform a triple-DES encryption of the 
 *    plaintext. The ciphertext is concatenated to the hash value and returned
 *    to the user. 
 *
 *    This sample also demonstrates the use of the CT_SetPrivilege() function
 *    to raise privilege in order to read the value of a sensitive attribute.
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
#include <fmciphobj.h>

extern CprovFnTable_t *FM_GetCprovFuncs(void);

#define FMCMD_SHA1_DES3_ENC     0x0001
#define KEYVALSIZE              24 /* DES3 key */
#define MY_FM_NUMBER            0x200

int DES_Enc(char *keyName, char *in, unsigned int inLen, char *out, int *outLen)
{
    CK_SESSION_HANDLE hSession;
    CK_OBJECT_HANDLE hKey;
    CK_OBJECT_HANDLE_PTR phKey = &hKey;
    CK_COUNT objectCount = 0;
    CK_ATTRIBUTE searchTemplate[] = {
        {CKA_LABEL, NULL, 0}
    };
    CK_SIZE totalOutBufLen = *outLen;
    CK_RV rv;
    static CK_BYTE keyVal[KEYVALSIZE];
    CK_ATTRIBUTE keyValTemplate[] = {
        {CKA_VALUE, keyVal, KEYVALSIZE}
    };
    unsigned int outLen_tmp = 0, hashLen = 0;

    CipherObj *pCiphObj = NULL;
    HashObj *pHashObj = NULL;

    /* Set up the search template to search for the DES3 key */
    searchTemplate[0].pValue = keyName;
    searchTemplate[0].valueLen = (CK_SIZE)strlen((char *)keyName);

    /* ...... KEY LOCATION ...... */

    /* The key is stored as a PKCS#11 object on the token in slot 0 - find it */
    rv = C_Initialize(NULL_PTR);
    if ( rv ) return rv;    

    rv = C_OpenSession(0, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL, NULL, &hSession);
    if ( rv ) return rv;

    rv = C_FindObjectsInit(hSession, searchTemplate, 1);
    if ( rv ) return rv;

    rv = C_FindObjects(hSession, phKey, 1, &objectCount);
    if ( rv ) return rv;

    if(objectCount < 1) {
        *outLen = 0;
        return CKR_ARGUMENTS_BAD;
    }

    /* To read the keys value, we need to set the privilege level to 
       PRIVILEGE_OVERRIDE, as the key may (should) be marked as 
       sensitive, thereby hiding its value. With the privilege
       level set to PRIVILEGE_OVERRIDE, the sensitive attribute will be
       overridden, allowing us to read the keys value*/
    CT_SetPrivilegeLevel(PRIVILEGE_OVERRIDE);

    rv = C_GetAttributeValue(hSession, *phKey, keyValTemplate, 1);   
    if (rv)
    {
        CT_SetPrivilegeLevel(PRIVILEGE_NORMAL);
        goto exit;
    }

    /* Reduce the privilege level back to normal (non-privileged) */
    CT_SetPrivilegeLevel(PRIVILEGE_NORMAL);

    /* Check the value of the key */
    if (searchTemplate[0].ulValueLen == -1)
    {
        /* The keys value could not be read. Error */
        rv = CKR_KEY_HANDLE_INVALID;
        goto exit;
    }

    hKey = *phKey;

    /* ...... HASH ........ */

    /* Create the hash object to hash the plaintext */
    pHashObj = FmCreateHashObject(FMCO_IDX_SHA1);
    if (pHashObj == NULL)
    {
        rv = CKR_FUNCTION_FAILED;
        goto exit;
    }

    /* Initialise the hashing operation */
    rv = pHashObj->Init(pHashObj);
    if (rv) goto exit;

    /* Perform the hash function */
    rv = pHashObj->Update(pHashObj, in, inLen);
    if (rv) goto exit;

    rv = pHashObj->Final(pHashObj, (unsigned char*)out, totalOutBufLen, &hashLen);
    if (rv) goto exit;

    /* ...... ENCRYPTION ........ */

    /* Create the cipher object to perform the DES operation */
    pCiphObj = FmCreateCipherObject(FMCO_IDX_TRIPLEDES);
    if (pCiphObj == NULL) 
    {
        rv = CKR_FUNCTION_FAILED;
        goto exit;
    }

    /* Initialise the encrypt operation */
    rv = pCiphObj->EncInit(pCiphObj, 
                           SYM_MODE_CBC, /* Note : No padding */
                           keyVal, KEYVALSIZE,
                           NULL, 0);
    if (rv) goto exit;

    /* Perform the encrypt operation ... length prediction first */
    rv = pCiphObj->EncryptUpdate(pCiphObj,
                                 NULL, 0, (unsigned int*)outLen,
                                 in, inLen);
    if (rv) goto exit;

    /* Actual encrypt - update and final */
    rv = pCiphObj->EncryptUpdate(pCiphObj,

                                 out + hashLen, totalOutBufLen - hashLen, (unsigned int*)outLen, 
                                 in, inLen);
    if (rv) goto exit;

    rv = pCiphObj->EncryptFinal(pCiphObj, 
                                out + *outLen,
                                totalOutBufLen - *outLen - hashLen,
                                &outLen_tmp);
    if (rv) goto exit;

    /* Sum up the length of the data (length of hash plus length of cipher text) */
    *outLen += outLen_tmp + hashLen;

    /* Finalise the PKCS#11 session */
    rv = C_CloseSession(hSession);
    if (rv) goto exit;
    
    rv = C_Finalize(NULL_PTR);
    if (rv) goto exit;

exit:

    /* Free the cipher object if it has been created */
    if (pCiphObj) 
    { 
        pCiphObj->Free(pCiphObj);
        pCiphObj = NULL;
    }

    /* Free the hash object if it has been created */
    if (pHashObj)
    {
        pHashObj->Free(pHashObj);
        pHashObj = NULL;
    }

    return rv;
}

/* command handler entry point */
static void CiphObjFM_HandleMessage(
    HI_MsgHandle token,            
    void *reqBuffer,            
    uint32_t reqLength)            
{
    char *keyName = NULL, 
         *in = NULL,
         *out = NULL,
         *parg = NULL;
    unsigned short cmd, keyName_len;
    unsigned int inLen;
    uint32_t outLen, outLen_user;
    int rv;

    /* Argument sanity check */
    if (reqLength < (3 * sizeof(unsigned short)) )
    {
        /* Ensure the request is long enough to contain at least the 
           cmd + length of keyName + length of buffer */ 
        return;
    }

    /* parse command */
    cmd = (unsigned short) ntoh_short(*(unsigned short *)reqBuffer); 
    parg = (char*)reqBuffer + sizeof(unsigned short);
    reqLength -= sizeof(unsigned short);

    /* command switch, only one command */
    switch(cmd) {
    case FMCMD_SHA1_DES3_ENC:
        /* parse len of keyName */
        memcpy(&keyName_len, parg, sizeof(keyName_len));
        keyName_len = (unsigned short)ntoh_short(keyName_len);
        parg += sizeof(unsigned short);
        reqLength -= sizeof(unsigned short);
        if ( keyName_len > reqLength )
        {
            SVC_SendReply(token, (uint32_t) CKR_DATA_LEN_RANGE); /* send error reply back and stop processing */
            break;
        }

        /* parse keyName, it's zero terminated string */
        keyName = malloc(keyName_len+1);
        if ( !keyName )
        {
            SVC_SendReply(token, (uint32_t) CKR_DEVICE_MEMORY); /* send error reply back and stop processing */
            break;
        }
        memcpy(keyName,parg,keyName_len);
        keyName[keyName_len] = 0;        
        parg += keyName_len;
        reqLength -= keyName_len;

        /* parse length of the buffer */
        inLen = ntoh_long(*(unsigned long *)parg); 
        parg += sizeof(unsigned long);

        /*  allocate buffer */
        in = malloc(inLen);
        memcpy(in,parg,inLen);


        if ( inLen > reqLength )
        {
            SVC_SendReply(token, (uint32_t) CKR_DATA_LEN_RANGE); /* send error reply back and stop processing */
            break;
        }

        /*  allocate buffer */
        in = malloc(inLen);
        if ( !in )
        {
            SVC_SendReply(token, (uint32_t) CKR_DEVICE_MEMORY); /* send error reply back and stop processing */
            break;
        }
        memcpy(in,parg,inLen);

        /* get size of the user reply buffer */
        outLen_user = SVC_GetUserReplyBufLen(token);

        /* Allocate the reply buffer. */
        out = SVC_GetReplyBuffer(token, outLen_user);
        if ( !in )
        {
            SVC_SendReply(token, (uint32_t) CKR_DEVICE_MEMORY); /* send error reply back and stop processing */
            break;
        }

        /* call API fuction */
        outLen = outLen_user ;
        rv = DES_Enc(keyName, in, inLen , out, (int*)&outLen);

        /* shrink reply buffer if needed */
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

    /* Clean up */
    if (keyName) free(keyName);
    if (in) free(in);

}

/* FM Startup function */
FM_RV Startup(void) 
{
    FM_RV rv = 0;

    /* register handler for our new API */
    debug(printf("Registering dispatch function ... ");)
    rv = FMSW_RegisterDispatch(MY_FM_NUMBER, CiphObjFM_HandleMessage);
    debug(printf("registered. Return Code = 0x%x", rv);)

    return rv;
}

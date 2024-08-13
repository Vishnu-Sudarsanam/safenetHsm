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
#include <key.h>

extern CprovFnTable_t *FM_GetCprovFuncs(void);

#define MY_FM_NUMBER    0x100

/* Commands */
#define FMCMD_OAEP_ENC  0x0001
#define FMCMD_OAEP_DEC  0x0002


int rightJustify(unsigned char * tgt, size_t tlen,
				const unsigned char * src, size_t slen);
CK_RV objHandleToKey(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CtPriRsaKey*, CtPubRsaKey*, unsigned short cmd);

int doOAEP(char *keyName, char *in, unsigned int inLen, unsigned short cmd, char *out, int *outLen)
{
    CK_RV rv;
    CK_SESSION_HANDLE hSession;
    CK_OBJECT_HANDLE hKey = 0;
    CK_OBJECT_HANDLE_PTR phKey = &hKey;
	CK_BBOOL ckTrue = TRUE;
	CK_OBJECT_CLASS priClass = CKO_PRIVATE_KEY;
	CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
	CK_KEY_TYPE ckKt = CKK_RSA;
	CK_ULONG numObjectsToFind = 1;
	CK_ULONG numObjectsFound = 0;
    CK_SIZE totalOutBufLen = *outLen;
    CipherObj *pCiphObj = NULL;
    CtPriRsaKey rsapri;
    CtPubRsaKey rsapub;
    CK_ATTRIBUTE searchTemplate[5];
    CK_RSA_PKCS_OAEP_PARAMS oParams;
    
    oParams.hashAlg = CKM_SHA256;
    oParams.mgf = CKG_MGF1_SHA256;
    oParams.pSourceData = NULL;
    oParams.source = CKZ_DATA_SPECIFIED;
    oParams.sourceDataLen = 0;

    searchTemplate[0].type = CKA_TOKEN;
    searchTemplate[0].pValue = &ckTrue;
    searchTemplate[0].valueLen = (CK_SIZE)sizeof(CK_BBOOL);
    searchTemplate[1].type = CKA_LABEL;
    searchTemplate[1].pValue = keyName;
    searchTemplate[1].valueLen = (CK_SIZE)strlen((char *)keyName);
    searchTemplate[2].type = CKA_KEY_TYPE;
    searchTemplate[2].pValue = &ckKt;
    searchTemplate[2].valueLen = (CK_SIZE)sizeof(ckKt);

    if(cmd == FMCMD_OAEP_ENC){
        searchTemplate[3].type = CKA_CLASS;
        searchTemplate[3].pValue = &pubClass;
        searchTemplate[3].valueLen = (CK_SIZE)sizeof(pubClass);
        searchTemplate[4].type = CKA_ENCRYPT;
        searchTemplate[4].pValue = &ckTrue;
        searchTemplate[4].valueLen = (CK_SIZE)sizeof(CK_BBOOL);
    }else if (cmd == FMCMD_OAEP_DEC) {
        searchTemplate[3].type = CKA_CLASS;
        searchTemplate[3].pValue = &priClass;
        searchTemplate[3].valueLen = (CK_SIZE)sizeof(priClass);
        searchTemplate[4].type = CKA_DECRYPT;
        searchTemplate[4].pValue = &ckTrue;
        searchTemplate[4].valueLen = (CK_SIZE)sizeof(CK_BBOOL);
    }else{
        rv = CKR_FUNCTION_NOT_SUPPORTED;
        goto exit;
    }

    /* The key is stored as a PKCS#11 object on the token in slot 0 - find it */
    rv = C_Initialize(NULL_PTR);
    if ( rv ) goto exit;    

    rv = C_OpenSession(0, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL, NULL, &hSession);
    if ( rv ) goto exit;

    rv = C_FindObjectsInit(hSession, searchTemplate, 5);
    if ( rv ) goto exit;

    rv = C_FindObjects(hSession, phKey, numObjectsToFind, &numObjectsFound);
    if ( rv ) goto exit;

    if(numObjectsFound < 1) {
        *outLen = 0;
        rv = CKR_ARGUMENTS_BAD;
        goto exit;
    }

    rv = C_FindObjectsFinal(hSession);

    rv = objHandleToKey(hSession, hKey, &rsapri, &rsapub, cmd);

    if(rv){
        rv = CKR_OBJECT_HANDLE_INVALID;
        goto exit;
    }

    pCiphObj = FmCreateCipherObject(FMCO_IDX_RSA);

    if(pCiphObj){
        unsigned int plen;
        
        if(cmd == FMCMD_OAEP_ENC){
            
            rv = pCiphObj->EncInit(pCiphObj, 
                           RSA_MODE_OAEP,
                           &rsapub, sizeof(rsapub),
                           &oParams, sizeof(oParams));

            if (rv) goto exit;


            rv = pCiphObj->EncryptUpdate(pCiphObj,
                                 out, totalOutBufLen, &plen, 
                                 in, inLen);
            if (rv) goto exit;

            *outLen = plen;
            
        }else if (cmd == FMCMD_OAEP_DEC){
            rv = pCiphObj->DecInit(pCiphObj, 
                           RSA_MODE_OAEP,
                           &rsapri, sizeof(rsapri),
                           &oParams, sizeof(oParams));

            if (rv) goto exit;                           

            rv = pCiphObj->DecryptUpdate(pCiphObj,
                                 out, totalOutBufLen, &plen, 
                                 in, inLen);

            if (rv) goto exit;

            *outLen = plen;
        }
    }else{
        rv = CKR_FUNCTION_FAILED;
        goto exit;
    }

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


    return rv;
}

CK_RV objHandleToKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObj, CtPriRsaKey *pri, CtPubRsaKey *pub, unsigned short cmd){
    CK_RV rv = CKR_OK;

    CK_BYTE_PTR bits = NULL,
                mod  = NULL,
                pubexp  = NULL,
                priexp = NULL,
                prime_1 = NULL,
                prime_2 = NULL,
                exp_1 = NULL,
                exp_2 = NULL,
                coeff = NULL;

    CK_ATTRIBUTE pubKeyTemplate [] = {
        { CKA_MODULUS_BITS, NULL, 0 },
        { CKA_MODULUS, NULL, 0 },
        { CKA_PUBLIC_EXPONENT, NULL, 0 }
    };

    CK_ATTRIBUTE priKeyTemplate [] = {
        { CKA_MODULUS_BITS, NULL, 0 },
        { CKA_MODULUS, NULL, 0 },
        { CKA_PUBLIC_EXPONENT, NULL, 0 },
        { CKA_PRIVATE_EXPONENT, NULL, 0 },
        { CKA_PRIME_1, NULL, 0 },
        { CKA_PRIME_2, NULL, 0 },
        { CKA_EXPONENT_1, NULL, 0 },
        { CKA_EXPONENT_2, NULL, 0 },
        { CKA_COEFFICIENT, NULL, 0 },
    };

    if(!hObj){
        rv =  CKR_OBJECT_HANDLE_INVALID;
        goto exit;
    }

    CT_SetPrivilegeLevel(PRIVILEGE_OVERRIDE);
    
    if(cmd == FMCMD_OAEP_ENC){
        rv = C_GetAttributeValue(hSession, hObj, pubKeyTemplate, sizeof(pubKeyTemplate) / sizeof(CK_ATTRIBUTE));
        if(rv){
            goto exit;
        }else{
            bits = (CK_BYTE_PTR) malloc(pubKeyTemplate[0].valueLen);
            mod = (CK_BYTE_PTR) malloc(pubKeyTemplate[1].valueLen);
            pubexp = (CK_BYTE_PTR) malloc(pubKeyTemplate[2].valueLen);
        }
        pubKeyTemplate[0].pValue = bits;
        pubKeyTemplate[1].pValue = mod;
        pubKeyTemplate[2].pValue = pubexp;
        
        rv = C_GetAttributeValue(hSession, hObj, pubKeyTemplate, sizeof(pubKeyTemplate) / sizeof(CK_ATTRIBUTE));

        pub->modSz = (*(CK_ULONG_PTR)bits) / 8;
        pub->isPub = TRUE;
       	pub->key.bits[0] = (byte)(pub->modSz * 8 / 256);
	    pub->key.bits[1] = (byte)(pub->modSz * 8 % 256);
        rightJustify(pub->key.mod, sizeof(pub->key.mod), mod, pubKeyTemplate[1].valueLen);
        rightJustify(pub->key.exp, sizeof(pub->key.exp), pubexp, pubKeyTemplate[2].valueLen);
    }
    else if(cmd == FMCMD_OAEP_DEC){
        rv = C_GetAttributeValue(hSession, hObj, priKeyTemplate, sizeof(priKeyTemplate) / sizeof(CK_ATTRIBUTE));
        if(rv){
            goto exit;
        }else{
            bits = (CK_BYTE_PTR) malloc(priKeyTemplate[0].valueLen);
            mod = (CK_BYTE_PTR) malloc(priKeyTemplate[1].valueLen);
            pubexp = (CK_BYTE_PTR) malloc(priKeyTemplate[2].valueLen);
            priexp = (CK_BYTE_PTR) malloc(priKeyTemplate[3].valueLen);
            prime_1 = (CK_BYTE_PTR) malloc(priKeyTemplate[4].valueLen);
            prime_2 = (CK_BYTE_PTR) malloc(priKeyTemplate[5].valueLen);
            exp_1 = (CK_BYTE_PTR) malloc(priKeyTemplate[6].valueLen);
            exp_2 = (CK_BYTE_PTR) malloc(priKeyTemplate[7].valueLen);
            coeff = (CK_BYTE_PTR) malloc(priKeyTemplate[8].valueLen);

        }

        priKeyTemplate[0].pValue = bits;
        priKeyTemplate[1].pValue = mod;
        priKeyTemplate[2].pValue = pubexp;
        priKeyTemplate[3].pValue = priexp;
        priKeyTemplate[4].pValue = prime_1;
        priKeyTemplate[5].pValue = prime_2;
        priKeyTemplate[6].pValue = exp_1;
        priKeyTemplate[7].pValue = exp_2;
        priKeyTemplate[8].pValue = coeff;

        rv = C_GetAttributeValue(hSession, hObj, priKeyTemplate, sizeof(priKeyTemplate) / sizeof(CK_ATTRIBUTE));
        
        pri->modSz = (*(CK_ULONG_PTR)bits) / 8;
        pri->isPub = FALSE;
       	pri->key.bits[0] = (byte)(pub->modSz * 8 / 256);
	    pri->key.bits[1] = (byte)(pub->modSz * 8 % 256);
        pri->isXcrt = TRUE;
        rightJustify(pri->key.mod, sizeof(pri->key.mod), mod, priKeyTemplate[1].valueLen);
        rightJustify(pri->key.pub, sizeof(pri->key.pub), pubexp, priKeyTemplate[2].valueLen);
        rightJustify(pri->key.pri, sizeof(pri->key.pri), priexp, priKeyTemplate[3].valueLen);
        rightJustify(pri->key.p, sizeof(pri->key.p), prime_1 , priKeyTemplate[4].valueLen);
        rightJustify(pri->key.q, sizeof(pri->key.q), prime_2 , priKeyTemplate[5].valueLen);
        rightJustify(pri->key.e1, sizeof(pri->key.e1), exp_1 , priKeyTemplate[6].valueLen);
        rightJustify(pri->key.e2, sizeof(pri->key.e2), exp_2 , priKeyTemplate[7].valueLen);
        rightJustify(pri->key.u, sizeof(pri->key.u), coeff , priKeyTemplate[8].valueLen);
    }

    if(cmd == FMCMD_OAEP_ENC){
        rv = C_GetAttributeValue(hSession, hObj, pubKeyTemplate, sizeof(pubKeyTemplate) / sizeof(CK_ATTRIBUTE));
    }else if(cmd == FMCMD_OAEP_DEC){
        rv = C_GetAttributeValue(hSession, hObj, priKeyTemplate, sizeof(priKeyTemplate) / sizeof(CK_ATTRIBUTE));
    }

    CT_SetPrivilegeLevel(PRIVILEGE_NORMAL);
    
exit:
    if(bits) free (bits);
    if(mod) free (mod);
    if(pubexp) free (pubexp);
    if(priexp) free (priexp);
    if(prime_1) free (prime_1);
    if(prime_2) free (prime_2);
    if(exp_1) free (exp_1);
    if(exp_2) free (exp_2);
    if(coeff) free (coeff);

    return rv;

}

int rightJustify(unsigned char *tgt, size_t tlen,
                    const unsigned char *src, size_t slen)
{
    if (tlen < slen) return -1;
    memcpy(tgt + tlen - slen, src, slen);
    memset(tgt, 0, tlen - slen);
    return 0;
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
    int rv = CKR_OK;

    /* Argument sanity check */
    if (reqLength < (3 * sizeof(unsigned short)) )
    {
        /* Ensure the request is long enough to contain at least the 
           cmd + length of keyName + length of buffer */ 
        SVC_SendReply(token, (uint32_t) CKR_ARGUMENTS_BAD);
    }

    /* parse command */
    cmd = (unsigned short) ntoh_short(*(unsigned short *)reqBuffer); 
    parg = (char*)reqBuffer + sizeof(unsigned short);
    reqLength -= sizeof(unsigned short);

    /* parse len of keyName */
    memcpy(&keyName_len, parg, sizeof(keyName_len));
    keyName_len = (unsigned short)ntoh_short(keyName_len);
    parg += sizeof(unsigned short);
    reqLength -= sizeof(unsigned short);
    if ( keyName_len > reqLength )
    {
        SVC_SendReply(token, (uint32_t) CKR_DATA_LEN_RANGE); /* send error reply back and stop processing */
    }

    /* parse keyName, it's zero terminated string */
    keyName = malloc(keyName_len+1);
    if ( !keyName )
    {
        SVC_SendReply(token, (uint32_t) CKR_DEVICE_MEMORY); /* send error reply back and stop processing */
    }
    memcpy(keyName,parg,keyName_len);
    keyName[keyName_len] = 0;        
    parg += keyName_len;
    reqLength -= keyName_len;

    /* parse length of the buffer */
    inLen = ntoh_long(*(unsigned long *)parg); 
    parg += sizeof(uint32_t);

    if ( inLen > reqLength )
    {
        SVC_SendReply(token, (uint32_t) CKR_DATA_LEN_RANGE); /* send error reply back and stop processing */
    }

    /*  allocate buffer */
    in = malloc(inLen);

    if ( !in )
    {
        SVC_SendReply(token, (uint32_t) CKR_DEVICE_MEMORY); /* send error reply back and stop processing */
    }

    memcpy(in,parg,inLen);

    /* get size of the user reply buffer */
    outLen_user = SVC_GetUserReplyBufLen(token);

    /* Allocate the reply buffer. */
    out = SVC_GetReplyBuffer(token, outLen_user);
    if ( !out )
    {
        SVC_SendReply(token, (uint32_t) CKR_DEVICE_MEMORY); /* send error reply back and stop processing */
    }

    outLen = outLen_user ;

    switch(cmd) {
    case FMCMD_OAEP_ENC:
    case FMCMD_OAEP_DEC:
        rv = doOAEP(keyName, in, inLen , cmd, out, (int*)&outLen);
        break;
    default:
        SVC_SendReply(token, (uint32_t) CKR_FUNCTION_NOT_SUPPORTED);
        break;            
    }
        
    /* shrink reply buffer if needed */
    if(rv == CKR_OK && outLen < outLen_user) { 
        if(SVC_ResizeReplyBuffer(token, outLen) == NULL) rv = CKR_DEVICE_MEMORY;
    }

    /* send reply back */
    SVC_SendReply(token, (uint32_t) rv);
  
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

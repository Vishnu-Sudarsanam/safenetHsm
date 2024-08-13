/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: cprovtbl.h
 */
#ifndef INC_CPROVTBL_H
#define INC_CPROVTBL_H
#include <cryptoki.h>
#include <ctfext.h>

#ifndef FM_NO_SETPRIVILEGELEVEL
#include <privilege.h>
#endif

#include <ctvdef.h>

#ifndef V1COMPLIANT
typedef struct CprovFnTable_st {
	unsigned int numEntries;

	CK_C_GetFunctionList C_GetFunctionList;
	CK_C_Initialize C_Initialize;
	CK_C_Finalize C_Finalize;
	CK_C_GetInfo C_GetInfo;
	CK_C_GetSlotList C_GetSlotList;
	CK_C_GetSlotInfo C_GetSlotInfo;
	CK_C_GetTokenInfo C_GetTokenInfo;
	CK_C_GetMechanismList C_GetMechanismList;
	CK_C_GetMechanismInfo C_GetMechanismInfo;
	CK_C_InitToken C_InitToken;
	CK_C_InitPIN C_InitPIN;
	CK_C_SetPIN C_SetPIN;
	CK_C_OpenSession C_OpenSession;
	CK_C_CloseSession C_CloseSession;
	CK_C_CloseAllSessions C_CloseAllSessions;
	CK_C_GetSessionInfo C_GetSessionInfo;
	CK_C_GetOperationState C_GetOperationState;
	CK_C_SetOperationState C_SetOperationState;
	CK_C_Login C_Login;
	CK_C_Logout C_Logout;
	CK_C_CreateObject C_CreateObject;
	CK_C_CopyObject C_CopyObject;
	CK_C_DestroyObject C_DestroyObject;
	CK_C_GetObjectSize C_GetObjectSize;
	CK_C_GetAttributeValue C_GetAttributeValue;
	CK_C_SetAttributeValue C_SetAttributeValue;
	CK_C_FindObjectsInit C_FindObjectsInit;
	CK_C_FindObjects C_FindObjects;
	CK_C_FindObjectsFinal C_FindObjectsFinal;
	CK_C_DigestInit C_DigestInit;
	CK_C_Digest C_Digest;
	CK_C_DigestUpdate C_DigestUpdate;
	CK_C_DigestFinal C_DigestFinal;
	CK_C_DigestKey C_DigestKey;
	CK_C_EncryptInit C_EncryptInit;
	CK_C_Encrypt C_Encrypt;
	CK_C_EncryptUpdate C_EncryptUpdate;
	CK_C_EncryptFinal C_EncryptFinal;
	CK_C_DecryptInit C_DecryptInit;
	CK_C_Decrypt C_Decrypt;
	CK_C_DecryptUpdate C_DecryptUpdate;
	CK_C_DecryptFinal C_DecryptFinal;
	CK_C_SignInit C_SignInit;
	CK_C_Sign C_Sign;
	CK_C_SignUpdate C_SignUpdate;
	CK_C_SignFinal C_SignFinal;
	CK_C_VerifyInit C_VerifyInit;
	CK_C_Verify C_Verify;
	CK_C_VerifyUpdate C_VerifyUpdate;
	CK_C_VerifyFinal C_VerifyFinal;
	CK_C_SignRecoverInit C_SignRecoverInit;
	CK_C_SignRecover C_SignRecover;
	CK_C_VerifyRecoverInit C_VerifyRecoverInit;
	CK_C_VerifyRecover C_VerifyRecover;
	CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
	CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
	CK_C_SignEncryptUpdate C_SignEncryptUpdate;
	CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
	CK_C_GenerateKey C_GenerateKey;
	CK_C_GenerateKeyPair C_GenerateKeyPair;
	CK_C_WrapKey C_WrapKey;
	CK_C_UnwrapKey C_UnwrapKey;
	CK_C_DeriveKey C_DeriveKey;
	CK_C_SeedRandom C_SeedRandom;
	CK_C_GenerateRandom C_GenerateRandom;
	CK_C_GetFunctionStatus C_GetFunctionStatus;
	CK_C_CancelFunction C_CancelFunction;
	CK_C_WaitForSlotEvent C_WaitForSlotEvent;
	CK_CT_ResetToken CT_ResetToken;
	CK_CT_InitToken CT_InitToken;
	CK_CT_CopyObject CT_CopyObject;

#ifndef FM_NO_SETPRIVILEGELEVEL
	CK_CT_SetPrivilegeLevel CT_SetPrivilegeLevel;
#endif
	CK_CT_SetHsmDead CT_SetHsmDead;
	CK_CT_GetHSMId CT_GetHSMId;
    CK_CT_InitPIN CT_InitPIN;
	CK_CT_InitOtpSeed CT_InitOtpSeed;
	CK_CT_DelOtpSeed CT_DelOtpSeed;
	CK_CT_FetchCertificate CT_FetchCertificate;
} CprovFnTable_t;

/* Global variable used by firmware for lookup of PKCS#11 functions. */
extern CprovFnTable_t CprovSvcTable;

/*
 * CPROV_FN_TABLE_SIZE calculates the number of entries in the
 * CprovFnTable_t. It assumes that all the function pointers have the same size
 * as the CK_C_Initialize.
 */
#define CPROV_FN_TABLE_SIZE \
          ((sizeof(CprovFnTable_t) - \
          sizeof(unsigned int))/sizeof(CK_C_Initialize) + 1)

#endif
#endif /* INC_CPROVTBL_H */

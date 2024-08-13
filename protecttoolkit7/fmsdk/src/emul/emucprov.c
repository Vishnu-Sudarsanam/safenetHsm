/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: emucprov.c
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <objstate.h>
#include <csa8fm.h>
#include <fmemul.h>
#include <noreent.h>
#include <md.h>



#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#define GET_PID() GetCurrentProcessId()
#elif defined __linux__
#include <unistd.h>
#define GET_PID() getpid()
#else /* UNIX */
#define GET_PID() 0
#endif /*UNIX */

/**
 * @file
 * This module builds a cryptoki provider for the applications that are going 
 * to be used in testing the FM in emulation mode.
 *
 * An FM can patch the cryptoki functions.
 * The function patching is handled using an internal table in the FM emulation
 * DLL. All the functions in this provider use that table.
 * 
 * The address of the FMs table is obtained from the emulation FM DLL with 
 * FM_GetCprovTbl(). 
 *
 * Although this provider is re-enterant (except the C_Initialise and 
 * C_Finalise) the FM patching is not. 
 * Therefore this provider protects the FM from multi-threaded applications 
 * by single threading all calls to the FM using a mutex.
 */

/* Address of the patchable Function table in the FM. See cprovtbl.h for the 
 * definition of CprovFnTable_t. */
static CprovFnTable_t *cprovTbl = NULL;

/*
 * Local PKCS#11 function list table, as defined by the PKCS#11 standard. See
 * the PKCS#11 standard, cryptoki.h, and pkcs11f.h for the definition of the
 * table.
 * NOTE - this is not the patched table.
 */
static
CK_FUNCTION_LIST ctFunList = {
	{2,01},
	C_Initialize,
	C_Finalize,
	C_GetInfo,
	C_GetFunctionList,
	C_GetSlotList,
	C_GetSlotInfo,
	C_GetTokenInfo,
	C_GetMechanismList,
	C_GetMechanismInfo,
	C_InitToken,
	C_InitPIN,
	C_SetPIN,
	C_OpenSession,
	C_CloseSession,
	C_CloseAllSessions,
	C_GetSessionInfo,
	C_GetOperationState,
	C_SetOperationState,
	C_Login,
	C_Logout,
	C_CreateObject,
	C_CopyObject,
	C_DestroyObject,
	C_GetObjectSize,
	C_GetAttributeValue,
	C_SetAttributeValue,
	C_FindObjectsInit,
	C_FindObjects,
	C_FindObjectsFinal,
	C_EncryptInit,
	C_Encrypt,
	C_EncryptUpdate,
	C_EncryptFinal,
	C_DecryptInit,
	C_Decrypt,
	C_DecryptUpdate,
	C_DecryptFinal,
	C_DigestInit,
	C_Digest,
	C_DigestUpdate,
	C_DigestKey,
	C_DigestFinal,
	C_SignInit,
	C_Sign,
	C_SignUpdate,
	C_SignFinal,
	C_SignRecoverInit,
	C_SignRecover,
	C_VerifyInit,
	C_Verify,
	C_VerifyUpdate,
	C_VerifyFinal,
	C_VerifyRecoverInit,
	C_VerifyRecover,
	C_DigestEncryptUpdate,
	C_DecryptDigestUpdate,
	C_SignEncryptUpdate,
	C_DecryptVerifyUpdate,
	C_GenerateKey,
	C_GenerateKeyPair,
	C_WrapKey,
	C_UnwrapKey,
	C_DeriveKey,
	C_SeedRandom,
	C_GenerateRandom,
	C_GetFunctionStatus,
	C_CancelFunction,
	C_WaitForSlotEvent
};

/* This macro is used at the beginning of Cprov functions to ensure that the
 * global function table is initialized properly. Since it is repeated 69 times,
 * it is placed in a macro to simplify the code.
 * Please note that it does not handle the C_Initialize check completely. It
 * will only catch the first missing C_Initialize(). If the application calls
 * C_Initialize(), followed by C_Finalize(), followed by any function other than
 * C_Initialize(), the actual library will report CKR_CRYPTOKI_NOT_INITIALIZED;
 * not this module.
 */
#define C_FUNC_INIT()								\
	{											\
		if (cprovTbl == NULL) {						\
			return CKR_CRYPTOKI_NOT_INITIALIZED;	\
		} 											\
	}

/*
 * Return function list as pointers to OUR functions, not the ones in the
 * table. This ensures that the patching can be done aytime. Not only before
 * this functions is called.
 */
DLL_EXPORT CK_RV CK_ENTRY C_GetFunctionList(
		CK_FUNCTION_LIST_PTR_PTR ppFunctionList
)
{
	* ppFunctionList = &ctFunList;
	return CKR_OK;
}

/*
 * This function initializes the FM module (for applications which only use
 * Cryptoki). It also obtains the function list address from the FM emulation
 * DLL, to ensure that further calls into cryptoki will be affected by FMs
 * function patching.
 *
 * This function must not be called from two threads simultaneously.
 */
DLL_EXPORT CK_RV CK_ENTRY C_Initialize(
		CK_VOID_PTR pReserved
)
{
	CK_RV rv;
	MD_RV fmRv;
	CK_C_INITIALIZE_ARGS iArgs = { 0, 0, 0, 0, CKF_OS_LOCKING_OK };

	/* ensure the FM is started up - (may safely be called more than once) */
	fmRv = EMULFM_Startup();
	if ( fmRv != MDR_OK )
		return CKR_GENERAL_ERROR;

	NOREENT_Init(&iArgs);
	/* get address of the patchable table from the fM 
	 * (cannot fail if startup is OK) 
	*/
	cprovTbl = FM_GetCprovFuncs();

	globalDispState.appId.oid = 0;
	globalDispState.appId.pid = GET_PID();
    if(pAPPID_SetAppId != NULL)
        pAPPID_SetAppId(&globalDispState.appId);

	/* pass down the initialise call */
	rv = cprovTbl->C_Initialize(pReserved);

	/* do any necessary cleanup */
	EMULFM_ResetPrivilegeLevel();

	return rv;
}

/*
 * This function finalizes the cryptoki
 */
DLL_EXPORT CK_RV CK_ENTRY C_Finalize(
		CK_VOID_PTR pReserved
)
{
	CK_RV rv;

	C_FUNC_INIT();

	NOREENT_Enter();

	rv = cprovTbl->C_Finalize(pReserved);

	EMULFM_ResetPrivilegeLevel();

	EMULFM_Shutdown();

	if (rv != CKR_OK) {
		NOREENT_Leave();
		return rv;
	}
	EMULFM_FreeAllUserData();

	NOREENT_Leave();

	return CKR_OK;
}

/*
 * The rest of the functions are simply calls into the actual functions using
 * the funtion table obtained in C_Initialize().
 */

/* -------------------------------------------------------------------------- */

DLL_EXPORT CK_RV CK_ENTRY C_GetInfo(
		CK_INFO_PTR pInfo
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_GetInfo(pInfo);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_GetSlotList(
		CK_BBOOL tokenPresent,
		CK_SLOT_ID_PTR pSlotList,
		CK_COUNT_PTR pCount
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_GetSlotList(tokenPresent, pSlotList, pCount);

	EMULFM_FreeAllUserData();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_GetSlotInfo(
		CK_SLOT_ID slotID,
		CK_SLOT_INFO_PTR pInfo
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_GetSlotInfo(slotID, pInfo);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_GetTokenInfo(
		CK_SLOT_ID slotID,
		CK_TOKEN_INFO_PTR pInfo
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_GetTokenInfo(slotID, pInfo);

	EMULFM_FreeAllUserData();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_GetMechanismList(
		CK_SLOT_ID slotID,
		CK_MECHANISM_TYPE_PTR pMechanismList,
		CK_COUNT_PTR pCount
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_GetMechanismList(slotID, pMechanismList, pCount);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_GetMechanismInfo(
		CK_SLOT_ID slotID,
		CK_MECHANISM_TYPE type,
		CK_MECHANISM_INFO_PTR pInfo
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_GetMechanismInfo(slotID, type, pInfo);

	EMULFM_FreeAllUserData();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_InitToken(
		CK_SLOT_ID slotID,
		CK_CHAR_PTR pPin,
		CK_SIZE pinLen,
		CK_CHAR_PTR pLabel
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_InitToken(slotID, pPin, pinLen, pLabel);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_InitPIN(
		CK_SESSION_HANDLE hSession,
		CK_CHAR_PTR pPin,
		CK_SIZE pinLen
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_InitPIN(hSession, pPin, pinLen);

	EMULFM_FreeAllUserData();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_SetPIN(
		CK_SESSION_HANDLE hSession,
		CK_CHAR_PTR pOldPin,
		CK_SIZE oldLen,
		CK_CHAR_PTR pNewPin,
		CK_SIZE newLen
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_SetPIN(hSession, pOldPin, oldLen, pNewPin, newLen);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_OpenSession(
		CK_SLOT_ID slotID,
		CK_FLAGS flags,
		CK_VOID_PTR pApplication,
		CK_NOTIFY Notify,
		CK_SESSION_HANDLE_PTR phSession
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_OpenSession(slotID, flags, pApplication, Notify,
			phSession);

	EMULFM_ResetPrivilegeLevel();

	if (rv == CKR_OK) {
		rv = EMULFM_AddSessionToSlot(slotID, *phSession);
		if (rv != CKR_OK) {
			C_CloseSession(*phSession);
			*phSession = CK_INVALID_HANDLE;
		}
	}
	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_CloseSession(
		CK_SESSION_HANDLE hSession
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_CloseSession(hSession);

	EMULFM_FreeSessionUserData(hSession);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_CloseAllSessions(
		CK_SLOT_ID slotID
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_CloseAllSessions(slotID);

	EMULFM_FreeSlotSessions(slotID);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_GetSessionInfo(
		CK_SESSION_HANDLE hSession,
		CK_SESSION_INFO_PTR pInfo
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_GetSessionInfo(hSession, pInfo);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_GetOperationState(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pOperationState,
		CK_SIZE_PTR pOperationStateLen)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_GetOperationState(hSession,
									   pOperationState,
									   pOperationStateLen);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_SetOperationState(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pOperationState,
		CK_SIZE operationStateLen,
		CK_OBJECT_HANDLE hEncKey,
		CK_OBJECT_HANDLE hAuthKey)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_SetOperationState(hSession, pOperationState,
			operationStateLen, hEncKey, hAuthKey);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_Login(
		CK_SESSION_HANDLE hSession,
		CK_USER_TYPE userType,
		CK_CHAR_PTR pPin,
		CK_SIZE pinLen
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_Login(hSession, userType, pPin, pinLen);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_Logout(
		CK_SESSION_HANDLE hSession
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_Logout(hSession);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_CreateObject(
		CK_SESSION_HANDLE hSession,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_COUNT count,
		CK_OBJECT_HANDLE_PTR phObject
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_CreateObject(hSession, pTemplate, count, phObject);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_CopyObject(
		CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_COUNT count,
		CK_OBJECT_HANDLE_PTR phNewObject
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_CopyObject(hSession, hObject, pTemplate, count,
			phNewObject);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_DestroyObject(
		CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_DestroyObject(hSession, hObject);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_GetObjectSize(
		CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject,
		CK_SIZE_PTR pSize
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_GetObjectSize(hSession, hObject, pSize);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_GetAttributeValue(
		CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_COUNT count
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_GetAttributeValue(hSession, hObject, pTemplate, count);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_SetAttributeValue(
		CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_COUNT count
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_SetAttributeValue(hSession, hObject, pTemplate, count);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_FindObjectsInit(
		CK_SESSION_HANDLE hSession,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_COUNT count
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_FindObjectsInit(hSession, pTemplate, count);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_FindObjects(
		CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE_PTR phObject,
		CK_COUNT maxObjectCount,
		CK_COUNT_PTR pObjectCount
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_FindObjects(hSession, phObject, maxObjectCount,
			pObjectCount);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_FindObjectsFinal(
		CK_SESSION_HANDLE hSession
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_FindObjectsFinal(hSession);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_DigestInit(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_DigestInit(hSession, pMechanism);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_Digest(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_SIZE dataLen,
		CK_BYTE_PTR pOutData,
		CK_SIZE_PTR pOutDataLen
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_Digest(hSession, pData, dataLen, pOutData, pOutDataLen);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_DigestUpdate(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_SIZE dataLen
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_DigestUpdate(hSession, pData, dataLen);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_DigestFinal(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pOutData,
		CK_SIZE_PTR pOutDataLen
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_DigestFinal(hSession, pOutData, pOutDataLen);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_DigestKey(
		CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hKey
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_DigestKey(hSession, hKey);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_EncryptInit(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_EncryptInit(hSession, pMechanism, hKey);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_Encrypt(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_SIZE dataLen,
		CK_BYTE_PTR pOutData,
		CK_SIZE_PTR pOutDataLen
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_Encrypt(hSession, pData, dataLen, pOutData, pOutDataLen);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_EncryptUpdate(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_SIZE dataLen,
		CK_BYTE_PTR pOutData,
		CK_SIZE_PTR pOutDataLen
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_EncryptUpdate(hSession, pData, dataLen, pOutData,
			pOutDataLen);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_EncryptFinal(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pOutData,
		CK_SIZE_PTR pOutDataLen
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_EncryptFinal(hSession, pOutData, pOutDataLen);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_DecryptInit(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_DecryptInit(hSession, pMechanism, hKey);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_Decrypt(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_SIZE dataLen,
		CK_BYTE_PTR pOutData,
		CK_SIZE_PTR pOutDataLen
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_Decrypt(hSession, pData, dataLen, pOutData, pOutDataLen);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_DecryptUpdate(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_SIZE dataLen,
		CK_BYTE_PTR pOutData,
		CK_SIZE_PTR pOutDataLen
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_DecryptUpdate(hSession, pData, dataLen, pOutData,
			pOutDataLen);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_DecryptFinal(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pOutData,
		CK_SIZE_PTR pOutDataLen
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_DecryptFinal(hSession, pOutData, pOutDataLen);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_SignInit(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_SignInit(hSession, pMechanism, hKey);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_Sign(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_SIZE dataLen,
		CK_BYTE_PTR pOutData,
		CK_SIZE_PTR pOutDataLen
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_Sign(hSession, pData, dataLen, pOutData, pOutDataLen);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_SignUpdate(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_SIZE dataLen
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_SignUpdate(hSession, pData, dataLen);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_SignFinal(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pOutData,
		CK_SIZE_PTR pOutDataLen
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_SignFinal(hSession, pOutData, pOutDataLen);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_VerifyInit(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_VerifyInit(hSession, pMechanism, hKey);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_Verify(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_SIZE dataLen,
		CK_BYTE_PTR pSignature,
		CK_SIZE signatureLen
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_Verify(hSession, pData, dataLen, pSignature,
			signatureLen);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_VerifyUpdate(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_SIZE dataLen
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_VerifyUpdate(hSession, pData, dataLen);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_VerifyFinal(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pSignature,
		CK_SIZE signatureLen
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_VerifyFinal(hSession, pSignature, signatureLen);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_SignRecoverInit(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_SignRecoverInit(hSession, pMechanism, hKey);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_SignRecover(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_SIZE dataLen,
		CK_BYTE_PTR pOutData,
		CK_SIZE_PTR pOutDataLen
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_SignRecover(hSession, pData, dataLen, pOutData,
			pOutDataLen);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_VerifyRecoverInit(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_VerifyRecoverInit(hSession, pMechanism, hKey);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_VerifyRecover(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_SIZE dataLen,
		CK_BYTE_PTR pOutData,
		CK_SIZE_PTR pOutDataLen
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_VerifyRecover(hSession, pData, dataLen, pOutData,
			pOutDataLen);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_DigestEncryptUpdate(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData, CK_SIZE dataLen,
		CK_BYTE_PTR pOutData, CK_SIZE_PTR pOutDataLen
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_DigestEncryptUpdate(hSession, pData, dataLen, pOutData,
			pOutDataLen);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_DecryptDigestUpdate(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData, CK_SIZE dataLen,
		CK_BYTE_PTR pOutData, CK_SIZE_PTR pOutDataLen
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_DecryptDigestUpdate(hSession, pData, dataLen, pOutData,
			pOutDataLen);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_SignEncryptUpdate(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData, CK_SIZE dataLen,
		CK_BYTE_PTR pOutData, CK_SIZE_PTR pOutDataLen
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_SignEncryptUpdate(hSession, pData, dataLen, pOutData,
			pOutDataLen);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_DecryptVerifyUpdate(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData, CK_SIZE dataLen,
		CK_BYTE_PTR pOutData, CK_SIZE_PTR pOutDataLen
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_DecryptVerifyUpdate(hSession, pData, dataLen, pOutData,
			pOutDataLen);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_GenerateKey(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_COUNT count,
		CK_OBJECT_HANDLE_PTR phKey
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_GenerateKey(hSession, pMechanism, pTemplate, count,
			phKey);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_GenerateKeyPair(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_ATTRIBUTE_PTR pPublicKeyTemplate,
		CK_COUNT publicKeyAttributeCount,
		CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
		CK_COUNT privateKeyAttributeCount,
		CK_OBJECT_HANDLE_PTR phPublicKey,
		CK_OBJECT_HANDLE_PTR phPrivateKey
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_GenerateKeyPair(hSession, pMechanism,
			pPublicKeyTemplate, publicKeyAttributeCount,
			pPrivateKeyTemplate, privateKeyAttributeCount,
			phPublicKey, phPrivateKey);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_WrapKey(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hWrappingKey,
		CK_OBJECT_HANDLE hKey,
		CK_BYTE_PTR pOutData,
		CK_SIZE_PTR pOutDataLen
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_WrapKey(hSession, pMechanism, hWrappingKey, hKey,
			pOutData, pOutDataLen);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_UnwrapKey(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hUnwrappingKey,
		CK_BYTE_PTR pWrappedKey,
		CK_SIZE wrappedKeyLen,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_COUNT attributeCount,
		CK_OBJECT_HANDLE_PTR phKey
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_UnwrapKey(hSession, pMechanism, hUnwrappingKey,
			pWrappedKey, wrappedKeyLen, pTemplate, attributeCount, phKey);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_DeriveKey(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hBaseKey,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_COUNT attributeCount,
		CK_OBJECT_HANDLE_PTR phKey
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_DeriveKey(hSession, pMechanism, hBaseKey, pTemplate,
			attributeCount, phKey);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_SeedRandom(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pSeed,
		CK_SIZE seedLen
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_SeedRandom(hSession, pSeed, seedLen);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_GenerateRandom(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pRandomData,
		CK_SIZE randomLen
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_GenerateRandom(hSession, pRandomData, randomLen);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_GetFunctionStatus(
		CK_SESSION_HANDLE hSession
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_GetFunctionStatus(hSession);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_CancelFunction(
		CK_SESSION_HANDLE hSession
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_CancelFunction(hSession);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY C_WaitForSlotEvent(
		CK_FLAGS flags,
		CK_SLOT_ID_PTR pSlotID,
		CK_VOID_PTR pReserved
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->C_WaitForSlotEvent(flags, pSlotID, pReserved);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY CT_ResetToken(
		CK_SESSION_HANDLE hSession,
		CK_CHAR_PTR pPin,
		CK_ULONG ulPinLen,
		CK_CHAR_PTR pLabel
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->CT_ResetToken(hSession, pPin, ulPinLen, pLabel);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY CT_InitToken(
		CK_SESSION_HANDLE hSession,
		CK_SLOT_ID slotId,
		CK_CHAR_PTR pPin,
		CK_ULONG ulPinLen,
		CK_CHAR_PTR pLabel
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->CT_InitToken(hSession, slotId, pPin, ulPinLen, pLabel);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY CT_CopyObject(
		CK_SESSION_HANDLE hSesDest,
		CK_SESSION_HANDLE hSesSrc,
		CK_OBJECT_HANDLE hObject,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_COUNT count,
		CK_OBJECT_HANDLE_PTR phNewObject
)
{
	CK_RV rv;

	C_FUNC_INIT();
	NOREENT_Enter();

	rv = cprovTbl->CT_CopyObject(hSesDest, hSesSrc, hObject, pTemplate, count,
			phNewObject);

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}

DLL_EXPORT CK_RV CK_ENTRY FMSC_SendReceive(
	CK_SESSION_HANDLE hSession,
        CK_USHORT fmNumber,
        CK_BYTE_PTR pRequest,
        CK_ULONG requestLen,
        CK_BYTE_PTR pResponse,
        CK_ULONG responseLen,
        CK_ULONG_PTR pReceivedLen,
        uint32_t *pfmStatus
)
{
    CK_RV rv;
    MD_Buffer_t     request[2], reply[2];
    uint32_t recvLen      = 0;

	C_FUNC_INIT();
	NOREENT_Enter();

    request[0].pData = pRequest;
    request[0].length = requestLen;

    request[1].pData = NULL;
    request[1].length = 0;

    reply[0].pData  = pResponse;
    reply[0].length = responseLen;

    reply[1].pData = NULL;
    reply[1].length = 0;

    rv = MD_SendReceive( 0,
                     0,
                     fmNumber,
                     request,
                     0,
                     reply,
                     &recvLen,
                     pfmStatus);

    *pReceivedLen = recvLen;

	EMULFM_ResetPrivilegeLevel();

	NOREENT_Leave();

	return rv;
}


#undef FN
#define FN "CT_ToHsmSession:"
DLL_EXPORT CK_RV CK_ENTRY CT_ToHsmSession(CK_SESSION_HANDLE hSession,
                    CK_SESSION_HANDLE_PTR phHsmSession)
{
    *phHsmSession = hSession;;

    return CKR_OK;
}


#undef FN
#define FN "CT_GetHSMId:"
DLL_EXPORT CK_RV CK_ENTRY CT_GetHSMId(CK_SESSION_HANDLE hSession,CK_ULONG_PTR hsmid)
{
    CK_RV ret=CKR_OK;

    *hsmid = 0;

    return ret;
}

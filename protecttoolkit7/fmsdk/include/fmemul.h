/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: fmemul.h
 */
#ifndef INC_FMEMUL_H
#define INC_FMEMUL_H
#include <integers.h>
#include <cryptoki.h>
#include <ctfext.h>
#include <md.h>
#include <cprovtbl.h>
#include <appid_t.h>

#define DISPATCH_STATE_SIGNATURE 0x97C162E4uL



/*
 * InitCprovTable() initializes the internal Cprov table used in function
 * patching. It populates the table withthe pointers obtained from the cryptoki
 * dynamic library found in the path.
 *
 * Return Value:
 * - CKR_OK: Function table initialized successfully.
 * - otherwise: An error occured. An appropriate error, describing the nature of
 * the error is returned.
 */
extern CK_RV InitCprovTable(void);

/* Cause functions to be exported if EXPORT_FM_FUNCS is defined
*  (Code outside the FM emulation should not define this)
*/
#ifndef INT_FMAPI
#ifdef _WIN32
# if defined(EXPORT_FM_FUNCS)
#  define INT_FMAPI __declspec(dllexport)
# else
#  define INT_FMAPI
# endif
#else
    #if defined(EXPORT_FM_FUNCS)
      #define INT_FMAPI __attribute__((visibility("default")))
    #else
      #define INT_FMAPI
    #endif
#endif
#endif

typedef struct DispatchState_st {
	uint32_t signature;
	uint8_t *requestBuffer;
	unsigned int requestLength;
	uint8_t *replyBuffer;
	unsigned int replyLength;
	unsigned int userReplyLength;
	AppId_t appId;
	uint32_t applicationStatus;
} DispatchState_t;

extern INT_FMAPI DispatchState_t globalDispState;

/**
 * Free user data associated with a particular session. This function can be
 * called even when there is no associated user data.
 *
 * @param hSession
 *     The session handle.
 */
INT_FMAPI void EMULFM_FreeSessionUserData(CK_SESSION_HANDLE hSession);

/**
 * Free all user data. This function can be called even when there is no
 * associated user data.
 */
INT_FMAPI void EMULFM_FreeAllUserData(void);

/**
 * Associate a session handle to a slot, so that it can be looked up later.
 *
 * @return CK_RV
 *     CKR_OK - Successful
 *     CKR_DEVICE_MEMORY - Not enough memory to complete operation.
 * @param hSession
 *     The session handle to associate with @ref slotId.
 * @param slotId
 *     The slot identifier to associate with @ref hSession.
 */
INT_FMAPI CK_RV EMULFM_AddSessionToSlot(
		CK_SLOT_ID slotId,
		CK_SESSION_HANDLE hSession);

/**
 * Free all session data associated with the specified session handle.
 *
 * @param slotId
 *     The slot identifier of the slot, whose session data is about to be
 *     freed.
 */
INT_FMAPI void EMULFM_FreeSlotSessions(CK_SLOT_ID slotId);

INT_FMAPI MD_RV EMULFM_MD_DispatchRequest(
					 uint32_t hsmIndex,
                     uint32_t originatorId,
                     uint16_t fmNumber,
                     MD_Buffer_t* pReq,
                     uint32_t timeout,
                     MD_Buffer_t* pResp,
                     uint32_t* pReceivedLen,
                     uint32_t* pFmStatus);

INT_FMAPI void EMULFM_ResetPrivilegeLevel(void);

/* Get the FM started
 * Load the SW cryptoki provider and then call Startup()
 * May be called multiple times - will only do something on the first call.
 * RETURN - 0 for OK else FM_UNSUCCESSFUL if the SW cryptoki failed to load
 */
INT_FMAPI MD_RV EMULFM_Startup(void);

/* query whether the MD_Init + C_Init exceeds MD_Final + C_Final
 * RETURN: zero if not connected
 */ 
INT_FMAPI int EMULFM_IsConnected(void);

/* shutdown
 * RETURN: zero if not started
 */ 
INT_FMAPI int EMULFM_Shutdown(void);

/* query whether the FM has been started up 
 * RETURN: zero if not started
 */ 
INT_FMAPI int EMULFM_IsConnected(void);

/* 
 * This function is exported from the emulation FM DLL. It is only
 * intended to be used internally by the emucprov library, which is linked 
 * into the cryptoki provider used for emulation of cryptoki patching.
 *
 * Return Value:
 * Address of the cprov function table.
 */
INT_FMAPI CprovFnTable_t *FM_GetCprovFuncs(void);

/* this function pointer is initialized to APPID_SetAppId in the libctsw */
DLL_EXPORT extern void (*pAPPID_SetAppId)(AppId_t *);

#endif /* INC_FMEMUL_H */

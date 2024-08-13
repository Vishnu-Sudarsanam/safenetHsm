/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: objstate.h
 */
#ifndef INC_OBJSTATE_H
#define INC_OBJSTATE_H
#include <cryptoki.h>
#include <fmhdr.h>
#include <csa8fm.h>

/**
 * This function can be used to associate user data with the calling
 * application. The data is associated with the PID of the calling
 * appplication. The function specified in this call will be called to free the
 * data when the last application using the library finalizes (e.g. when it
 * calls C_Finalize()).
 *
 * If the application already has an associated user data, it will be freed
 * (by calling the current free function) before the new data association is
 * created.
 *
 * @return CK_RV
 *     CKR_OK - The operation was successful.
 *     CKR_ARGUMENTS_BAD - freeUserData was NULL, when userData was not NULL;
 *     or fmNo was not FM_NUMBER_CUSTOM_FM.
 *     CKR_CRYPTOKI_NOT_INITIALIZED - Cryptoki is not initialized yet.
 * @param fmNo
 *     The fm number of the caller. It must be FM_NUMBER_CUSTOM_FM in this
 *     release.
 * @param userData
 *     Address of the memory block that will be associated with the session
 *     handle. If it is NULL, the current associated buffer is freed.
 * @param freeUserData
 *     Address of a function that will be called to free the userData, if the
 *     library decides that it should be freed. It must be non-NULL if userData
 *     is not NULL.
 */
CK_RV FM_SetAppUserData(
		FmNumber_t fmNo,
		CK_VOID_PTR userData,
		CK_VOID (*freeUserData)(CK_VOID_PTR)
		);

/**
 * This function is used to obtain the userData associated with the current
 * application. If there are no associated buffers, NULL is returned in
 * ppUserData.
 *
 * @return CK_RV
 *     CKR_OK - Operation was successful. The associated user data is placed in
 *     the variable specified by ppUserData.
 *     CKR_ARGUMENTS_BAD - ppUserData was NULL;or fmNo was not
 *     FM_NUMBER_CUSTOM_FM.
 *     CKR_CRYPTOKI_NOT_INITIALIZED - Cryptoki is not initialized yet.
 *
 * @param fmNo
 *     The fm number of the caller. It must be FM_NUMBER_CUSTOM_FM in this
 *     release.
 * @param ppUserData
 *     Address of a variable (of type CK_VOID_PTR) which will contain the
 *     address of the user data if this function returns CKR_OK. It must be
 *     non-NULL.
 */
CK_RV FM_GetAppUserData(
		FmNumber_t fmNo,
		CK_VOID_PTR_PTR ppUserData
		);

/**
 * This function can be used to associate user data with a slot.
 * The data is associated with the slot identified by slotId. The
 * function specified in this call will be called to free the data when the
 * last application using the library finalizes.
 *
 * If the slot already has an associated user data, it will be freed
 * (by calling the current free function) before the new data association is
 * created.
 *
 * @return CK_RV
 *     CKR_OK - The operation was successful.
 *     CKR_ARGUMENTS_BAD - freeUserData was NULL, when userData was not NULL;or
 *     fmNo was not FM_NUMBER_CUSTOM_FM.
 *     CKR_SLOT_ID_INVALID - the specified slot ID is invalid.
 *     CKR_CRYPTOKI_NOT_INITIALIZED - Cryptoki is not initialized yet.
 *
 * @param fmNo
 *     The fm number of the caller. It must be FM_NUMBER_CUSTOM_FM in this
 *     release.
 * @param slotId
 *     The slot ID of the slot.
 * @param userData
 *     Address of the memory block that will be associated with the session
 *     handle. If it is NULL, the current associated buffer is freed.
 * @param freeUserData
 *     Address of a function that will be called to free the userData, if the
 *     library decides that it should be freed. It must be non-NULL if userData
 *     is not NULL.
 */
CK_RV FM_SetSlotUserData(
		FmNumber_t fmNo,
		CK_SLOT_ID slotId,
		CK_VOID_PTR userData,
		CK_VOID (*freeUserData)(CK_VOID_PTR)
		);

/**
 * This function is used to obtain the userData associated with the specified
 * slot. If there are no associated buffers, NULL is returned in ppUserData.
 *
 * @return CK_RV
 *     CKR_OK - Operation was successful. The associated user data is placed in
 *     the variable specified by ppUserData.
 *     CKR_ARGUMENTS_BAD - ppUserData was NULL; or fmNo was not
 *     FM_NUMBER_CUSTOM_FM.
 *     CKR_SLOT_ID_INVALID - the specified slot ID is invalid.
 *     CKR_CRYPTOKI_NOT_INITIALIZED - Cryptoki is not initialized yet.
 *
 * @param fmNo
 *     The fm number of the caller. It must be FM_NUMBER_CUSTOM_FM in this
 *     release.
 * @param slotId
 *     The slot ID indicating the sot to be used.
 * @param ppUserData
 *     Address of a variable (of type CK_VOID_PTR) which will contain the
 *     address of the user data if this function returns CKR_OK. It must be
 *     non-NULL.
 */
CK_RV FM_GetSlotUserData(
		FmNumber_t fmNo,
		CK_SLOT_ID slotId,
		CK_VOID_PTR_PTR ppUserData
		);

/**
 * This function can be used to associate user data with a token.
 * The data is associated with the token in slotId by the library. The
 * function specified in this call will be called to free the data when the
 * last application using the library finalizes, or when the token is removed
 * from the slot.
 *
 * If the token already has an associated user data, it will be freed
 * (by calling the current free function) before the new data association is
 * created.
 *
 * @return CK_RV
 *     CKR_OK - The operation was successful.
 *     CKR_ARGUMENTS_BAD - freeUserData was NULL; or fmNo was not
 *     FM_NUMBER_CUSTOM_FM.
 *     CKR_SLOT_ID_INVALID - the specified slot ID is invalid.
 *     CKR_TOKEN_NOT_PRESENT - the specified slot does not contain a token.
 *     CKR_CRYPTOKI_NOT_INITIALIZED - Cryptoki is not initialized yet.
 *
 * @param fmNo
 *     The fm number of the caller. It must be FM_NUMBER_CUSTOM_FM in this
 *     release.
 * @param slotId
 *     The slot ID of the slot containing the token.
 * @param userData
 *     Address of the memory block that will be associated with the session
 *     handle. If it is NULL, the current associated buffer is freed.
 * @param freeUserData
 *     Address of a function that will be called to free the userData, if the
 *     library decides that it should be freed. It must be non-NULL if userData
 *     is not NULL.
 */
CK_RV FM_SetTokenUserData(
		FmNumber_t fmNo,
		CK_SLOT_ID slotId,
		CK_VOID_PTR userData,
		CK_VOID (*freeUserData)(CK_VOID_PTR)
		);

/**
 * This function is used to obtain the userData associated with the specified
 * token. If there are no associated buffers, or if the token is not present,
 * NULL is returned in ppUserData.
 *
 * @return CK_RV
 *     CKR_OK - Operation was successful. The associated user data is placed in
 *     the variable specified by ppUserData.
 *     CKR_ARGUMENTS_BAD - ppUserData was NULL; or fmNo was not
 *     FM_NUMBER_CUSTOM_FM.
 *     CKR_SLOT_ID_INVALID - the specified slot ID is invalid.
 *     CKR_CRYPTOKI_NOT_INITIALIZED - Cryptoki is not initialized yet.
 *
 * @param fmNo
 *     The fm number of the caller. It must be FM_NUMBER_CUSTOM_FM in this
 *     release.
 * @param slotId
 *     A slot Id indicating the slot containing the token.
 * @param ppUserData
 *     Address of a variable (of type CK_VOID_PTR) which will contain the
 *     address of the user data if this function returns CKR_OK. It must be
 *     non-NULL.
 */
CK_RV FM_GetTokenUserData(
		FmNumber_t fmNo,
		CK_SLOT_ID slotId,
		CK_VOID_PTR_PTR ppUserData
		);

/**
 * This function can be used to associate user data with a token in the
 * context of the calling application.
 * The data is associated with the (token,PID) pair. The function specified in
 * this call will be called to free the data when the application using the
 * library finalizes, or when the token is removed from the slot.
 *
 * If the token already has an associated user data, it will be freed
 * (by calling the current free function) before the new data association is
 * created.
 *
 * @return CK_RV
 *     CKR_OK - The operation was successful.
 *     CKR_ARGUMENTS_BAD - freeUserData was NULL; or fmNo was not
 *     FM_NUMBER_CUSTOM_FM.
 *     CKR_SLOT_ID_INVALID - the specified slot ID is invalid.
 *     CKR_TOKEN_NOT_PRESENT - the specified slot does not contain a token.
 *     CKR_CRYPTOKI_NOT_INITIALIZED - Cryptoki is not initialized yet.
 *
 * @param fmNo
 *     The fm number of the caller. It must be FM_NUMBER_CUSTOM_FM in this
 *     release.
 * @param slotId
 *     The slot ID of the slot containing the token.
 * @param userData
 *     Address of the memory block that will be associated with the session
 *     handle. If it is NULL, the current associated buffer is freed.
 * @param freeUserData
 *     Address of a function that will be called to free the userData, if the
 *     library decides that it should be freed. It must be non-NULL if userData
 *     is not NULL.
 */
CK_RV FM_SetTokenAppUserData(
		FmNumber_t fmNo,
		CK_SLOT_ID slotId,
		CK_VOID_PTR userData,
		CK_VOID (*freeUserData)(CK_VOID_PTR)
		);

/**
 * This function is used to obtain the userData associated with the specified
 * token in the application context. If there are no associated buffers, or if
 * the token is not present, NULL is returned in ppUserData.
 *
 * @return CK_RV
 *     CKR_OK - Operation was successful. The associated user data is placed in
 *     the variable specified by ppUserData.
 *     CKR_ARGUMENTS_BAD - ppUserData was NULL; or fmNo was not
 *     FM_NUMBER_CUSTOM_FM.
 *     CKR_SLOT_ID_INVALID - the specified slot ID is invalid.
 *     CKR_CRYPTOKI_NOT_INITIALIZED - Cryptoki is not initialized yet.
 *
 * @param fmNo
 *     The fm number of the caller. It must be FM_NUMBER_CUSTOM_FM in this
 *     release.
 * @param slotId
 *     A slot Id indicating the slot containing the token.
 * @param ppUserData
 *     Address of a variable (of type CK_VOID_PTR) which will contain the
 *     address of the user data if this function returns CKR_OK. It must be
 *     non-NULL.
 */
CK_RV FM_GetTokenAppUserData(
		FmNumber_t fmNo,
		CK_SLOT_ID slotId,
		CK_VOID_PTR_PTR ppUserData
		);

/**
 * This function can be used to associate user data with a session handle.
 * The data is associated with the (PID, hSession) pair by the library. The
 * function specified in this call will be called to free the user data if the
 * session is closed (via a C_CloseSesion() or a C_CloseAllSessions() call), or
 * the application owning the session finalizes.
 *
 * If the session handle already contains another user data, it will be freed
 * (by calling the current free function) before the new data association is
 * created.
 *
 * @return CK_RV
 *     CKR_OK - The operation was successful.
 *     CKR_ARGUMENTS_BAD - freeUserData was NULL; or fmNo was not
 *     FM_NUMBER_CUSTOM_FM.
 *     CKR_SESSION_HANDLE_INVALID - the specified session handle is invalid.
 *     CKR_CRYPTOKI_NOT_INITIALIZED - Cryptoki is not initialized yet.
 *
 * @param fmNo
 *     The fm number of the caller. It must be FM_NUMBER_CUSTOM_FM in this
 *     release.
 * @param hSession
 *     A session handle, which was obtained from an C_OpenSesion() call. The
 *     validity of this parameter is checked.
 * @param userData
 *     Address of the memory block that will be associated with the session
 *     handle. If it is NULL, the current associated buffer is freed.
 * @param freeUserData
 *     Address of a function that will be called to free the userData, if the
 *     library decides that it should be freed. It must be non-NULL if userData
 *     is not NULL.
 */
CK_RV FM_SetSessionUserData(
		FmNumber_t fmNo,
		CK_SESSION_HANDLE hSession,
		CK_VOID_PTR userData,
		CK_VOID (*freeUserData)(CK_VOID_PTR)
		);

/**
 * This function is used to obtain the userData associated with the specified
 * session handle. If there are no associated buffers, NULL is returned in
 * ppUserData.
 *
 * @return CK_RV
 *     CKR_OK - Operation was successful. The associated user data is placed in
 *     the variable specified by ppUserData.
 *     CKR_ARGUMENTS_BAD - ppUserData was NULL; or fmNo was not
 *     FM_NUMBER_CUSTOM_FM.
 *     CKR_SESSION_HANDLE_INVALID - hSession is not a valid session handle.
 *     CKR_CRYPTOKI_NOT_INITIALIZED - Cryptoki is not initialized yet.
 *
 * @param hSession
 *     A session handle, which was obtained from an C_OpenSesion() call. The
 *     validity of this parameter is checked.
 * @param ppUserData
 *     Address of a variable (of type CK_VOID_PTR) which will contain the
 *     address of the user data if this function returns CKR_OK. It must be
 *     non-NULL.
 */
CK_RV FM_GetSessionUserData(
		FmNumber_t fmNo,
		CK_SESSION_HANDLE hSession,
		CK_VOID_PTR_PTR ppUserData
		);


#endif /* INC_OBJSTATE_H */

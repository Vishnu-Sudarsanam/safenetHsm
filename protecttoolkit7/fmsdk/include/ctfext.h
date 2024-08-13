/*
 *  This file is provided as part of the SafeNet Protect Toolkit SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: ctfext.h
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <cryptoki.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CT_ENTRY(Ret, Func, Params)      \
    DLL_EXPORT Ret CK_ENTRY Func Params; \
    typedef CK_DECLARE_FUNCTION_POINTER(Ret, CK_##Func) Params;

/*  This function is an ERACOM extension to the PKCS#11.

	This function allows adapter administrator to initialize a token.

	Return Value:
	CKR_OK: Operation successful.
	CKR_ARGUMENTS_BAD: pLabel is NULL, or pPin is NULL, although pinLen is nonzero.
	CKR_SESSION_HANDLE_INVALID: hSession is invalid.
	CKR_USER_NOT_LOGGED_IN: user is not logged in to the admin token.
	CKR_NOT_ADMIN_TOKEN: hSession is opened to the administration token.
	CKR_TOKEN_NOT_PRESENT: The hSession does not have a token (this is an
	internal consistency error).
	CKR_SLOT_ID_INVALID: The slot ID is not a valid token on the system, or it
	is already initialized.
*/
CT_ENTRY(CK_RV, CT_InitToken, (
		CK_SESSION_HANDLE hSession,
		CK_SLOT_ID slotId,
		CK_CHAR_PTR pPin,
		CK_ULONG ulPinLen,
		CK_CHAR_PTR pLabel
	)
)

CT_ENTRY(CK_RV, CT_InitPIN, (
	CK_SESSION_HANDLE hSession,
	CK_USER_TYPE userType,
	CK_CHAR_PTR pPin,
	CK_SIZE pinLen
	)
)

/*  This function is an ERACOM extension to PKCS #11.

	It will erase (reset) the token which the token is connected to. The session
	must be in RW SO mode for this function to succeed.

	Return Values:
	CKR_OK: Operation successful.
	CKR_ARGUMENTS_BAD: pLabel is NULL, or pPin is NULL, although pinLen is nonzero.
	CKR_SESSION_HANDLE_INVALID: hSession is invalid.
	CKR_USER_NOT_LOGGED_IN: The SO is not logged in to the session.
	CKR_TOKEN_NOT_PRESENT: The token is not in the slot.
	CKR_SESSION_EXISTS: Other sessions are active to the same token.
*/
CT_ENTRY(CK_RV, CT_ResetToken, (
		CK_SESSION_HANDLE hSession,
		CK_CHAR_PTR pPin,
		CK_ULONG ulPinLen,
		CK_CHAR_PTR pLabel
	)
)

/*  This function is an ERACOM extension to PKCS #11.

	It will copy an object from a token to another token.

	Return Values:
	CKR_OK: Object copied successfully.
	CKR_SESSION_HANDLE_INVALID: Either source or destination session handle is
	invalid.
	CKR_OBJECT_HANDLE_INVALID: The source object handle is invalid.
	CKR_TOKEN_NOT_PRESENT: Either the source token, or the destination token
	does not exist.
	CKR_ARGUMENTS_BAD: phNewObject is NULL, or the attribute template is invalid.
	CKR_HOST_MEMORY: Not enough memory on the host system to carry out request.
	CKR_DEVICE_MEMORY: Not enough memory on the device to complete request.
*/
CT_ENTRY(CK_RV, CT_CopyObject, (
		CK_SESSION_HANDLE hSesDest,
		CK_SESSION_HANDLE hSesSrc,
		CK_OBJECT_HANDLE hObject,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_COUNT ulCount,
		CK_OBJECT_HANDLE_PTR phNewObject
	)
)

/*  This function is an ERACOM extension to PKCS #11.

	It returns the real HSM id for the specified user Slot ID.

    Return Values:
	CKR_OK: Successfully mapped the slotID to a physical HSM.
    CKR_ARGUMENTS_BAD: The supplied pHsmID is NULL.
    CKR_SLOT_ID_INVALID: The supplied slotID does not exist.
    CKR_FUNCTION_NOT_SUPPORTED: The library is in WLD mode, and this
                                functionality is not supported.
*/
CT_ENTRY(CK_RV, CT_HsmIdFromSlotId, (
    CK_SLOT_ID slotID,
    unsigned int *pHsmID
	)
)

/*  This function is an ERACOM extension to PKCS #11.

	It return the HSM session handle for the specified user Session Handle.

    Return Values:
	CKR_OK: Successfully mapped the user Session Handle to a HSM Session Handle.
    CKR_ARGUMENTS_BAD: The supplied pHsmID is NULL.
    CKR_FUNCTION_NOT_SUPPORTED: The library is in WLD mode, and this
                                functionality is not supported.
*/
CT_ENTRY(CK_RV, CT_ToHsmSession, (
                    CK_SESSION_HANDLE hSession,
                    CK_SESSION_HANDLE_PTR phHsmSession
	)
)

/*  This function is an ERACOM extension to PKCS #11.

	It return the HSM session handle for the specified user Session Handle.

    Return Values:
	CKR_OK: Successfully mapped the user Session Handle to a HSM Session Handle.
    CKR_ARGUMENTS_BAD: The supplied pHsmID is NULL.
    CKR_FUNCTION_NOT_SUPPORTED: The library is in WLD mode, and this
                                functionality is not supported.
*/
CT_ENTRY(CK_RV, CT_SetHsmDead, (
                    CK_ULONG hsmIDx, 
                    CK_BBOOL bDisable
	)
)

/*  This function is an SafeNet extension to PKCS #11.
	It return the HSM session handle for the specified user Session Handle.
*/
CT_ENTRY(CK_RV, CT_GetHSMId, (
					CK_SESSION_HANDLE hSession,
					CK_ULONG_PTR hsmid
	)
)

/*  This function is an ERACOM extension to PKCS #11 to support custom FMs.

*/
CT_ENTRY(CK_RV, FMSC_SendReceive, (
	CK_SESSION_HANDLE hSession, 
	CK_USHORT fmNumber,
	CK_BYTE_PTR pRequest, 
	CK_ULONG requestLen,
	CK_BYTE_PTR pResponse,
	CK_ULONG responseLen,
	CK_ULONG_PTR pReceivedLen, 
	unsigned int *pfmStatus
	)
)

/*  This function is an ERACOM extension to PKCS #11 to implement OTP feature.
*/
CT_ENTRY(CK_RV, CT_InitOtpSeed, (
    CK_SESSION_HANDLE hSession,
	CK_BYTE_PTR passcode,
	CK_ULONG passcodeLen,
	CK_BYTE_PTR psalt,
	CK_ULONG saltLen,
	CK_ULONG iterations,
	CK_ULONG keyLen,
	CK_BYTE_PTR pSeed,
	CK_ULONG seedLen,
	CK_BYTE_PTR hmac,
	CK_ULONG hmacLen,
	CK_BYTE_PTR ghmac,
	CK_ULONG ghmacLen,
	CK_CHAR_PTR puserPin,
	CK_SIZE userpinLen,
	CK_CHAR_PTR pSoPin,
	CK_SIZE sopinLen,
	CK_USER_TYPE userType
	)
)

CT_ENTRY(CK_RV, CT_DelOtpSeed, (
    CK_SESSION_HANDLE hSession,
	CK_USER_TYPE userType
	)
)

CT_ENTRY(CK_RV, CT_GetSMC, (
    unsigned int      hsmId,
    CK_SESSION_HANDLE hSession,
    uint32_t          version,
    uint8_t *input, size_t inlen,
    uint8_t *output, size_t *outlen
    )
)

CT_ENTRY(CK_RV, CT_FetchCertificate, (
    unsigned int      hsmId,
    CK_ATTRIBUTE_TYPE   cert_type,
    CK_CHAR_PTR output, CK_ULONG_PTR outlen
    )
)

#ifdef __cplusplus
}
#endif

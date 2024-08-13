
/*
 *  This file is provided as part of the SafeNet Protect Toolkit SDK.
 *
 *  (c) Copyright 2009-2016 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: fmsc.h
 */

#ifndef FMSC_H_INCLUDED
#define FMSC_H_INCLUDED

#include <stdint.h>

#include <cryptoki.h>

#ifdef __cplusplus
    extern "C" {        /* define as 'C' functions to prevent mangling */
#endif /* #ifdef __cplusplus */



/*																																		
 * Desc: Send and Receive custom FM request/response to the HSM identified by the specified session handle. It takes					
 * the following parameters:
 *
 * @param hSession			session handle.
 * @param fmNumber			FM ID to which request is sent.
 * @param *pRequest			pointer to the request buffer.
 * @param pRequestLen			Length of pRequest.
 * @param *pResponse			pointer to the response buffer.
 * @param responseLen			length of the initialized pResponse buffer.
 * @param *pReceiveLen			Actual data received.
 * @param *fmStatus			FM return code.
 *
 * NOTE:
 *		pRequest		Pointer to the request buffer. The request buffer should be formatted as FM_NUMBER|REQUEST_DATA	where
						FM_NUMBER Identifies whether the request is intended for a Functionality Module(FM) or not. This value 
						must be set to FM_NUMBER_CUSTOM_FM (#include csa8fm.h).
							
 *		pResponse		The response from the FM is stored in these buffers. The memory for 'pResponse' buffer must be allocated in 
						the context of the application	to accomodate anticipated response packets. Buffer overflow condition is 
						determined by the 'pReceivedLen'. The value of this parameter can be NULL if the FM will not return a response.
 *
 *		pReceivedLen	Address of a variable to hold the total number of bytes placed in the response buffers by the FM. The memory
 *						of this variable must be allocated in the context of the application which calls the function. The value could
 *						NULL if the FM function will not return a response.
 *
 *
 */
DLL_EXPORT CK_RV FMSC_SendReceive(
					CK_SESSION_HANDLE hSession, 
					CK_USHORT fmNumber,
					CK_BYTE_PTR pRequest, 
					CK_ULONG requestLen,
					CK_BYTE_PTR pResponse,
					CK_ULONG responseLen,
					CK_ULONG_PTR pReceivedLen, 
					uint32_t *pfmStatus);


#ifdef __cplusplus
}
#endif /* #ifdef __cplusplus */

#endif
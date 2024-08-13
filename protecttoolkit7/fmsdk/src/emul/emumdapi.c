/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: emumdapi.c
 */
#include <stdlib.h>
#include <md.h>
#include <fmemul.h>

/**
 * Initialize the message dispatch library. Until this function is called, all
 * other functions will return @c MDR_NOT_INITIALIZED.
 */
MD_RV MD_Initialize(void)
{
	MD_RV fmRv;

	/* ensure the FM is started up - (may safely be called more than once) */
	fmRv = EMULFM_Startup();

	if ( fmRv )
		return fmRv;

	return MDR_OK;
}

/**
 * Finalize the message dispatch library. After this function returns, only the
 * MD_Initialize() function can be called. All other functions will return
 * @c MDR_NOT_INITIALIZED error code.
 */
void MD_Finalize(void)
{
	EMULFM_Shutdown();
}

/**
 * Retrieve the number of visible HSMs.
 *
 * @param pHsmCount
 *  Address of a variable to hold the result.
 */
MD_RV MD_GetHsmCount(uint32_t* pHsmCount)
{
	if ( !EMULFM_IsConnected() )
		return MDR_NOT_INITIALIZED;

	*pHsmCount = 1;
	return MDR_OK;
}

/**
 * Retrieve the state of the specified HSM.
 *
 * @param hsmIndex
 *  Zero based index of the HSM to query.
 *
 * @param pState
 *  Address of a variable to hold the result. This parameter must not be @c
 *  NULL.
 *
 * @param pErrorCode
 *  If the HSM is halted, this represents what caused the halt. This parameter
 *  may be @c NULL.
 */
MD_RV MD_GetHsmState(uint32_t hsmIndex,
                     HsmState_t* pState,/* this should change */
                     uint32_t* pErrorCode)
{
	hsmIndex = hsmIndex;

	if ( !EMULFM_IsConnected() )
		return MDR_NOT_INITIALIZED;

	*pState = S_NORMAL_OPERATION;
	*pErrorCode = 0;
	return MDR_OK;
}

/**
 * Reset the specified HSM.
 *
 * @param hsmIndex
 *  Zero based index of the HSM to reset.
 */
MD_RV MD_ResetHsm(uint32_t hsmIndex)
{
	hsmIndex = hsmIndex;

	if ( !EMULFM_IsConnected() )
		return MDR_NOT_INITIALIZED;

	return MDR_OPERATION_NOT_ALLOWED;
}

/**
 * Send a request and receive the response.
 *
 * @param hsmIndex
 *  Zero based index of the HSM to sned the request to.
 *
 * @param originatorId
 *  Id of the request originator. This Id is typically 0, only if the
 *  calling application is acting as a proxy would this be non-zero.
 *
 * @param fmNumber
 *  Identifier of the Functionality Module to send the request to.
 *
 * @param pReq
 *  Array of buffers to send. The final element in the array 
 *  must be {NULL, 0}.
 *
 * @param reserved
 *  Reserved for future use. Currently must be set to zero.
 *
 * @param pResp
 *  Array of buffers allocated to receive the response. The
 *  final element in the array must be {NULL, 0}.<br>
 *
 * @param pReceivedLen
 *  Address of variable to hold total number of bytes placed in the
 *  response buffers specified during the related MD_Send call. The
 *  buffers are filled in order until either the entire response is
 *  copied or the buffers overflow. The value of this parameter may be
 *  @c NULL.
 *
 * @param pFmStatus
 *  Address of variable to hold the status/return code from the
 *  Functionality Module which processed the request. The meaning of
 *  the value is defined by the FM. The value of this parameter may be
 *  @c NULL.
 */
MD_RV MD_SendReceive(uint32_t hsmIndex,
                     uint32_t originatorId,
                     uint16_t fmNumber,
                     MD_Buffer_t* pReq,
                     uint32_t reserved,
                     MD_Buffer_t* pResp,
                     uint32_t* pReceivedLen,
                     uint32_t* pFmStatus)
{
	if ( !EMULFM_IsConnected() )
		return MDR_NOT_INITIALIZED;

	return EMULFM_MD_DispatchRequest(hsmIndex, originatorId, fmNumber,
						pReq, reserved, pResp, 
						pReceivedLen,	pFmStatus);
}

/**
 * Obtain the value of a system parameter. For a definition of parameters, and
 * the buffer types required for these parameters, see MD_Parameter_t
 * documentation.
 *
 * If the buffer length is not correct, MDR_INVALID_PARAMETER is returned.
 *
 * @param parameter
 *   The parameter whose value is being queried.
 *
 * @param pValue
 *   The address of the buffer to hold the parameter value. The buffer must
 *   have been allocated by the caller. The size of the buffer is determined by
 *   the parameter that is being obtained.
 *
 * @param valueLen
 *   The length of the buffer pValue, in number of bytes.
 */
MD_RV MD_GetParameter(MD_Parameter_t parameter,
                      void *pValue,
                      unsigned int valueLen)
{
	switch(parameter)
	{
	case MDP_MAX_BUFFER_LENGTH:
		if ( pValue && valueLen >= sizeof(uint32_t) )
			*(uint32_t*)pValue = 4*1024;		/* assume 4Kbytes */
		else
			return MDR_INVALID_PARAMETER;
		break;
	default:
		return MDR_INVALID_PARAMETER;
	}
	return MDR_OK;
}





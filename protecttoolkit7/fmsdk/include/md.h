/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 1997-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: md.h
 */
#ifndef INC_MD_H
#define INC_MD_H
#include <stdint.h>
#include <stddef.h>

#include <hsmstate.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DLL_EXPORT
#if defined(_MSC_VER)
#define DLL_EXPORT __declspec( dllexport )
#else
#define DLL_EXPORT __attribute__((visibility("default")))
#endif
#endif

/**
 * Set of possible MD_ function return codes.
 */
typedef enum
{
    /** Operation was completed successfully. */
    MDR_OK                          = 0,

    /** MD_Initialize() function was not called. */
    MDR_NOT_INITIALIZED             = 1,

    /** At least one of the parameter values is invalid. */
    MDR_INVALID_PARAMETER           = 3,

    /** The specified HSM index is greater than or equal to the total HSM
     * count. */
    MDR_INVALID_HSM_INDEX           = 4,

    /** The system or the HSM does not have enough resources to complete
     * operation. */
    MDR_INSUFFICIENT_RESOURCES      = 6,

    /** The operation was cancelled. This return value is currently unused. */
    MDR_OPERATION_CANCELLED         = 8,

    /** The HSM was restarted while the operation was in progress. */
    MDR_HSM_RESET                   = 9,

    /** The specified FM number is not available on the specified HSM. */
    MDR_FM_NOT_AVAILABLE            = 10,

    /** The operation could not be carried out, and the reason is unknown. */
    MDR_UNSUCCESSFUL                = 11,

    /** There is an internal error in the library. This error should never be
     * encountered. */
    MDR_INTERNAL_ERROR              = 12,

    /** The operation was not allowed to be carried out. */
    MDR_OPERATION_NOT_ALLOWED       = 13,

    /* Remote HSM communication error */
    MDR_TCP_LINK_ERROR            = 14,

    /* HSM not operational */
    MDR_HSM_FAILED            = 15
} MD_RV;

/**
 * MD library parameters used for MD_GetParameter() and MD_SetParameter()
 * function calls.
 */
typedef enum {
    /**
     * The recommended maximum buffer size, in number of bytes, for messages
     * that can be sent using the MD library. This value is informational only.
     * Whilst messages larger than this buffer size may be accepted by the
     * library, it is not recommended to do so.
     *
     * Different types of HSM access providers have different values for this
     * parameter. The value 0 means that there is no limit to the amount of
     * data that can be sent using this library.
     *
     * The value type is a uint32_t (4-byte integer value).
     *
     * This parameter is read only.
     */
    MDP_MAX_BUFFER_LENGTH = 1
} MD_Parameter_t;

typedef struct
{
    uint8_t* pData;
    uint32_t length;
} MD_Buffer_t;

typedef struct hsmInfoRet_t
{
	char ipAddr[INET_NAME_ADDRSTRLEN];
	unsigned int port;
	uint32_t errorCode;
	HsmState_t status;
	unsigned int hsmIndex;
}hsmInfoRet_t;

typedef struct hsmInfo_t {
	hsmInfoRet_t retInfo;
	MD_RV md_rv;
	unsigned int serverIndex;
	unsigned int serverHsmIndex;
	int sock;
	int sockState;
	unsigned char sockAddr[100];//should be enough for "struct sockaddr" & IPv6 structs
	unsigned int sockAddrLen;
} hsmInfo_t;

/**
 * Initialize the message dispatch library. Until this function is called, all
 * other functions will return @c MDR_NOT_INITIALIZED.
 */
DLL_EXPORT MD_RV MD_Initialize(void /* Mutex? */);

/**
 * Finalize the message dispatch library. After this function returns, only the
 * MD_Initialize() function can be called. All other functions will return
 * @c MDR_NOT_INITIALIZED error code.
 */
DLL_EXPORT void MD_Finalize(void);

/**
 * Retrieve the number of visible HSMs.
 *
 * @param pHsmCount
 *  Address of a variable to hold the result.
 */
DLL_EXPORT MD_RV MD_GetHsmCount(uint32_t* pHsmCount);

/**
 * Retrieve the number and info of visible HSMs.
 * Tries to recover HSMs
 */
DLL_EXPORT MD_RV MD_QueryHsms( hsmInfoRet_t *failedHsm, int *failedCount);

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
DLL_EXPORT MD_RV MD_GetHsmState(uint32_t hsmIndex,
                     HsmState_t* pState,/* this should change */
                     uint32_t* pErrorCode);

/**
 * Reset the specified HSM.
 *
 * @param hsmIndex
 *  Zero based index of the HSM to reset.
 */
DLL_EXPORT MD_RV MD_ResetHsm(uint32_t hsmIndex);

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
DLL_EXPORT MD_RV MD_SendReceive(uint32_t hsmIndex,
                     uint32_t originatorId,
                     uint16_t fmNumber,
                     MD_Buffer_t* pReq,
                     uint32_t reserved,
                     MD_Buffer_t* pResp,
                     uint32_t* pReceivedLen,
                     uint32_t* pFmStatus);

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
DLL_EXPORT MD_RV MD_GetParameter(MD_Parameter_t parameter,
                      void *pValue,
                      uint32_t valueLen);


/**
 * Read/write from/to adapter memory-mapped I/O regions. Two regions
 * are defined: dualport (shared memory) and Command And Status registers
 * (CSR).
 *
 *
 * @param hsmIndex
 *  Zero based index of the HSM to reset.
 *
 * @param offset
 *   Offset within I/O region.
 *
 * @param from or to
 *   User source or destination buffer.
 *
 * @param length
 *   Length of data to read or write to/from the user buffer.
 */
DLL_EXPORT MD_RV MD_WriteDualport(uint32_t hsmIndex,
                  uint32_t offset,
                  void* from,
                  uint32_t length);

DLL_EXPORT MD_RV MD_ReadDualport(uint32_t hsmIndex,
                  uint32_t offset,
                  void* to,
                  uint32_t length);


DLL_EXPORT MD_RV MD_WriteCSR(uint32_t hsmIndex,
                  uint32_t offset,
                  void* from,
                  uint32_t length);

DLL_EXPORT MD_RV MD_ReadCSR(uint32_t hsmIndex,
                  uint32_t offset,
                  void* to,
                  uint32_t length);

#ifdef __cplusplus
}
#endif

#endif

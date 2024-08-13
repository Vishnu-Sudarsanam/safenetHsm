/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: fmerr.h
 */
#ifndef INC_FMERR_H
#define INC_FMERR_H

/*
 * This enumeration defines all possible errors from the FM components. Some of
 * these errors can only be returned by particular FM subsystems, like the FM
 * dispatcher, or the FM startup.
 */
typedef enum FM_RV_e
{
    FM_OK                               = 0x00000000uL,
    FM_ALREADY_INITIALIZED              = 0x00000001uL,
    FM_ARGUMENTS_BAD                    = 0x00000002uL,
    FM_CANT_LOCK                        = 0x00000003uL,
    FM_HOST_MEMORY                      = 0x00000004uL,
    FM_INVALID_ADAPTER_NUMBER           = 0x00000005uL,
    FM_MUTEX_BAD                        = 0x00000006uL,
    FM_MUTEX_NOT_LOCKED                 = 0x00000007uL,

    /* HIFACE module error messages */
    FM_ERR_DMA_FAILED                   = 0x00000008uL,
    FM_ERR_OUT_OF_MEMORY                = 0x00000009uL,
    FM_ERR_INVALID_DESTINATION_MODULE   = 0x0000000AuL,
    FM_WRN_REPLY_TOO_LONG               = 0x0000000BuL,
    FM_ERR_INVALID_REQUEST              = 0x0000000CuL,
    FM_ERR_INVALID_LENGTH               = 0x0000000DuL,
    FM_ERR_INVALID_CMD                  = 0x0000000EuL,

    /* Internal message dispatch error messages */
    FM_IERR_INVALID_CONNECTION_HANDLE   = 0x0000000FuL,
    FM_IERR_PENDING_DESTROY             = 0x00000010uL,
    FM_IERR_CONNECTION_BUSY             = 0x00000011uL,
    FM_IERR_PENDING_REQUEST             = 0x00000012uL,
    FM_IERR_NO_PENDING_REQUEST          = 0x00000013uL,
    FM_IERR_REPLY_NOT_AVAILABLE         = 0x00000014uL,
    FM_IERR_OPERATION_CANCELLED         = 0x00000015uL,
    FM_IERR_UNSUCCESSFUL                = 0x00000016uL,
    FM_IERR_INVALID_POINTER             = 0x00000017uL,
    FM_IERR_ADAPTER_RESET               = 0x00000018uL,
    FM_IERR_GENERAL                     = 0x00000019uL,

    /* FM_Startup(): FM version is not compatible with the version required by
     * this FM. */
    FM_INCOMPATIBLE                     = 0x0000001AuL,

    /* FM_Startup(): Not enough resources to initialize FM. */
    FM_INSUFFICIENT_RESOURCES           = 0x0000001BuL,

    /* FM_Startup(): An error occured in the Cprov OS. */
    FM_UNSUCCESSFUL                     = 0x0000001CuL
} FM_RV;


#endif /* INC_FMERR_H */

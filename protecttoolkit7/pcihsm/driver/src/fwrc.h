/****************************************************************************\
*
* Copyright (c) 2013-2017 Safenet.  All rights reserved.
*
*  Filename:      fwCKR.h
*
*  Description:   This file contains the Cryptoki return codes.
*
* This file is protected by laws protecting trade secrets and confidential
* information, as well as copyright laws and international treaties.
* Copyright (C) 1997-2003 Chrysalis-ITS Incorporated and its licensors.
* All rights reserved. 
*
* This file contains confidential and proprietary information of
* Chrysalis-ITS Incorporated and its licensors and may not be
* copied (in any manner), distributed (by any means) or transferred
* without prior written consent from Chrysalis-ITS Incorporated. 
*
\****************************************************************************/
#ifndef __INCLUDE_FWRC_H
#define __INCLUDE_FWRC_H

#ifdef COMPILING_FIRMWARE
#include "fwdefs.h"
#else
#include "Defs.h"
#endif

/****************************************************************************\
*                                                                            *
*           Cryptoki Return Codes                                            *
*                                                                            *
* The following definitions match those of PKCS11 return codes (from both    *
* version 1 and 2).  They should never be changed.                           *
*                                                                            *
\****************************************************************************/

/* Return code types */
#define fwCKR_OK                               0x0000
#define fwCKR_CANCEL                           0x0001
#define fwCKR_HOST_MEMORY                      0x0002
#define fwCKR_SLOT_ID_INVALID                  0x0003
#define fwCKR_FLAGS_INVALID                    0x0004
#define fwCKR_GENERAL_ERROR                    0x0005
#define fwCKR_FUNCTION_FAILED                  0x0006
#define fwCKR_ARGUMENTS_BAD                    0x0007
#define fwCKR_NO_EVENT                         0x0008
#define fwCKR_NEED_TO_CREATE_THREADS           0x0009
#define fwCKR_CANT_LOCK                        0x000A
#define fwCKR_ATTRIBUTE_READ_ONLY              0x0010
#define fwCKR_ATTRIBUTE_SENSITIVE              0x0011
#define fwCKR_ATTRIBUTE_TYPE_INVALID           0x0012
#define fwCKR_ATTRIBUTE_VALUE_INVALID          0x0013
#define fwCKR_DATA_INVALID                     0x0020
#define fwCKR_DATA_LEN_RANGE                   0x0021
#define fwCKR_DEVICE_ERROR                     0x0030
#define fwCKR_DEVICE_MEMORY                    0x0031
#define fwCKR_DEVICE_REMOVED                   0x0032
#define fwCKR_ENCRYPTED_DATA_INVALID           0x0040
#define fwCKR_ENCRYPTED_DATA_LEN_RANGE         0x0041
#define fwCKR_FUNCTION_CANCELED                0x0050
#define fwCKR_FUNCTION_NOT_PARALLEL            0x0051
#define fwCKR_FUNCTION_PARALLEL                0x0052
#define fwCKR_FUNCTION_NOT_SUPPORTED           0x0054
#define fwCKR_KEY_HANDLE_INVALID               0x0060
#define fwCKR_KEY_SENSITIVE                    0x0061
#define fwCKR_KEY_SIZE_RANGE                   0x0062
#define fwCKR_KEY_TYPE_INCONSISTENT            0x0063
#define fwCKR_KEY_NOT_NEEDED                   0x0064
#define fwCKR_KEY_CHANGED                      0x0065
#define fwCKR_KEY_NEEDED                       0x0066
#define fwCKR_KEY_INDIGESTIBLE                 0x0067
#define fwCKR_KEY_FUNCTION_NOT_PERMITTED       0x0068
#define fwCKR_KEY_NOT_WRAPPABLE                0x0069
#define fwCKR_KEY_UNEXTRACTABLE                0x006A
#define fwCKR_MECHANISM_INVALID                0x0070
#define fwCKR_MECHANISM_PARAM_INVALID          0x0071
#define fwCKR_OBJECT_CLASS_INCONSISTENT        0x0080
#define fwCKR_OBJECT_CLASS_INVALID             0x0081
#define fwCKR_OBJECT_HANDLE_INVALID            0x0082
#define fwCKR_OPERATION_ACTIVE                 0x0090
#define fwCKR_OPERATION_NOT_INITIALIZED        0x0091
#define fwCKR_PIN_INCORRECT                    0x00A0
#define fwCKR_PIN_INVALID                      0x00A1
#define fwCKR_PIN_LEN_RANGE                    0x00A2
#define fwCKR_PIN_EXPIRED                      0x00A3
#define fwCKR_PIN_LOCKED                       0x00A4
#define fwCKR_SESSION_CLOSED                   0x00B0
#define fwCKR_SESSION_COUNT                    0x00B1
#define fwCKR_SESSION_EXCLUSIVE_EXISTS         0x00B2
#define fwCKR_SESSION_HANDLE_INVALID           0x00B3
#define fwCKR_SESSION_PARALLEL_NOT_SUPPORTED   0x00B4
#define fwCKR_SESSION_READ_ONLY                0x00B5
#define fwCKR_SESSION_EXISTS                   0x00B6
#define fwCKR_SESSION_READ_ONLY_EXISTS         0x00B7
#define fwCKR_SESSION_READ_WRITE_SO_EXISTS     0x00B8
#define fwCKR_SIGNATURE_INVALID                0x00C0
#define fwCKR_SIGNATURE_LEN_RANGE              0x00C1
#define fwCKR_TEMPLATE_INCOMPLETE              0x00D0
#define fwCKR_TEMPLATE_INCONSISTENT            0x00D1
#define fwCKR_TOKEN_NOT_PRESENT                0x00E0
#define fwCKR_TOKEN_NOT_RECOGNIZED             0x00E1
#define fwCKR_TOKEN_WRITE_PROTECTED            0x00E2
#define fwCKR_UNWRAPPING_KEY_HANDLE_INVALID    0x00F0
#define fwCKR_UNWRAPPING_KEY_SIZE_RANGE        0x00F1
#define fwCKR_UNWRAPPING_KEY_TYPE_INCONSISTENT 0x00F2
#define fwCKR_USER_ALREADY_LOGGED_IN           0x0100
#define fwCKR_USER_NOT_LOGGED_IN               0x0101
#define fwCKR_USER_PIN_NOT_INITIALIZED         0x0102
#define fwCKR_USER_TYPE_INVALID                0x0103
#define fwCKR_USER_ANOTHER_ALREADY_LOGGED_IN   0x0104
#define fwCKR_USER_TOO_MANY_TYPES              0x0105
#define fwCKR_WRAPPED_KEY_INVALID              0x0110
#define fwCKR_WRAPPED_KEY_LEN_RANGE            0x0112
#define fwCKR_WRAPPING_KEY_HANDLE_INVALID      0x0113
#define fwCKR_WRAPPING_KEY_SIZE_RANGE          0x0114
#define fwCKR_WRAPPING_KEY_TYPE_INCONSISTENT   0x0115
#define fwCKR_RANDOM_SEED_NOT_SUPPORTED        0x0120
#define fwCKR_RANDOM_NO_RNG                    0x0121
#define fwCKR_INSERTION_CALLBACK_NOT_SUPPORTED 0x0141
#define fwCKR_BUFFER_TOO_SMALL                 0x0150
#define fwCKR_SAVED_STATE_INVALID              0x0160
#define fwCKR_INFORMATION_SENSITIVE            0x0170
#define fwCKR_STATE_UNSAVEABLE                 0x0180
#define fwCKR_CRYPTOKI_NOT_INITIALIZED         0x0190
#define fwCKR_CRYPTOKI_ALREADY_INITIALIZED     0x0191
#define fwCKR_MUTEX_BAD                        0x01A0
#define fwCKR_MUTEX_NOT_LOCKED                 0x01A1


#define fwCKR_VENDOR_DEFINED                   ((UInt)0x8000)





/****************************************************************************\
*                                                                            *
*           Luna Return Codes                                                *
*                                                                            *
* These return codes encapsulate a "suggested" cryptoki return code that can *
* serve as the translation if they get passed through to the cryptoki layer. *
* This CKR_ code in captured in the upper 16 bits of the LUNA_ value.        *
*                                                                            *
\****************************************************************************/

#define BuildRC(ckr, value) ((SInt32)(((ckr) << 16) + (value)))
#define VendorRC(a) (BuildRC(fwCKR_VENDOR_DEFINED, a))

// NOTE: if you add new result codes, make sure that they either have a good
// encapsulated CKR_ code, or that you update the CodeMapper::ResultToCryptokiCode
// function so that they get properly translated if they're returned through to
// cryptoki.

typedef enum
{
    // fixme: these definitions are thoroughly mixed up.  It is very difficult
    // to add new ones while ensuring that the value assigned is unique.
    // They should be re-ordered in such a way that adding new values is
    // easy (of course, this will break up the grouping by function, making
    // it more difficult to find a return code to serve a given purpose...

    LUNA_RET_OK                                    = BuildRC(fwCKR_OK,              0x0000),
    LUNA_RET_CANCEL                                = BuildRC(fwCKR_CANCEL,          0x0000),
    LUNA_RET_FLAGS_INVALID                         = BuildRC(fwCKR_FLAGS_INVALID,   0x0000),
    
// NOTE: if you add new result codes, make sure that they either have a good
// encapsulated CKR_ code, or that you update the CodeMapper::ResultToCryptokiCode
// function so that they get properly translated if they're returned through to
// cryptoki.

    // Secure Port and PED in general
    LUNA_RET_FORMER_INVALID_ENTRY_TYPE             = BuildRC(fwCKR_DEVICE_ERROR, 0x0130),
    LUNA_RET_SP_TX_ERROR                           = BuildRC(fwCKR_DEVICE_ERROR, 0x0131),
    LUNA_RET_SP_RX_ERROR                           = BuildRC(fwCKR_DEVICE_ERROR, 0x0132),
    LUNA_RET_SP_TIMEOUT                            = BuildRC(fwCKR_DEVICE_ERROR, 0x0134),
    // can be reused LUNA_RET_SP_UNSUPPORTED_PROTOCOL              = BuildRC(fwCKR_DEVICE_ERROR, 0x0135),
    // can be reused LUNA_RET_SP_UNPLUGGED                         = BuildRC(fwCKR_DEVICE_ERROR, 0x0136),

    LUNA_RET_PED_ID_INVALID                        = BuildRC(fwCKR_DEVICE_ERROR, 0x0140),
    LUNA_RET_PED_UNSUPPORTED_PROTOCOL              = BuildRC(fwCKR_DEVICE_ERROR, 0x0141),
    LUNA_RET_PED_UNPLUGGED                         = BuildRC(fwCKR_DEVICE_ERROR, 0x0142),
    LUNA_RET_PED_ERROR                             = BuildRC(fwCKR_DEVICE_ERROR, 0x0144),
    LUNA_RET_PED_UNSUPPORTED_CRYPTO_PROTOCOL       = BuildRC(fwCKR_DEVICE_ERROR, 0x0145),
    LUNA_RET_PED_DEK_INVALID                       = BuildRC(fwCKR_DEVICE_ERROR, 0x0146),

// NOTE: if you add new result codes, make sure that they either have a good
// encapsulated CKR_ code, or that you update the CodeMapper::ResultToCryptokiCode
// function so that they get properly translated if they're returned through to
// cryptoki.

    // Communication Layer related
    LUNA_RET_CL_ALIGNMENT_ERROR                    = BuildRC(fwCKR_DEVICE_ERROR, 0x0200),
    LUNA_RET_CL_QUEUE_LOCATION_ERROR               = BuildRC(fwCKR_DEVICE_ERROR, 0x0201),
    LUNA_RET_CL_QUEUE_OVERLAP_ERROR                = BuildRC(fwCKR_DEVICE_ERROR, 0x0202),
    LUNA_RET_CL_TRANSMISSION_ERROR                 = BuildRC(fwCKR_DEVICE_ERROR, 0x0203),
    LUNA_RET_CL_NO_TRANSMISSION                    = BuildRC(fwCKR_DEVICE_ERROR, 0x0204),
    LUNA_RET_CL_COMMAND_MALFORMED                  = BuildRC(fwCKR_DEVICE_ERROR, 0x0205),
    LUNA_RET_CL_MAILBOXES_NOT_AVAILABLE            = BuildRC(fwCKR_DEVICE_ERROR, 0x0206),
    LUNA_RET_CL_COMMAND_NON_BACKUP                 = BuildRC(fwCKR_DEVICE_ERROR, 0x0207),    

// NOTE: if you add new result codes, make sure that they either have a good
// encapsulated CKR_ code, or that you update the CodeMapper::ResultToCryptokiCode
// function so that they get properly translated if they're returned through to
// cryptoki.

    // Memory Manager related
    LUNA_RET_MM_NOT_ENOUGH_MEMORY                  = BuildRC(fwCKR_DEVICE_MEMORY, 0x0000),
    LUNA_RET_MM_INVALID_HANDLE                     = BuildRC(fwCKR_DEVICE_MEMORY, 0x0001),
    LUNA_RET_MM_USAGE_ALREADY_SET                  = BuildRC(fwCKR_DEVICE_MEMORY, 0x0002),
    LUNA_RET_MM_ACCESS_OUTSIDE_ALLOCATION_RANGE    = BuildRC(fwCKR_DEVICE_MEMORY, 0x0003),
    LUNA_RET_MM_INVALID_USAGE                      = BuildRC(fwCKR_DEVICE_MEMORY, 0x0004),
    LUNA_RET_MM_ITERATOR_PAST_END                  = BuildRC(fwCKR_DEVICE_MEMORY, 0x0005),
    LUNA_RET_MM_FATAL_ERROR                        = BuildRC(fwCKR_DEVICE_MEMORY, 0x0006),
    
// NOTE: if you add new result codes, make sure that they either have a good
// encapsulated CKR_ code, or that you update the CodeMapper::ResultToCryptokiCode
// function so that they get properly translated if they're returned through to
// cryptoki.

    // Object Module related
    LUNA_RET_TEMPLATE_INCOMPLETE                   = BuildRC(fwCKR_TEMPLATE_INCOMPLETE,     0x0000),
    LUNA_RET_TEMPLATE_INCONSISTENT                 = BuildRC(fwCKR_TEMPLATE_INCONSISTENT,   0x0000),
    LUNA_RET_ATTRIBUTE_TYPE_INVALID                = BuildRC(fwCKR_ATTRIBUTE_TYPE_INVALID,  0x0000),
    LUNA_RET_ATTRIBUTE_VALUE_INVALID               = BuildRC(fwCKR_ATTRIBUTE_VALUE_INVALID, 0x0000),
    LUNA_RET_ATTRIBUTE_READ_ONLY                   = BuildRC(fwCKR_ATTRIBUTE_READ_ONLY,     0x0000),
    LUNA_RET_ATTRIBUTE_SENSITIVE                   = BuildRC(fwCKR_ATTRIBUTE_SENSITIVE,     0x0000),
    LUNA_RET_OBJECT_HANDLE_INVALID                 = BuildRC(fwCKR_OBJECT_HANDLE_INVALID,   0x0000),
    LUNA_RET_MAX_OBJECT_COUNT                      = BuildRC(fwCKR_OBJECT_HANDLE_INVALID,   0x0001),
    LUNA_RET_ATTRIBUTE_NOT_FOUND                   = BuildRC(fwCKR_ATTRIBUTE_TYPE_INVALID,  0x0010),
    LUNA_RET_CAN_NOT_CREATE_SECRET_KEY             = BuildRC(fwCKR_TEMPLATE_INCONSISTENT,   0x0011),
    LUNA_RET_CAN_NOT_CREATE_PRIVATE_KEY            = BuildRC(fwCKR_TEMPLATE_INCONSISTENT,   0x0012),
    LUNA_RET_SECRET_KEY_MUST_BE_SENSITIVE          = BuildRC(fwCKR_ATTRIBUTE_VALUE_INVALID, 0x0013),
    LUNA_RET_SECRET_KEY_MUST_HAVE_SENSITIVE_ATTRIBUTE  = BuildRC(fwCKR_TEMPLATE_INCOMPLETE,     0x0014),
    LUNA_RET_PRIVATE_KEY_MUST_BE_SENSITIVE             = BuildRC(fwCKR_ATTRIBUTE_VALUE_INVALID, 0x0015),
    LUNA_RET_PRIVATE_KEY_MUST_HAVE_SENSITIVE_ATTRIBUTE = BuildRC(fwCKR_TEMPLATE_INCOMPLETE,     0x0016),
    LUNA_RET_SIGNING_KEY_MUST_BE_LOCAL                 = BuildRC(fwCKR_TEMPLATE_INCONSISTENT,   0x0017),
    LUNA_RET_MULTI_FUNCTION_KEYS_NOT_ALLOWED       = BuildRC(fwCKR_TEMPLATE_INCONSISTENT,   0x0018),
    LUNA_RET_CAN_NOT_CHANGE_KEY_FUNCTION           = BuildRC(fwCKR_ATTRIBUTE_READ_ONLY,     0x0019),
    
// NOTE: if you add new result codes, make sure that they either have a good
// encapsulated CKR_ code, or that you update the CodeMapper::ResultToCryptokiCode
// function so that they get properly translated if they're returned through to
// cryptoki.

    // Key Module related

    // Not used
    LUNA_RET_KEY_SENSITIVE                         = BuildRC(fwCKR_KEY_SENSITIVE,   0x0000),

    LUNA_RET_KEY_SIZE_RANGE                        = BuildRC(fwCKR_KEY_SIZE_RANGE,  0x0000),
    // Obsolete. Not used
    LUNA_RET_SM_KEY_SIZE_ERROR                     = BuildRC(fwCKR_KEY_SIZE_RANGE,  0x0001),

    LUNA_RET_KEY_TYPE_INCONSISTENT                 = BuildRC(fwCKR_KEY_TYPE_INCONSISTENT, 0x0000),
    LUNA_RET_KEY_INVALID_FOR_OPERATION             = BuildRC(fwCKR_KEY_TYPE_INCONSISTENT, 0x0001),
    LUNA_RET_KEY_PARITY                            = BuildRC(fwCKR_KEY_TYPE_INCONSISTENT, 0x0002),
    LUNA_RET_KEY_UNEXTRACTABLE                     = BuildRC(fwCKR_KEY_TYPE_INCONSISTENT, 0x0003),
    LUNA_RET_KEY_EXTRACTABLE                       = BuildRC(fwCKR_KEY_TYPE_INCONSISTENT, 0x0004),

    LUNA_RET_KEY_NOT_WRAPPABLE                     = BuildRC(fwCKR_KEY_NOT_WRAPPABLE, 0),
    LUNA_RET_KEY_NOT_UNWRAPPABLE                   = BuildRC(fwCKR_KEY_NOT_WRAPPABLE, 1),
    
    LUNA_RET_ARGUMENTS_BAD                         = BuildRC(fwCKR_ARGUMENTS_BAD, 0x0000),
    LUNA_RET_INVALID_ENTRY_TYPE                    = BuildRC(fwCKR_ARGUMENTS_BAD, 0x0001),

    LUNA_RET_DATA_INVALID                          = BuildRC(fwCKR_DATA_INVALID, 0x0000),

    // Obsolete. Not used
    LUNA_RET_TPV_INVALID                           = BuildRC(fwCKR_DATA_INVALID, 0x0001),

    LUNA_RET_SM_DATA_INVALID                       = BuildRC(fwCKR_DATA_INVALID, 0x0002),
    LUNA_RET_NO_RNG_SEED                           = BuildRC(fwCKR_DATA_INVALID, 0x0015),

    LUNA_RET_NO_OFFBOARD_STORAGE                   = BuildRC(fwCKR_FUNCTION_NOT_SUPPORTED, 0x0001),    

// NOTE: if you add new result codes, make sure that they either have a good
// encapsulated CKR_ code, or that you update the CodeMapper::ResultToCryptokiCode
// function so that they get properly translated if they're returned through to
// cryptoki.

    // User provided buffer is too small.
    LUNA_RET_BUFFER_TOO_SMALL                      = BuildRC(fwCKR_BUFFER_TOO_SMALL, 0x0000),
    LUNA_RET_410_BUFFER_TOO_SMALL                  = BuildRC(fwCKR_DATA_INVALID,     0x0016),  // For 4.1.0 firmware only
    LUNA_RET_DATA_LEN_RANGE                        = BuildRC(fwCKR_DATA_LEN_RANGE,   0x0000),
    LUNA_RET_GENERAL_ERROR                         = BuildRC(fwCKR_GENERAL_ERROR,    0x0000),
    
// NOTE: if you add new result codes, make sure that they either have a good
// encapsulated CKR_ code, or that you update the CodeMapper::ResultToCryptokiCode
// function so that they get properly translated if they're returned through to
// cryptoki.

    LUNA_RET_DEVICE_ERROR                          = BuildRC(fwCKR_DEVICE_ERROR, 0x0000),
    LUNA_RET_UNKNOWN_COMMAND                       = BuildRC(fwCKR_DEVICE_ERROR, 0x0001),
    LUNA_RET_TOKEN_LOCKED_OUT                      = BuildRC(fwCKR_DEVICE_ERROR, 0x0002),
    LUNA_RET_RNG_ERROR                             = BuildRC(fwCKR_DEVICE_ERROR, 0x0003),
    LUNA_RET_DES_SELF_TEST_FAILURE                 = BuildRC(fwCKR_DEVICE_ERROR, 0x0004),
    LUNA_RET_CAST_SELF_TEST_FAILURE                = BuildRC(fwCKR_DEVICE_ERROR, 0x0005),
    LUNA_RET_CAST3_SELF_TEST_FAILURE               = BuildRC(fwCKR_DEVICE_ERROR, 0x0006),
    LUNA_RET_CAST5_SELF_TEST_FAILURE               = BuildRC(fwCKR_DEVICE_ERROR, 0x0007),
    LUNA_RET_MD2_SELF_TEST_FAILURE                 = BuildRC(fwCKR_DEVICE_ERROR, 0x0008),
    LUNA_RET_MD5_SELF_TEST_FAILURE                 = BuildRC(fwCKR_DEVICE_ERROR, 0x0009),
    LUNA_RET_SHA_SELF_TEST_FAILURE                 = BuildRC(fwCKR_DEVICE_ERROR, 0x000a),
    LUNA_RET_RSA_SELF_TEST_FAILURE                 = BuildRC(fwCKR_DEVICE_ERROR, 0x000b),
    LUNA_RET_RC2_SELF_TEST_FAILURE                 = BuildRC(fwCKR_DEVICE_ERROR, 0x000c),
    LUNA_RET_RC4_SELF_TEST_FAILURE                 = BuildRC(fwCKR_DEVICE_ERROR, 0x000d),
    LUNA_RET_RC5_SELF_TEST_FAILURE                 = BuildRC(fwCKR_DEVICE_ERROR, 0x000e),
    LUNA_RET_SO_LOGIN_FAILURE_THRESHOLD            = BuildRC(fwCKR_DEVICE_ERROR, 0x000f),
    LUNA_RET_RNG_SELF_TEST_FAILURE                 = BuildRC(fwCKR_DEVICE_ERROR, 0x0010),
    LUNA_RET_SM_UNKNOWN_COMMAND                    = BuildRC(fwCKR_DEVICE_ERROR, 0x0011),
    LUNA_RET_UM_TSN_MISSING                        = BuildRC(fwCKR_DEVICE_ERROR, 0x0012),
    LUNA_RET_SM_TSV_MISSING                        = BuildRC(fwCKR_DEVICE_ERROR, 0x0013),
    LUNA_RET_SM_UNKNOWN_TOSM_STATE                 = BuildRC(fwCKR_DEVICE_ERROR, 0x0014),
    LUNA_RET_DSA_PARAM_GEN_FAILURE                 = BuildRC(fwCKR_DEVICE_ERROR, 0x0015),
    LUNA_RET_DSA_SELF_TEST_FAILURE                 = BuildRC(fwCKR_DEVICE_ERROR, 0x0016),
    LUNA_RET_SEED_SELF_TEST_FAILURE                = BuildRC(fwCKR_DEVICE_ERROR, 0x0017),
    LUNA_RET_AES_SELF_TEST_FAILURE                 = BuildRC(fwCKR_DEVICE_ERROR, 0x0018),
    LUNA_RET_FUNCTION_NOT_SUPPORTED_BY_HARDWARE    = BuildRC(fwCKR_DEVICE_ERROR, 0x0019),
    LUNA_RET_HAS160_SELF_TEST_FAILURE              = BuildRC(fwCKR_DEVICE_ERROR, 0x001a),
    LUNA_RET_KCDSA_PARAM_GEN_FAILURE               = BuildRC(fwCKR_DEVICE_ERROR, 0x001b),
    LUNA_RET_KCDSA_SELF_TEST_FAILURE               = BuildRC(fwCKR_DEVICE_ERROR, 0x001c),


   

// NOTE: if you add new result codes, make sure that they either have a good
// encapsulated CKR_ code, or that you update the CodeMapper::ResultToCryptokiCode
// function so that they get properly translated if they're returned through to
// cryptoki.

    // Internal HSM buffer is too small. Usually programming error
    LUNA_RET_HSM_INTERNAL_BUFFER_TOO_SMALL         = BuildRC(fwCKR_DEVICE_ERROR, 0x001d),
    LUNA_RET_COUNTER_WRAPAROUND                    = BuildRC(fwCKR_DEVICE_ERROR, 0x001e),

    // General internal timeout (waiting for device, input, etc)
    LUNA_RET_TIMEOUT                               = BuildRC(fwCKR_DEVICE_ERROR, 0x001f),

    // Internally used status code; for example, when waiting asynchronous result.
    LUNA_RET_NOT_READY                             = BuildRC(fwCKR_DEVICE_ERROR, 0x0020),

    LUNA_RET_SHA1_RSA_SELF_TEST_FAILURE            = BuildRC(fwCKR_DEVICE_ERROR, 0x0021),
    
    // token initialization errors
    LUNA_RET_TOKEN_LOCKED_OUT_CL                   = BuildRC(fwCKR_DEVICE_ERROR, 0x0100),
    LUNA_RET_TOKEN_LOCKED_OUT_MM                   = BuildRC(fwCKR_DEVICE_ERROR, 0x0101),
    LUNA_RET_TOKEN_LOCKED_OUT_UM                   = BuildRC(fwCKR_DEVICE_ERROR, 0x0102),
    LUNA_RET_TOKEN_LOCKED_OUT_SM                   = BuildRC(fwCKR_DEVICE_ERROR, 0x0103),
    LUNA_RET_TOKEN_LOCKED_OUT_RN                   = BuildRC(fwCKR_DEVICE_ERROR, 0x0104),
    LUNA_RET_TOKEN_LOCKED_OUT_CA                   = BuildRC(fwCKR_DEVICE_ERROR, 0x0105),
    LUNA_RET_TOKEN_LOCKED_OUT_PM                   = BuildRC(fwCKR_DEVICE_ERROR, 0x0106),
    LUNA_RET_TOKEN_LOCKED_OUT_OH                   = BuildRC(fwCKR_DEVICE_ERROR, 0x0107),
    LUNA_RET_TOKEN_LOCKED_OUT_CCM                  = BuildRC(fwCKR_DEVICE_ERROR, 0x0108),
    LUNA_RET_TOKEN_LOCKED_OUT_SHA_DIGEST           = BuildRC(fwCKR_DEVICE_ERROR, 0x0109),
    
// NOTE: if you add new result codes, make sure that they either have a good
// encapsulated CKR_ code, or that you update the CodeMapper::ResultToCryptokiCode
// function so that they get properly translated if they're returned through to
// cryptoki.

    // Session Manager memory errors
    LUNA_RET_SM_ACCESS_REALLOC_ERROR               = BuildRC(fwCKR_DEVICE_MEMORY, 0x0101),
    LUNA_RET_SM_SESSION_REALLOC_ERROR              = BuildRC(fwCKR_DEVICE_MEMORY, 0x0102),
    LUNA_RET_SM_MEMORY_ALLOCATION_ERROR            = BuildRC(fwCKR_DEVICE_MEMORY, 0x0103),
    
    LUNA_RET_ENCRYPTED_DATA_INVALID                = BuildRC(fwCKR_ENCRYPTED_DATA_INVALID,      0x0000),
    LUNA_RET_ENCRYPTED_DATA_LEN_RANGE              = BuildRC(fwCKR_ENCRYPTED_DATA_LEN_RANGE,    0x0000),
    LUNA_RET_FUNCTION_CANCELED                     = BuildRC(fwCKR_FUNCTION_CANCELED,           0x0000),
    LUNA_RET_KEY_HANDLE_INVALID                    = BuildRC(fwCKR_KEY_HANDLE_INVALID,          0x0000),
    LUNA_RET_MECHANISM_INVALID                     = BuildRC(fwCKR_MECHANISM_INVALID,           0x0000),
    LUNA_RET_MECHANISM_PARAM_INVALID               = BuildRC(fwCKR_MECHANISM_PARAM_INVALID,     0x0000),
    LUNA_RET_OPERATION_ACTIVE                      = BuildRC(fwCKR_OPERATION_ACTIVE,            0x0000),
    LUNA_RET_OPERATION_NOT_INITIALIZED             = BuildRC(fwCKR_OPERATION_NOT_INITIALIZED,   0x0000),
    LUNA_RET_UM_PIN_INCORRECT                      = BuildRC(fwCKR_PIN_INCORRECT,               0x0000),
    LUNA_RET_UM_PIN_INCORRECT_CONTAINER_ZEROIZED   = BuildRC(fwCKR_PIN_INCORRECT,               0x0001),
    LUNA_RET_UM_PIN_INCORRECT_CONTAINER_LOCKED     = BuildRC(fwCKR_PIN_INCORRECT,               0x0002),
    LUNA_RET_UM_PIN_LEN_RANGE                      = BuildRC(fwCKR_PIN_LEN_RANGE,               0x0000),
    LUNA_RET_SM_PIN_EXPIRED                        = BuildRC(fwCKR_PIN_EXPIRED,                 0x0000),
    LUNA_RET_SM_EXCLUSIVE_SESSION_EXISTS           = BuildRC(fwCKR_SESSION_EXCLUSIVE_EXISTS,    0x0000),
    LUNA_RET_SM_SESSION_HANDLE_INVALID             = BuildRC(fwCKR_SESSION_HANDLE_INVALID,      0x0000),
    LUNA_RET_SIGNATURE_INVALID                     = BuildRC(fwCKR_SIGNATURE_INVALID,           0x0000),
    LUNA_RET_SIGNATURE_LEN_RANGE                   = BuildRC(fwCKR_SIGNATURE_LEN_RANGE,         0x0000),
    LUNA_RET_UNWRAPPING_KEY_HANDLE_INVALID         = BuildRC(fwCKR_UNWRAPPING_KEY_HANDLE_INVALID, 0x0000),
    LUNA_RET_UNWRAPPING_KEY_SIZE_RANGE             = BuildRC(fwCKR_UNWRAPPING_KEY_SIZE_RANGE,   0x0000),
    LUNA_RET_UNWRAPPING_KEY_TYPE_INCONSISTENT      = BuildRC(fwCKR_UNWRAPPING_KEY_TYPE_INCONSISTENT, 0x0000),
    LUNA_RET_USER_ALREADY_LOGGED_IN                = BuildRC(fwCKR_USER_ALREADY_LOGGED_IN,      0x0000),
    LUNA_RET_SM_OTHER_USER_LOGGED_IN               = BuildRC(fwCKR_USER_ALREADY_LOGGED_IN,      0x0001),

// NOTE: if you add new result codes, make sure that they either have a good
// encapsulated CKR_ code, or that you update the CodeMapper::ResultToCryptokiCode
// function so that they get properly translated if they're returned through to
// cryptoki.

    // Not used
    LUNA_RET_USER_NOT_LOGGED_IN                    = BuildRC(fwCKR_USER_NOT_LOGGED_IN,          0x0000),

    LUNA_RET_SM_NOT_LOGGED_IN                      = BuildRC(fwCKR_USER_NOT_LOGGED_IN,          0x0001),
    LUNA_RET_USER_PIN_NOT_INITIALIZED              = BuildRC(fwCKR_USER_PIN_NOT_INITIALIZED,    0x0000),
    LUNA_RET_USER_TYPE_INVALID                     = BuildRC(fwCKR_USER_TYPE_INVALID,           0x0000),
    LUNA_RET_WRAPPED_KEY_INVALID                   = BuildRC(fwCKR_WRAPPED_KEY_INVALID,         0x0000),
    LUNA_RET_WRAPPED_KEY_LEN_RANGE                 = BuildRC(fwCKR_WRAPPED_KEY_LEN_RANGE,       0x0000),
    LUNA_RET_WRAPPING_KEY_HANDLE_INVALID           = BuildRC(fwCKR_WRAPPING_KEY_HANDLE_INVALID, 0x0000),
    LUNA_RET_WRAPPING_KEY_SIZE_RANGE               = BuildRC(fwCKR_WRAPPING_KEY_SIZE_RANGE,     0x0000),
    LUNA_RET_WRAPPING_KEY_TYPE_INCONSISTENT        = BuildRC(fwCKR_WRAPPING_KEY_TYPE_INCONSISTENT, 0x0000),
    
    LUNA_RET_CERT_VERSION_NOT_SUPPORTED            = BuildRC(fwCKR_DEVICE_ERROR, 0x0300),
    
// NOTE: if you add new result codes, make sure that they either have a good
// encapsulated CKR_ code, or that you update the CodeMapper::ResultToCryptokiCode
// function so that they get properly translated if they're returned through to
// cryptoki.

    LUNA_RET_ERROR                                 = VendorRC(0x0000),
    LUNA_RET_CONTAINER_HANDLE_INVALID              = VendorRC(0x0001),
    LUNA_RET_INVALID_PADDING_TYPE                  = VendorRC(0x0002),
    LUNA_RET_NOT_FOUND                             = VendorRC(0x0007),
    LUNA_RET_TOO_MANY_CONTAINERS                   = VendorRC(0x0008),
    LUNA_RET_CONTAINER_LOCKED                      = VendorRC(0x0009),

    LUNA_RET_CONTAINER_IS_DISABLED                 = VendorRC(0x000a),
    LUNA_RET_SECURITY_PARAMETER_MISSING            = VendorRC(0x000b),


// NOTE: if you add new result codes, make sure that they either have a good
// encapsulated CKR_ code, or that you update the CodeMapper::ResultToCryptokiCode
// function so that they get properly translated if they're returned through to
// cryptoki.

    //key cloning related
    LUNA_RET_KCV_PARAMETER_ALREADY_EXISTS          = VendorRC(0x0100),
    LUNA_RET_KCV_PARAMETER_COULD_NOT_BE_ADDED      = VendorRC(0x0101),
    LUNA_RET_INVALID_CERTIFICATE_DATA              = VendorRC(0x0102),
    LUNA_RET_INVALID_CERTIFICATE_TYPE              = VendorRC(0x0103),
    LUNA_RET_INVALID_CERTIFICATE_VERSION           = VendorRC(0x0104),
    LUNA_RET_INVALID_MODULUS_SIZE                  = VendorRC(0x0105),
    LUNA_RET_WRAPPING_ERROR                        = VendorRC(0x0107),
    LUNA_RET_UNWRAPPING_ERROR                      = VendorRC(0x0108),
    LUNA_RET_INVALID_PRIVATE_KEY_TYPE              = VendorRC(0x0109),
    LUNA_RET_TSN_MISMATCH                          = VendorRC(0x010a),
    LUNA_RET_KCV_PARAMETER_MISSING                 = VendorRC(0x010b),
    LUNA_RET_TWC_PARAMETER_MISSING                 = VendorRC(0x010c),
    LUNA_RET_TUK_PARAMETER_MISSING                 = VendorRC(0x010d),
    LUNA_RET_CPK_PARAMETER_MISSING                 = VendorRC(0x010e),
    LUNA_RET_MASKING_NOT_SUPPORTED                 = VendorRC(0x010f),
    LUNA_RET_INVALID_ACCESS_LEVEL                  = VendorRC(0x0110),

// NOTE: if you add new result codes, make sure that they either have a good
// encapsulated CKR_ code, or that you update the CodeMapper::ResultToCryptokiCode
// function so that they get properly translated if they're returned through to
// cryptoki.

//hardware secured certificates (HSC) related 
//keep this at 0x1-- since it's close to the cloning stuff
    LUNA_RET_MAC_MISSING                           = VendorRC(0x0111),
    LUNA_RET_DAC_POLICY_PID_MISMATCH               = VendorRC(0x0112),
    LUNA_RET_DAC_MISSING                           = VendorRC(0x0113),
    LUNA_RET_BAD_DAC                               = VendorRC(0x0114),
    LUNA_RET_SSK_MISSING                           = VendorRC(0x0115),
    LUNA_RET_BAD_MAC                               = VendorRC(0x0116),
    LUNA_RET_DAK_MISSING                           = VendorRC(0x0117),
    LUNA_RET_BAD_DAK                               = VendorRC(0x0118),
    LUNA_RET_HOK_MISSING                           = VendorRC(0x0119),
    LUNA_RET_CITS_DAK_MISSING                      = VendorRC(0x011a),

    LUNA_RET_SIM_AUTHORIZATION_FAILED              = VendorRC(0x011b),
    LUNA_RET_SIM_VERSION_UNSUPPORTED               = VendorRC(0x011c),
    LUNA_RET_SIM_CORRUPT_DATA                      = VendorRC(0x011d),
    LUNA_RET_SIM_AUTHFORM_INVALID                  = BuildRC(fwCKR_DATA_INVALID, 0x011e),

// NOTE: if you add new result codes, make sure that they either have a good
// encapsulated CKR_ code, or that you update the CodeMapper::ResultToCryptokiCode
// function so that they get properly translated if they're returned through to
// cryptoki.
    
    //M of N related error codes
    LUNA_RET_N_TOO_LARGE                           = VendorRC(0x0200),
    LUNA_RET_N_TOO_SMALL                           = VendorRC(0x0201),
    LUNA_RET_M_TOO_LARGE                           = VendorRC(0x0202),
    LUNA_RET_M_TOO_SMALL                           = VendorRC(0x0203),
    LUNA_RET_WEIGHT_TOO_LARGE                      = VendorRC(0x0204),
    LUNA_RET_WEIGHT_TOO_SMALL                      = VendorRC(0x0205),
    LUNA_RET_TOTAL_WEIGHT_INVALID                  = VendorRC(0x0206),
    LUNA_RET_MISSING_SPLITS                        = VendorRC(0x0207),
    LUNA_RET_SPLIT_DATA_INVALID                    = VendorRC(0x0208),
    LUNA_RET_SPLIT_ID_INVALID                      = VendorRC(0x0209),
    LUNA_RET_M_OF_N_PARAMETER_NOT_AVAILABLE        = VendorRC(0x020a),
    LUNA_RET_M_OF_N_ACTIVATION_REQUIRED            = VendorRC(0x020b),
    LUNA_RET_TOO_MANY_WEIGHTS                      = VendorRC(0x020e),
    LUNA_RET_MISSING_WEIGHT_VALUE                  = VendorRC(0x020f),
    LUNA_RET_MISSING_VALUE_FOR_M                   = VendorRC(0x0210),
    LUNA_RET_MISSING_VALUE_FOR_N                   = VendorRC(0x0211),
    LUNA_RET_MISSING_NUMBER_OF_VECTORS             = VendorRC(0x0212),
    LUNA_RET_MISSING_VECTOR                        = VendorRC(0x0213),
    LUNA_RET_VECTOR_TOO_LARGE                      = VendorRC(0x0214),
    LUNA_RET_VECTOR_TOO_SMALL                      = VendorRC(0x0215),
    LUNA_RET_TOO_MANY_VECTORS_PROVIDED             = VendorRC(0x0216),
    LUNA_RET_INVALID_VECTOR_SIZE                   = VendorRC(0x0217),
    LUNA_RET_M_OF_N_PARAMETER_EXIST                = VendorRC(0x0218),
    LUNA_RET_VECTOR_VERSION_INVALID                = VendorRC(0x0219),
    LUNA_RET_VECTOR_OF_DIFFERENT_SET               = VendorRC(0x021a),
    LUNA_RET_VECTOR_DUPLICATE                      = VendorRC(0x021b),
    LUNA_RET_VECTOR_TYPE_INVALID                   = VendorRC(0x021c),
    LUNA_RET_MISSING_COMMAND_PARAMETER             = VendorRC(0x021d),
    LUNA_RET_M_OF_N_CLONING_IS_NOT_ALLOWED         = VendorRC(0x021e),
    LUNA_RET_M_OF_N_IS_NOT_REQUIRED                = VendorRC(0x021f),
    LUNA_RET_M_OF_N_IS_NOT_INITIALZED              = VendorRC(0x0220),
    LUNA_RET_M_OF_N_SECRET_INVALID                 = VendorRC(0x0221),

// NOTE: if you add new result codes, make sure that they either have a good
// encapsulated CKR_ code, or that you update the CodeMapper::ResultToCryptokiCode
// function so that they get properly translated if they're returned through to
// cryptoki.
    
    // custom command module related error codes
    LUNA_RET_CCM_NOT_PRESENT                       = VendorRC(0x0300),
    LUNA_RET_CCM_NOT_SUPPORTED                     = VendorRC(0x0301),
    LUNA_RET_CCM_UNREMOVABLE                       = VendorRC(0x0302),
    LUNA_RET_CCM_CERT_INVALID                      = VendorRC(0x0303),
    LUNA_RET_CCM_SIGN_INVALID                      = VendorRC(0x0304),
    LUNA_RET_CCM_UPDATE_DENIED                     = VendorRC(0x0305),
    LUNA_RET_CCM_FWUPDATE_DENIED                   = VendorRC(0x0306),
    LUNA_RET_CCM_TOO_LARGE                         = BuildRC(fwCKR_DATA_LEN_RANGE, 1),

// NOTE: if you add new result codes, make sure that they either have a good
// encapsulated CKR_ code, or that you update the CodeMapper::ResultToCryptokiCode
// function so that they get properly translated if they're returned through to
// cryptoki.
    
    // Session Manager Error Codes
    LUNA_RET_SM_ACCESS_ID_INVALID                  = VendorRC(0x0400),
    LUNA_RET_SM_ACCESS_ALREADY_EXISTS              = VendorRC(0x0401),
    LUNA_RET_SM_MULTIPLE_ACCESS_DISABLED           = VendorRC(0x0402),
    LUNA_RET_SM_UNKNOWN_ACCESS_TYPE                = VendorRC(0x0403),
    LUNA_RET_SM_BAD_ACCESS_HANDLE                  = VendorRC(0x0404),
    LUNA_RET_SM_BAD_CONTEXT_NUMBER                 = VendorRC(0x0405),
    LUNA_RET_SM_UNKNOWN_SESSION_TYPE               = VendorRC(0x0406),
    LUNA_RET_SM_CONTEXT_ALREADY_ALLOCATED          = VendorRC(0x0407),
    LUNA_RET_SM_CONTEXT_NOT_ALLOCATED              = VendorRC(0x0408),
    LUNA_RET_SM_CONTEXT_BUFFER_OVERFLOW            = VendorRC(0x0409),
    LUNA_RET_SM_TOSM_DOES_NOT_VALIDATE             = VendorRC(0x040A),
    LUNA_RET_SM_ACCESS_DOES_NOT_VALIDATE           = VendorRC(0x040B),

// NOTE: if you add new result codes, make sure that they either have a good
// encapsulated CKR_ code, or that you update the CodeMapper::ResultToCryptokiCode
// function so that they get properly translated if they're returned through to
// cryptoki.
    
    // HIFN Data Encryption Processor Error Codes.
    LUNA_RET_HIFN_NOT_PRESENT					    = VendorRC(0x0500),
    LUNA_RET_HIFN_SOURCE_COUNT_INVALID			    = VendorRC(0x0501),
    LUNA_RET_HIFN_DESTINATION_COUNT_INVALID		    = VendorRC(0x0502),
    LUNA_RET_HIFN_INVALID_MAC_ALGORITHM			    = VendorRC(0x0503),
    LUNA_RET_HIFN_INVALID_MAC_MODE				    = VendorRC(0x0504),
    LUNA_RET_HIFN_MAC_SOURCE_COUNT_INVALID		    = VendorRC(0x0505),
    LUNA_RET_HIFN_MAC_HEADER_COUNT_INVALID		    = VendorRC(0x0506),
    LUNA_RET_HIFN_INVALID_ENCRYPT_ALGORITHM		    = VendorRC(0x0507),
    LUNA_RET_HIFN_INVALID_ENCRYPT_MODE			    = VendorRC(0x0508),
    LUNA_RET_HIFN_ENCRYPT_SOURCE_COUNT_INVALID	    = VendorRC(0x0509),
    LUNA_RET_HIFN_ENCRYPT_HEADER_COUNT_INVALID	    = VendorRC(0x050a),
    LUNA_RET_HIFN_DMA_ERROR						    = VendorRC(0x050b),
    LUNA2_RET_HIFN_RESET_ERROR					    = VendorRC(0x050c),
    LUNA_RET_HIFN_DMA_NOT_IDLE					    = VendorRC(0x050d),
    LUNA_RET_HIFN_DMA_TIMED_OUT					    = VendorRC(0x050e),
    LUNA_HIFN_UNKNOWN_ALGORITHM					    = VendorRC(0x050f),
    LUNA_INVALID_PACKET_LAYOUT					    = VendorRC(0x0510),
    LUNA_RET_HIFN_INVALID_COMPRESSION_ALGORITHM     = VendorRC(0x0511),
    LUNA_RET_HIFN_COMPRESSION_SOURCE_COUNT_INVALID  = VendorRC(0x0512),
    LUNA_RET_HIFN_COMPRESSION_HEADER_COUNT_INVALID  = VendorRC(0x0513),   
    LUNA_RET_HIFN_INVALID_PAD_ALGORITHM             = VendorRC(0x0514),
    LUNA_RET_HIFN_PAD_SOURCE_COUNT_INVALID          = VendorRC(0x0515),
    LUNA_RET_HIFN_END_MARKER_NOT_PRESENT			= VendorRC(0x0516),
    LUNA_RET_HIFN_DESTINATION_OVERRUN				= VendorRC(0x0517),
    LUNA_RET_HIFN_COMPRESS_SOURCE_NOT_ZERO			= VendorRC(0x0518),
    LUNA_RET_HIFN_MAC_SOURCE_NOT_ZERO				= VendorRC(0x0519),
    LUNA_RET_HIFN_ENCRYPT_SOURCE_NOT_ZERO			= VendorRC(0x051a),

// NOTE: if you add new result codes, make sure that they either have a good
// encapsulated CKR_ code, or that you update the CodeMapper::ResultToCryptokiCode
// function so that they get properly translated if they're returned through to
// cryptoki.
    
    LUNA_RET_HIFN_DMA_INVALID_REVISION				= VendorRC(0x0530),
    
    LUNA_RET_INVALID_IP_PACKET						= VendorRC(0x0600),
    
    LUNA_RET_INVALID_BOARD_TYPE                     = VendorRC(0x0700),
    
    LUNA_RET_ISES_ERROR                             = BuildRC(fwCKR_DEVICE_ERROR, 0x0880),
    LUNA_RET_ISES_INIT_FAILED                       = BuildRC(fwCKR_DEVICE_ERROR, 0x0881),
    LUNA_RET_ISES_LNAU_TEST_FAILED                  = BuildRC(fwCKR_DEVICE_ERROR, 0x0882),
    LUNA_RET_ISES_RNG_TEST_FAILED                   = BuildRC(fwCKR_DEVICE_ERROR, 0x0883),
    LUNA_RET_ISES_CMD_FAILED                        = BuildRC(fwCKR_DEVICE_ERROR, 0x0884),
    LUNA_RET_ISES_CMD_PARAMETER_INVALID             = BuildRC(fwCKR_DEVICE_ERROR, 0x0885),
    LUNA_RET_ISES_TEST_VS_BSAFE_FAILED              = BuildRC(fwCKR_DEVICE_ERROR, 0x0886),

// NOTE: if you add new result codes, make sure that they either have a good
// encapsulated CKR_ code, or that you update the CodeMapper::ResultToCryptokiCode
// function so that they get properly translated if they're returned through to
// cryptoki.
    
    LUNA_RET_HIFN6500_NOT_PRESENT                   = BuildRC(fwCKR_DEVICE_ERROR, 0x0801),
    LUNA_RET_HIFN6500_RESET_TIMEOUT                 = BuildRC(fwCKR_DEVICE_ERROR, 0x0802),
    LUNA_RET_HIFN6500_DATA_LINES_BROKEN             = BuildRC(fwCKR_DEVICE_ERROR, 0x0803),
    LUNA_RET_HIFN6500_ADDRESS_LINES_BROKEN          = BuildRC(fwCKR_DEVICE_ERROR, 0x0804),
    LUNA_RET_HIFN6500_KNOWN_ANSWER_TEST_FAILED      = BuildRC(fwCKR_DEVICE_ERROR, 0x0805),
    LUNA_RET_HIFN6500_RNG_FAILED                    = BuildRC(fwCKR_DEVICE_ERROR, 0x0806),
    LUNA_RET_HIFN6500_RNG_TIMEOUT                   = BuildRC(fwCKR_DEVICE_ERROR, 0x0807),
    LUNA_RET_HIFN6500_RNG_UNDERFLOW                 = BuildRC(fwCKR_DEVICE_ERROR, 0x0808),
    LUNA_RET_HIFN6500_ALU_TIMEOUT                   = BuildRC(fwCKR_DEVICE_ERROR, 0x0809),
    LUNA_RET_HIFN6500_INVALID_PARAMETERS            = BuildRC(fwCKR_DEVICE_ERROR, 0x080a),
    LUNA_RET_HIFN6500_INVALID_OPERAND_LENGTH        = BuildRC(fwCKR_DEVICE_ERROR, 0x080b),
    LUNA_RET_HIFN6500_INVALID_OPERAND_ENDIANESS     = BuildRC(fwCKR_DEVICE_ERROR, 0x080c),
    LUNA_RET_HIFN6500_INVALID_RESULT_ENDIANESS      = BuildRC(fwCKR_DEVICE_ERROR, 0x080d),
    LUNA_RET_HIFN6500_TOO_SMALL_USER_BUFFER_FOR_RESULT      = BuildRC(fwCKR_DEVICE_ERROR, 0x080e),

// NOTE: if you add new result codes, make sure that they either have a good
// encapsulated CKR_ code, or that you update the CodeMapper::ResultToCryptokiCode
// function so that they get properly translated if they're returned through to
// cryptoki.
    
    LUNA_RET_TEST_VS_BSAFE_FAILED                   = BuildRC(fwCKR_DEVICE_ERROR, 0x0820),
    
    // Certicom ECDSA specific Error Codes.
    LUNA_RET_ECC_NOT_SUPPORTED                      = VendorRC(0x0601),
    LUNA_RET_ECC_BUFFER_OVERFLOW                    = VendorRC(0x0602),
    LUNA_RET_ECC_POINT_INVALID                      = VendorRC(0x0603),
    LUNA_RET_ECC_SELF_TEST_FAILURE                  = VendorRC(0x0604),
    
    
    // High Availability errors
    LUNA_RET_HA_NOT_SUPPORTED                       = VendorRC(0x0900),
    LUNA_RET_HA_USER_NOT_INITIALIZED                = VendorRC(0x0901),

// NOTE: if you add new result codes, make sure that they either have a good
// encapsulated CKR_ code, or that you update the CodeMapper::ResultToCryptokiCode
// function so that they get properly translated if they're returned through to
// cryptoki.
    
    LUNA_RET_RM_ELEMENT_VALUE_INVALID               = BuildRC(fwCKR_DATA_INVALID,     0x0a00),
    LUNA_RET_RM_ELEMENT_ID_INVALID                  = BuildRC(fwCKR_DATA_INVALID,     0x0a01),
    LUNA_RET_RM_NO_MEMORY                           = BuildRC(fwCKR_DEVICE_MEMORY,    0x0a02),
    LUNA_RET_RM_BAD_HSM_PARAMS                      = BuildRC(fwCKR_DEVICE_ERROR,     0x0a03),
    LUNA_RET_RM_POLICY_ELEMENT_DESTRUCTIVE          = BuildRC(fwCKR_DATA_INVALID,     0x0a04),
    LUNA_RET_RM_POLICY_ELEMENT_NOT_DESTRUCTIVE      = BuildRC(fwCKR_DATA_INVALID,     0x0a05),
    LUNA_RET_RM_CONFIG_CHANGE_ILLEGAL               = BuildRC(fwCKR_CANCEL,           0x0a06),
    LUNA_RET_RM_CONFIG_CHANGE_FAILS_DEPENDENCIES    = BuildRC(fwCKR_CANCEL,           0x0a07),
    LUNA_RET_LICENSE_ID_UNKNOWN                     = BuildRC(fwCKR_DATA_INVALID,     0x0a08),
    LUNA_RET_LICENSE_CAPACITY_EXCEEDED              = BuildRC(fwCKR_CANCEL,           0x0a09),
    LUNA_RET_RM_POLICY_WRITE_RESTRICTED             = BuildRC(fwCKR_CANCEL,           0x0a0a),
    LUNA_RET_OPERATION_RESTRICTED                   = BuildRC(fwCKR_DEVICE_ERROR,     0x0a0b),
    LUNA_RET_CANNOT_PERFORM_OPERATION_TWICE         = BuildRC(fwCKR_DEVICE_ERROR,     0x0a0c),
    LUNA_RET_BAD_PPID                               = BuildRC(fwCKR_DATA_INVALID,     0x0a0d),
    LUNA_RET_BAD_FW_VERSION                         = BuildRC(fwCKR_DATA_INVALID,     0x0a0e),
    LUNA_RET_OPERATION_SHOULD_BE_DESTRUCTIVE        = BuildRC(fwCKR_DATA_INVALID,     0x0a0f),
    LUNA_RET_RM_CONFIG_ILLEGAL                      = BuildRC(fwCKR_DATA_INVALID,     0x0a10),
    LUNA_RET_BAD_SN                                 = BuildRC(fwCKR_DATA_INVALID,     0x0a11),

// NOTE: if you add new result codes, make sure that they either have a good
// encapsulated CKR_ code, or that you update the CodeMapper::ResultToCryptokiCode
// function so that they get properly translated if they're returned through to
// cryptoki.
    
    LUNA_RET_CHALLENGE_TYPE_INVALID                 = BuildRC(fwCKR_DATA_INVALID,     0x0b00),
    LUNA_RET_CHALLENGE_REQUIRES_PED                 = BuildRC(fwCKR_CANCEL,           0x0b01),
    LUNA_RET_CHALLENGE_NOT_REQUIRED                 = BuildRC(fwCKR_CANCEL,           0x0b02),
    LUNA_RET_CHALLENGE_RESPONSE_INCORRECT           = BuildRC(fwCKR_PIN_INCORRECT,    0x0b03),
    LUNA_RET_410_CHALLENGE_RESPONSE_INCORRECT       = BuildRC(fwCKR_CANCEL,           0x0b03),  // For 4.1.0 firmware only

// NOTE: if you add new result codes, make sure that they either have a good
// encapsulated CKR_ code, or that you update the CodeMapper::ResultToCryptokiCode
// function so that they get properly translated if they're returned through to
// cryptoki.

    LUNA_RET_OH_OBJECT_VERSION_INVALID              = BuildRC(fwCKR_DEVICE_ERROR,     0x0c00),
    LUNA_RET_OH_OBJECT_TYPE_INVALID                 = BuildRC(fwCKR_DEVICE_ERROR,     0x0c01),
    LUNA_RET_OH_OBJECT_ALREADY_EXISTS               = BuildRC(fwCKR_CANCEL,           0x0c02),
    LUNA_RET_OH_OBJECT_OWNER_DOES_NOT_EXIST         = BuildRC(fwCKR_DATA_INVALID,     0x0c03),
    LUNA_RET_STORAGE_TYPE_INCONSISTENT              = BuildRC(fwCKR_DATA_INVALID,     0x0c04),
    LUNA_RET_CONTAINER_CAN_NOT_HAVE_MEMBERS         = BuildRC(fwCKR_DATA_INVALID,     0x0c05),


// NOTE: if you add new result codes, make sure that they either have a good
// encapsulated CKR_ code, or that you update the CodeMapper::ResultToCryptokiCode
// function so that they get properly translated if they're returned through to
// cryptoki.
    LUNA_RET_CB_NOT_SUPPORTED                       = VendorRC(0x0a01),
    LUNA_RET_CB_PARAM_INVALID                       = VendorRC(0x0a02),
    LUNA_RET_CB_NO_MEMORY                           = VendorRC(0x0a03),
    LUNA_RET_CB_TIMEOUT                             = VendorRC(0x0a04),
    LUNA_RET_CB_RETRY                               = VendorRC(0x0a05),
    LUNA_RET_CB_ABORTED                             = VendorRC(0x0a06),
    LUNA_RET_CB_SYS_ERROR                           = VendorRC(0x0a07),
    LUNA_RET_CB_HIOS_HANDLE_INVALID                 = VendorRC(0x0a10),
    LUNA_RET_CB_HIOS_ID_INVALID                     = VendorRC(0x0a11),
    LUNA_RET_CB_HIOS_CLOSED                         = VendorRC(0x0a12),
    LUNA_RET_CB_HIOS_CANCELED                       = VendorRC(0x0a13),
    LUNA_RET_CB_HIOS_IO_ERROR                       = VendorRC(0x0a14),
    LUNA_RET_CB_HIOS_SEND_TIMEOUT                   = VendorRC(0x0a15),
    LUNA_RET_CB_HIOS_RECV_TIMEOUT                   = VendorRC(0x0a16),
    LUNA_RET_CB_HIOS_STATE_INVALID                  = VendorRC(0x0a17),
    LUNA_RET_CB_HIOS_OUTPUT_BUFFER_TOO_SMALL        = VendorRC(0x0a18),
    LUNA_RET_CB_HIOS_INPUT_BUFFER_TOO_SMALL         = VendorRC(0x0a19),
    LUNA_RET_CB_HANDLE_INVALID                      = VendorRC(0x0a20),
    LUNA_RET_CB_ID_INVALID                          = VendorRC(0x0a21),
    LUNA_RET_CB_REMOTE_ABORT                        = VendorRC(0x0a22),
    LUNA_RET_CB_REMOTE_CLOSED                       = VendorRC(0x0a23),
    LUNA_RET_CB_REMOTE_ABANDONED                    = VendorRC(0x0a24),
    LUNA_RET_CB_MUST_READ                           = VendorRC(0x0a25),
    LUNA_RET_CB_MUST_WRITE                          = VendorRC(0x0a26),
    LUNA_RET_CB_INVALID_CALL_FOR_THE_STATE          = VendorRC(0x0a27),
    LUNA_RET_CB_SYNC_ERROR                          = VendorRC(0x0a28),
    LUNA_RET_CB_PROT_DATA_INVALID                   = VendorRC(0x0a29)

#ifdef COMPILING_FIRMWARE
} ResultCode;
#else
} fwResultCode;
#endif


#undef BuildRC




#endif // __INCLUDE_FWRC_H



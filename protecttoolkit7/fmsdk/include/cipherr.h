/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: cipherr.h
 */

#ifndef CIPHERR_INCLUDED
#define CIPHERR_INCLUDED

/* This is the type returned from CiphObj functions */
enum _CiphObjStat {
    CO_OK                       = 0,    /* OK */
    CO_PARAM_INVALID            = 1,    /* Usually mode is wrong */
    CO_SIG_INVALID              = 2,
    CO_LENGTH_INVALID           = 3,
    CO_DEVICE_ERROR             = 4,
    CO_GENERAL_ERROR            = 5,
    CO_MEMORY_ERROR             = 6,
    CO_BUFFER_TOO_SMALL         = 7,
    CO_DATA_INVALID             = 8,
    CO_NEED_IV_UPDATE           = 9,
    CO_NOT_SUPPORTED            = 10,
    CO_DUPLICATE_IV_FOUND       = 11,
    CO_FIPSG_ERROR              = 12,   /* Output from FIPSG whitener failed FIPS RNG test */
    CO_FUNCTION_NOT_IMPLEMENTED = 13,
    CO_POINT_INVALID            = 14
};

typedef enum _CiphObjStat CiphObjStat;

#endif

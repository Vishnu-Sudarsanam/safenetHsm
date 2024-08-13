/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 */

#pragma once
#include <fmhdr.h>

#ifdef __GNUC__
    #define FMHDR_VISIBILITY __attribute__((section(FM_HEADER_SECTION))) \
                             __attribute__((visibility("protected")))
#else
    #define FMHDR_VISIBILITY
#endif

/*
 * FM_VERSION must be stored in the header as if a 16 bit integer in big endian
 * format with MAJOR_VERSION in the high byte and MINOR_VERSION in the low byte.
 */
#ifdef IS_BIG_ENDIAN
    #define FM_MAKE_VERSION(MAJOR,MINOR) ((((MAJOR)&0x00FF)<<8) | ((MINOR)&0x00FF))
#else
    #define FM_MAKE_VERSION(MAJOR,MINOR) (((MAJOR)&0x00FF) | (((MINOR)&0xFF)<<8))
#endif

/*
 * FM_TIMESTAMP is a 64 bit time_t integer value.
 * If it is not set at compilation time, it will default to 0, and be set by the
 * mkfm utility.
 */
#ifndef FM_TIMESTAMP
#define FM_TIMESTAMP 0
#endif

#ifdef _MSC_VER
//MSVC is not c99 compatible as of msvc 16
#define DEFINE_FM_HEADER( FM_NUMBER,                \
        FM_VERSION,                                 \
        FM_SERIAL_NO,                               \
        MANUFACTURER_ID,                            \
        PRODUCT_ID)                                 \
const FM_Header_t FM_HEADER = {                     \
        FM_FORMAT_VERSION,                          \
        FM_NUMBER,                                  \
        FM_VERSION,                                 \
        FM_SERIAL_NO,                               \
        FM_TIMESTAMP,                               \
        MANUFACTURER_ID,                            \
        PRODUCT_ID                                  \
};
#else
#define DEFINE_FM_HEADER( FM_NUMBER,                \
        FM_VERSION,                                 \
        FM_SERIAL_NO,                               \
        MANUFACTURER_ID,                            \
        PRODUCT_ID)                                 \
const FM_Header_t FM_HEADER FMHDR_VISIBILITY = {    \
        .formatVersion = FM_FORMAT_VERSION,         \
        .number = FM_NUMBER,                        \
        .version = FM_VERSION,                      \
        .serialNo = FM_SERIAL_NO,                   \
        .productionDate = FM_TIMESTAMP,             \
        .manufacturerId = MANUFACTURER_ID,          \
        .productId = PRODUCT_ID,                    \
};
#endif

/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: appid_t.h
 */
#ifndef INC_APPID_T_H
#define INC_APPID_T_H

#include <stdint.h>

/*
 * AppId structure for HSM and FM Emulation use
 */
typedef struct {
    uint32_t pid;
    uint32_t oid;
} AppId_t;

#endif /* INC_APPID_T_H */

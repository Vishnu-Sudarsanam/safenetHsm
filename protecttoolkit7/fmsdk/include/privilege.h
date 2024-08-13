/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: privilege.h
 */
/**
 * @file
 *  privilege - Allows elevatation of privilege level to circumvent
 *              builtin security mechanisms on PKCS#11 objects.
 */
#ifndef INC_PRIVILEGE_H
#define INC_PRIVILEGE_H

#include <cryptoki.h>
#ifdef __cplusplus
extern "C" {
#endif

/**
 * Normal privilege level
 */
#define PRIVILEGE_NORMAL    0

/**
 * Elevate privilege level allowing override of sensitive attribute and
 * key usage
 */
#define PRIVILEGE_OVERRIDE  1

/**
 * This function is an ERACOM extension to PKCS#11. It can be used to set
 * the privilege level of the caller to the specified value, if the caller
 * has access to the function. It has a global effect on all
 * sessions/applications.
 *
 * @param level
 *  Required privilege level
 */
DLL_EXPORT void CK_ENTRY CT_SetPrivilegeLevel( int level );

/**
 * This function is an ERACOM extension to PKCS#11. It can be used to get
 * the privilege level of the caller. 
 *
 * @return Required privilege level
 */
DLL_EXPORT int CK_ENTRY CT_GetPrivilegeLevel( void );

#ifdef _WIN32
typedef void (CK_ENTRY *CK_CT_SetPrivilegeLevel)( int level );
typedef int (CK_ENTRY *CK_CT_GetPrivilegeLevel)( void );
#else
typedef void CK_ENTRY (*CK_CT_SetPrivilegeLevel)( int level );
typedef int CK_ENTRY (*CK_CT_GetPrivilegeLevel)( void );
#endif

#ifdef __cplusplus
}
#endif

#endif /* INC_PRIVILEGE_H */

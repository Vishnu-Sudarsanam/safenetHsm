/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: fmappid.h
 */
#ifndef INC_FMAPPID_H
#define INC_FMAPPID_H
#include <limits.h>

#define FM_DEFAULT_PID UINT_MAX
#define FM_DEFAULT_OID UINT_MAX

/**
 * This function returns the PID recorded in the current request originated
 * from the host side. If there is no active request (e.g. a call from
 * Startup()function), FM_DEFAULT_PID is returned.
 *
 * @return unsigned long
 *     The pid of the application which originated the request.
 */
unsigned long FM_GetCurrentPid(void);

/**
 * This function returns the OID recorded in the current request originated
 * from the host side. If there is no active request (e.g. a call from
 * Startup() function), FM_DEFAULT_OID is returned.
 *
 * @return unsigned long
 *     The oid of the application which originated the request.
 */
unsigned long FM_GetCurrentOid(void);

/**
 * This function overrides the PID recorded in the current request originated
 * from the host side. If there is no active request the function does nothing.
 *
 * @param pid
 *     The new PID to be recorded in the request.
 */
void FM_SetCurrentPid(unsigned long pid);

/**
 * This function overrides the OID recorded in the current request originating
 * from the host side. If there is no active request the function does nothing.
 *
 * @param oid
 *     The new OID to be recorded in the request.
 */
void FM_SetCurrentOid(unsigned long oid);


#endif /* INC_FMAPPID_H */

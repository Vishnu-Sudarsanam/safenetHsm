/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: cprovpch.h
 */
#ifndef INC_CPROVPCH_H
#define INC_CPROVPCH_H
#include <cprovtbl.h>

/*
 * Obtain the address of the Cprov function table. 
 *
 * Return Value:
 * Address of the Cprov function table. This function will return NULL.
 */
CprovFnTable_t *OS_GetCprovFuncTable(void);

#endif /* INC_CPROVPCH_H */

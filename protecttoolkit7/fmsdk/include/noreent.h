/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: noreent.h
 */
#ifndef INC_NOREENT_H
#define INC_NOREENT_H

#include <cryptoki.h>

/**
 * Initialize the single threading module.
 *
 * @param pInitializeArgs
 *    The CK_C_INITIALIZE_ARGS structure address passed to C_Initialize()
 *    function.
 */
DLL_EXPORT CK_RV NOREENT_Init(CK_VOID_PTR pInitializeArgs);

/**
 * Finalize the single threading module, so that NOREENT_Init() can be called again.
 */
DLL_EXPORT void NOREENT_Final(void);

/**
 * Enter a block of code to be protected from re-entrancy.
 */
DLL_EXPORT CK_RV NOREENT_Enter(void);

/**
 * Leave a block of code to be protected from re-entrancy.
 */
DLL_EXPORT CK_RV NOREENT_Leave(void);

#endif /* INC_NOREENT_H */

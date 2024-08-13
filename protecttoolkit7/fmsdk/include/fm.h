/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: fm.h
 */
#ifndef INC_FM_H
#define INC_FM_H
#include <cryptoki.h>
#include <fmhdr.h>
#include <fmerr.h>
/*
 * For compatibility with pre FMSDK 5.0 toolkits, include endian macros.
 */
#include <endyn.h>

/**
 * @file
 * This header declares the functions that must be implemented by a FM.
 */

/*
 * Startup() is the entry point of the FM. 
 * 
 * The FM can perform the initialization and resource acquisition required by
 * the rest of its functions in this function.
 *
 * This function must perform its operations, and return immediately. The rest
 * of the system is blocked until the initialization is finished. If the adapter
 * is reset before the FM initialization is finished, the FM will be disabled
 * automatically.
 */
FM_RV Startup(void);

#endif /* INC_FM_H */

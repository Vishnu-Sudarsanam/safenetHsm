/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2004-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: hsmstate.h
 */
 /**
  * @file This file contains information about the state of the HSM.
  */
#ifndef INC_HSMSTATE_H
#define INC_HSMSTATE_H

#define INET_NAME_ADDRSTRLEN 32

/**
 * Possible states that the HSM can be in.
 */
typedef enum {
    /**
     * Power off state, with no key material in the HSM. Has been observed as an
     * explicit state during reset after firmware or FM update, or FM disable. */
    S_POWER_OFF_WITH_NO_KEYS = 0,

    /** The HSM is waiting for the tamper cause to be removed. */
    S_WAIT_ON_TAMPER = 1,

    /** Power off state, with key material stored in secure memory. Never
     * observed as an explicit state. */
    S_POWER_OFF_WITH_KEYS = 2,

    /** The HSM is in NON FIPS mode. */
    S_NONFIPS_MODE = 5,

    /** The HSM is halted due to a failure. */
    S_HALT = 6,

    /** The HSM is initializing, and performing POST (Power On Self Test). */
    S_POST = 7,

    /** The HSM is responding to tamper. */
    S_TAMPER_RESPOND = 8,

    /* The firmware is started, and the HSM is in FIPS mode. */
    S_FIPS_MODE = 9,

    /** The HSM has booted OK and is waiting for a C_Initialize. */
    S_WAIT_FOR_INIT = 10,

    /** The HSM does not have firmware loaded. Ready to process
     * boot block commands */
    S_BOOTCMD = 11,
    /*
     * The following two definitions relate to remote HSMs
     */
    S_HSM_ACCESSIBLE = 12,
    S_HSM_UNACCESSIBLE = 13,
    S_HSM_STATE_BL_ERASING = 14,

    S_HSM_STATE_BL_STARTED = 15,   // BL perfoming startup
    S_HSM_STATE_BL_COMMANDS = 16,  // BL full interactive mode - no FW - same as S_BOOTCMD
    S_HSM_STATE_BL_READY  = 17,    // BL limited interactive mode - FW ready

    S_HSM_STATE_HW_ERROR = 18,
    S_HSM_STATE_BL1_FATAL = 19,
    S_HSM_STATE_BL2_FATAL = 20,
    S_HSM_STATE_BOOTING   = 21,
    S_HSM_STATE_DMA_READY = 22,
    S_HSM_STATE_CONFIGURE = 23,

    /** The HSM is in one of the following three states: S_NONFIPS_MODE,
     * S_WAIT_FOR_INIT, or S_FIPS_MODE. */
    S_NORMAL_OPERATION = 0x8000uL,

    /* The HSM contains a Manufacturing Test Firmware, and it is started. */
    S_MTF_MODE = 0x8001uL
} HsmState_t;

#endif /* INC_HSMSTATE_H */

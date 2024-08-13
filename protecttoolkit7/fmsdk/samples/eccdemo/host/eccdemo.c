/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2023 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cryptoki.h>
#include <endyn.h>
#include <fmerr.h>
#include <md.h>

#include "eccdemo.h"

int main()
{
    MD_RV       mdrv = MDR_UNSUCCESSFUL;
    CK_RV       rv   = CKR_OK;
    MD_Buffer_t request[2];
    MD_Buffer_t reply[1];

    uint32_t recvLen      = 0,
             appState     = 0,
             originatorID = 0;
    uint8_t  adapter      = 0;
    uint16_t cmd          = ECC_DEMO_CMD;

    /** Initialize the message dispatch library */
    mdrv = MD_Initialize();
    if (mdrv != MDR_OK) {
        printf("MD_Initialize error %08x\n", mdrv);
        exit(EXIT_FAILURE);
    }

    /** Build send buffer. The structure of the buffer will depend on
     * the FM implementation.
     */
    cmd               = hton_short(cmd);
    request[0].pData  = (uint8_t *)&cmd;
    request[0].length = sizeof(uint16_t);

    /** The last MD_Buffer_t MUST be terminated in this fashion. - VERY IMPORTANT */
    request[1].pData  = NULL;
    request[1].length = 0;

    /** Terminate our receive buffer as per earlier comment - VERY IMPORTANT */
    reply[0].pData  = NULL;
    reply[0].length = 0;

    /** Send and receive our buffer via MD_SendReceive() */
    mdrv = MD_SendReceive(adapter,
                          originatorID,
                          ECCDEMO_FM_NUMBER,
                          request,
                          0,
                          reply,
                          &recvLen,
                          &appState);

    /* check if the message was sent to the FM OK */
    if (mdrv != MDR_OK) {
        printf("Failed to send message to FM - MD error 0x%x\n", mdrv);
    } else {
        /**
         * MD_SendReceive() returns MD_RV, which does not necessarily
         * mean that the FM operation was successful. The only way to
         * find out is the appState. This varible holds the value passed
         * by the FM in SVC_SendReply()
         */
        rv = appState;
        printf("Test result %s\n", rv == CKR_OK ? "PASS" : "FAIL");
    }

    /** Finalize the library. */
    MD_Finalize();

    return EXIT_SUCCESS;
}

/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: samples/cipherobj/host/stub_cipherobj.c
 */
#include <stdio.h>
#include <string.h>
#include <cryptoki.h>
#include <md.h>
#include <integers.h>
#include <csa8fm.h>
#include <endyn.h>

/** 
 * cipherobj program host stub
 */
#define RESERVED        0
#define MY_FM_NUMBER    0x100

/* Commands */
#define FMCMD_OAEP_ENC  0x0001
#define FMCMD_OAEP_DEC  0x0002


/** serialize arguments and send them to adapter */
int oaepenc(char   *id, 
                 uint16_t idLen,
                 uint8_t  *in, 
                 uint32_t inLen, 
                 uint8_t  *out, 
                 uint32_t *outLen) 
{
    MD_Buffer_t     request[6], /* this array must be big enough for all entries - below */
                    reply[2];   /* this array must be big enough for all entries - below */

    uint32_t recvLen      = 0, 
           appState     = 0,
           in_len       = 0,
           originatorID = 0;
    uint8_t adapter       = 0;
    uint16_t id_len       = 0;
    uint16_t cmd          = FMCMD_OAEP_ENC;
    MD_RV rv            = MDR_UNSUCCESSFUL;

    /** 
     * Build our send buffer. 
     * 
     * The structure of the buffer will depend on the implementation 
     * of the FM. The format is similar to the older fmhost format with
     * the exception of the last buffer. See comment further down the code.
     */
    cmd = (uint16_t)hton_short(cmd);
    request[0].pData = (uint8_t *)&cmd;
    request[0].length = sizeof(uint16_t);

    id_len = (uint16_t)hton_short(idLen);
    request[1].pData = (uint8_t *)&id_len;
    request[1].length = sizeof(uint16_t); 

    request[2].pData = (unsigned char*) id;
    request[2].length = idLen; 

    in_len = hton_long(inLen);
    request[3].pData = (uint8_t *)&in_len;
    request[3].length = sizeof(uint32_t);

    request[4].pData = in;
    request[4].length = inLen;

    /** The last MD_Buffer_t MUST be terminated in this fashion - VERY IMPORTANT */
    request[5].pData = NULL;
    request[5].length = 0;

    /** 
     * We must allocate enough receive buffer otherwise we will receive 
     * incomplete data.
     */
    reply[0].pData  = out;
    reply[0].length = *outLen;

    /** Terminate our receive buffer as per earlier comment - VERY IMPORTANT */
    reply[1].pData = NULL;
    reply[1].length = 0;

    recvLen = 0; appState = 0;

    /** Send and receive our buffer via MD_SendReceive() */
    rv = MD_SendReceive( adapter, 
                         originatorID, 
                         MY_FM_NUMBER,
                         request, 
                         RESERVED,
                         reply, 
                         &recvLen,          
                         &appState);

    if (rv != MDR_OK) 
    {
        *outLen = 0;        
        /* convert MD error codes to the error name space returned by the application */
        /* In this case just convert all MD errors to Cryptoki error code.           */
        return CKR_GENERAL_ERROR;
    }
    else 
    {
        /** recvLen indicates how many bytes are received */
          *outLen = (unsigned int) recvLen;
    }

    /** 
     * MD_SendReceive() only returns MD_RV. 
     * If zero it means the message got to the HSM and got back.
     * However, it does not guarantee that FM operation was successful. Only way to 
     * find out is the appState. This variable holds whatever
     * value was passed by FM in SVC_SendReply() 
     */
    return appState;
};


/** serialize arguments and send them to adapter */
int oaepdec(char   *id, 
                 uint16_t idLen,
                 uint8_t  *in, 
                 uint32_t inLen, 
                 uint8_t  *out, 
                 uint32_t *outLen) 
{
    MD_Buffer_t     request[6], /* this array must be big enough for all entries - below */
                    reply[2];   /* this array must be big enough for all entries - below */

    uint32_t recvLen      = 0, 
           appState     = 0,
           in_len       = 0,
           originatorID = 0;
    uint8_t adapter       = 0;
    uint16_t id_len       = 0;
    uint16_t cmd          = FMCMD_OAEP_DEC;
    MD_RV rv            = MDR_UNSUCCESSFUL;

    /** 
     * Build our send buffer. 
     * 
     * The structure of the buffer will depend on the implementation 
     * of the FM. The format is similar to the older fmhost format with
     * the exception of the last buffer. See comment further down the code.
     */
    cmd = (uint16_t)hton_short(cmd);
    request[0].pData = (uint8_t *)&cmd;
    request[0].length = sizeof(uint16_t);

    id_len = (uint16_t)hton_short(idLen);
    request[1].pData = (uint8_t *)&id_len;
    request[1].length = sizeof(uint16_t); 

    request[2].pData = (unsigned char*) id;
    request[2].length = idLen; 

    in_len = hton_long(inLen);
    request[3].pData = (uint8_t *)&in_len;
    request[3].length = sizeof(uint32_t);

    request[4].pData = in;
    request[4].length = inLen;

    /** The last MD_Buffer_t MUST be terminated in this fashion - VERY IMPORTANT */
    request[5].pData = NULL;
    request[5].length = 0;

    /** 
     * We must allocate enough receive buffer otherwise we will receive 
     * incomplete data.
     */
    reply[0].pData  = out;
    reply[0].length = *outLen;

    /** Terminate our receive buffer as per earlier comment - VERY IMPORTANT */
    reply[1].pData = NULL;
    reply[1].length = 0;

    recvLen = 0; appState = 0;

    /** Send and receive our buffer via MD_SendReceive() */
    rv = MD_SendReceive( adapter, 
                         originatorID, 
                         MY_FM_NUMBER,
                         request, 
                         RESERVED,
                         reply, 
                         &recvLen,          
                         &appState);

    if (rv != MDR_OK) 
    {
        *outLen = 0;        
        /* convert MD error codes to the error name space returned by the application */
        /* In this case just convert all MD errors to Cryptoki error code.           */
        return CKR_GENERAL_ERROR;
    }
    else 
    {
        /** recvLen indicates how many bytes are received */
          *outLen = (unsigned int) recvLen;
    }

    /** 
     * MD_SendReceive() only returns MD_RV. 
     * If zero it means the message got to the HSM and got back.
     * However, it does not guarantee that FM operation was successful. Only way to 
     * find out is the appState. This variable holds whatever
     * value was passed by FM in SVC_SendReply() 
     */
    return appState;
};

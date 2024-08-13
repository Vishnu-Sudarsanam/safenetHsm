/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: samples/smfs/host/stub_smfs.c
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <csa8fm.h>
#include <endyn.h>
#include <md.h>

/** 
 * cipherobj program host stub
 */

#define FMCMD_WRITE_FILE     0x0001 /* Create AND write the file */
#define FMCMD_READ_FILE      0x0002
#define FMCMD_DELETE_FILE    0x0003
#define RESERVED             0
#define MY_FM_NUMBER         0x500

/** serialize arguments and send them to adapter */
int DoSMFSFileIO(char   *id, 
                 uint16_t idLen,
                 uint8_t  *in, 
                 uint32_t inLen, 
                 uint8_t  *out, 
                 uint32_t *outLen) 
{
    MD_Buffer_t     request[6], 
                    reply[2];

    uint32_t recvLen      = 0, 
           appState     = 0,
           in_len       = 0,
           originatorID = 0;
    uint8_t adapter       = 0;
    uint16_t id_len       = 0;
    uint16_t cmd          = FMCMD_WRITE_FILE;
    MD_RV rv            = MDR_UNSUCCESSFUL;

    /** 
     * Build our send buffer. 
     * 
     * The structure of the buffer will depend on the implementation 
     * of the FM. The format is similar to the older fmhost format with
     * the exception of the last buffer. See comment further down the code.
     */

    /* First command - write file */
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

    /** Terminate our receive buffer as per earlier comment */
    reply[0].pData = NULL;
    reply[0].length = 0;

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
        return rv;
    }

    if (appState != 0)
    {
        printf("Failed to create/write the file. Error = %#x\n", appState);
    }

    printf("Wrote to %s : %s\n", id, in);

    /* Second command - read the data back from the file */
    cmd = FMCMD_READ_FILE;
    cmd = (uint16_t)hton_short(cmd);
    request[0].pData = (uint8_t *)&cmd;
    request[0].length = sizeof(uint16_t);

    /* The request 1 and 2 structures are already set up from the command 
       above - they hold the length of the filename and the filename, 
       respectively. The next 2 structures hold the data to write to the
       file. Since we are not writing to the file this time, terminate
       the array after the filename */       
    request[3].pData = NULL;
    request[3].length = 0;

    reply[0].pData  = out;
    if (inLen <= *outLen)
    {
        reply[0].length = inLen;
    }
    else 
    {
        reply[0].length = *outLen;
    }

    reply[1].pData  = NULL;
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
        return rv;
    }

    if (appState != 0)
    {
        printf("Failed to read the file. Error = %#x\n", appState);
    }

    /* Print the contents of the file - Null terminate the buffer first */
    out[recvLen] = '\0';
    printf("Read %d bytes from %s : %s\n", recvLen, id, out);

    /* Third command - delete the file */
    cmd = FMCMD_DELETE_FILE;
    cmd = (uint16_t)hton_short(cmd);
    request[0].pData = (uint8_t *)&cmd;
    request[0].length = sizeof(uint16_t);

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
    if (appState != 0)
    {
        printf("Failed to delete the file. Error = %#x\n", appState);
    }

    if (rv != MDR_OK)
    {
        return rv;
    }

    printf("Deleted %s\n", id);

    if (appState != 0)
    {
        printf("Failed to delete the file. Error = %#x\n", appState);
    }

    /** 
     * MD_SendReceive() only returns MD_RV. However, it does not 
     * guarantee that FM operation was successful. Only way to 
     * find out is the appState. This variable holds whatever
     * value was passed by FM in SVC_SendReply() 
     */
    return appState;
};

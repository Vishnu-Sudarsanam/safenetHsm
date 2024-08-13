/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: samples/smfs/host/smfstest.c
 */

/**
 * @file
 * SMFS FM program : host side test code
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cryptoki.h>
#include <fmerr.h>
#include <md.h>

#define BUFF_SIZE	128
#define HASH_SIZE   20

int DoSMFSFileIO(char *, uint16_t ,uint8_t  *, uint32_t , uint8_t  *, uint32_t *); 

int 
main() 
{
    char  Id[]    = "/TestFile";
    uint8_t InBuf[] = "ABCDEFGHJIKLMNOPQRSTUVWXYZ"; 

    uint8_t  OutBuf[BUFF_SIZE];
    uint32_t OutLen = BUFF_SIZE;
    uint32_t InLen  = 0;     
    uint16_t IdLen  = 0;

    MD_RV rv = MDR_UNSUCCESSFUL;

    /** Initialize the message dispatch library */
    rv = MD_Initialize();
    if(rv != MDR_OK)
    {
        printf("MD_Initialize %x\n", rv);
        exit(1);
    }

    InLen = strlen((char*)InBuf);
    IdLen = (uint16_t)strlen(Id);

    /** 
      * Perform RSA encoding. 
      * 
      * This function will send our data to the HSM. The medium
      * for sending data to FM in HSM is MD_SendReceive. See stub_smfs.c
      */
	rv = DoSMFSFileIO( Id, 
                       IdLen,
                       InBuf,
                       InLen,
                       OutBuf,
                       &OutLen);

    if(rv != MDR_OK) 
    {
        printf("DoSMFSFileIO failed with error code: 0x%x\n", rv);
        exit(1);
    }

    /** Finalize the library. */
    MD_Finalize();

    exit(0);
}

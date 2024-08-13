/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2021 Thales. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: samples/cipherobj/host/oaepciptest.c
 */

/** 
 * @file
 * CIPHEROBJ FM program : host side test code
 * 
 * Before executing this FM/Host application, please generate a RSA 2048-bit keypair with label "RSA2048" on slot 0 with the attributes 'ED'.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fmerr.h>
#include <cryptoki.h>
#include <md.h>
#include <integers.h>

#define BUFF_SIZE	256

int oaepenc(char *, uint16_t ,uint8_t  *, uint32_t , uint8_t  *, uint32_t *); 
int oaepdec(char *, uint16_t ,uint8_t  *, uint32_t , uint8_t  *, uint32_t *); 

int main() 
{
    char  Id[]    = "RSA2048";
    uint8_t InBuf[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}; 

    uint8_t OutBufDec[BUFF_SIZE];
    uint32_t OutBufDecLen = BUFF_SIZE;

    uint8_t  OutBuf[BUFF_SIZE];
    uint32_t OutLen = BUFF_SIZE;
    uint32_t i = 0,
           InLen  = 0;     
    uint16_t IdLen  = 0;
    
    MD_RV rv = MDR_UNSUCCESSFUL;

    /** Initialize the message dispatch library */
    rv = MD_Initialize();
    if(rv != MDR_OK)
    {
        printf("MD_Initialize error 0x%x\n", rv);
        exit(1);
    }

    InLen = sizeof(InBuf);
    IdLen = (uint16_t)strlen(Id);

    rv = oaepenc( Id, 
                  IdLen,
                  InBuf,
                  InLen,
                  OutBuf,
                  &OutLen);
    if(rv != MDR_OK) 
    {
        printf("Failed with error code: 0x%x\n", rv);
        if ( rv == CKR_ARGUMENTS_BAD )
        {
            printf("Have you created 2048-bit RSA keypair in Slot zero labelled 'RSA2048'?\n");
        }
        exit(1);
    }



    printf("\nCiphertext length: %d"
           "\n------ Encrypted Text -----------\n", OutLen);
    for(i=0; i<OutLen; printf("%02x",(unsigned char)OutBuf[i++]) ); 
    printf("\n----------------------------\n");

	rv = oaepdec( Id, 
                  IdLen,
                  OutBuf,
                  OutLen,
                  OutBufDec,
                  &OutBufDecLen);
    if(rv != MDR_OK) 
    {
        printf("Failed with error code: 0x%x\n", rv);
        if ( rv == CKR_ARGUMENTS_BAD )
        {
            printf("Have you created 2048-bit RSA keypair in Slot zero labelled 'RSA2048'?\n");
        }
        exit(1);
    }

    printf("Decrypted Text length: %d"
           "\n------ Decrypted Text -----------\n", OutBufDecLen);
    for(i=0; i<OutBufDecLen; printf("%02x",(unsigned char)OutBufDec[i++]) ); 
    printf("\n----------------------------\n");

    MD_Finalize();

    exit(0);
}

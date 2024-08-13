/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: samples/cipherobj/host/cipherobjtest.c
 */

/** 
 * @file
 * CIPHEROBJ FM program : host side test code
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

int Sha1_Des3Enc(char *, uint16_t ,uint8_t  *, uint32_t , uint8_t  *, uint32_t *); 

int 
main() 
{
    char  Id[]    = "TEST_DES3_KEY";
    /** The FM does not perform padding of the data so we ensure the message 
        is a multiple of 8 bytes (for DES3 encryption) */
    uint8_t InBuf[] = "Test Message...."; 

    uint8_t  OutBuf[BUFF_SIZE];
    uint32_t OutLen = BUFF_SIZE;
    uint32_t i      = 0,
           InLen  = 0;     
    uint16_t IdLen  = 0;
    uint8_t hash[HASH_SIZE];

    MD_RV rv = MDR_UNSUCCESSFUL;

    /** Initialize the message dispatch library */
    rv = MD_Initialize();
    if(rv != MDR_OK)
    {
        printf("MD_Initialize error 0x%x\n", rv);
        exit(1);
    }

    InLen = strlen((char*)InBuf);
    IdLen = (uint16_t)strlen(Id);

    /** 
      * Perform RSA encoding. 
      * 
      * This function will send our plain text to the HSM. The medium
      * for sending data to FM in HSM is MD_SendReceive. See stub_cipherobj.c
      */
	rv = Sha1_Des3Enc( Id, 
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
            printf("Have you created a DES key in Slot zero labelled 'TEST_DES3_KEY'?\n");
        }
        exit(1);
    }

    /** Finalize the library. */
    MD_Finalize();

    /** The returned buffer contains a SHA-1 hash of the plaintext followed 
        by the DES3 encrypted plaintext */

    /** Extract the hash - SHA_1 so we know it's a fixed size (20 bytes) */
    memcpy(hash, OutBuf, HASH_SIZE);

    /** Print the hash value */
    printf("\nHash length: %d"
           "\n------ Hash of plaintext -----------\n", HASH_SIZE);
    for(i=0; i<HASH_SIZE; printf("%02x",(unsigned char)hash[i++]) ); 
    printf("\n------------------------------------\n");

    /** Print the cipher text */
    printf("\nCiphertext length: %d"
           "\n------ Ciphertext -----------\n", OutLen - HASH_SIZE);
    for(i=0; i<OutLen-HASH_SIZE; printf("%02x",(unsigned char)OutBuf[HASH_SIZE + i++]) ); 
    printf("\n----------------------------\n");

    exit(0);
}

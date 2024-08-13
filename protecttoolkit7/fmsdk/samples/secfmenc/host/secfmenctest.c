/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2016 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: samples/secfmenc/host/secfmenctest.c
 */

/**
 * @file
 * secfmenctest FM test program : This sample demonstrates the use of extension function FMSC_SendReceive() introduced in cryptoki library
 * to send and receive response from a custom FM. Before running this test make sure you have created a 1024-bit rsa key with label "TEST_RSA_KEY" 
 * and DES3 key with label "TEST_DES3_KEY" on slot 0.
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cryptoki.h>
#include <ctfext.h>
#include <ctvdef.h>

#define FMCMD_RSA_ENC	0x0C		/* FM command for RSA encryption */
#define FMCMD_DES3_ENC	0x0D		/* FM command for TDES encryption */
#define MY_FM_NUMBER	0x400		/* FM_ID */
#define BUFF_SIZE		256			/* Buffer to hold output. make sure its enough for the type of cipher/key being used. */


CK_RV fmhostcall(char *test, char *in);
void printError(char *api, CK_RV rv);
void Usage(void);


int main(int argc, char *argv[])
{
	CK_RV rv;
	char *t;
	int loop = 1;
	int count;

	char *clrTxt = "Test Message";

	if(argc < 2 || argc > 3)
	{
		Usage();
	}
	else 
	{
		if(argc == 3)
		{
			loop = atoi(argv[2]);
		}

		if(strcmp("rsa", argv[1]) == 0)
		{
			t = "rsa";
		}
		else if(strcmp("tdes", argv[1]) == 0)
		{
			t = "tdes";
		}
		else
		{
			printf("Unsupported algorithm specified\n");
			exit(0);
		}
	}

	rv = C_Initialize(NULL);

	for(count = 0; count<loop; count++)
	{
		rv = fmhostcall(t, clrTxt);
	}

	rv = C_Finalize(NULL);

	return 0;

}

CK_RV fmhostcall(char *test, char *in)
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_SLOT_ID slot = 0;
	uint32_t fmstat;
	CK_ULONG recvlen;
	char *keyId;
	uint8_t keyIdlen;
	CK_BYTE cmd;
	uint8_t inlen;
	CK_USHORT fmId = MY_FM_NUMBER;

	CK_ULONG requestlen, responselen;
	CK_BYTE_PTR request, response;

	int k;

	if(strcmp("rsa", test) == 0)
	{
		cmd = FMCMD_RSA_ENC;
		keyId = "TEST_RSA_KEY";
	}
	else if(strcmp("tdes", test) == 0)
	{
		cmd = FMCMD_DES3_ENC;
		keyId = "TEST_DES3_KEY";
	}

	keyIdlen = (uint8_t) strlen(keyId);
	inlen = (uint8_t) strlen(in);
	
	requestlen = (CK_ULONG)(sizeof(CK_BYTE) + keyIdlen + inlen + 2*sizeof(uint8_t));
	request = (CK_BYTE_PTR)malloc(requestlen);
    
    responselen = BUFF_SIZE;
	response = (CK_BYTE_PTR) malloc(responselen);

	memcpy(request , &cmd, sizeof(CK_BYTE));
	
	memcpy(request + sizeof(CK_BYTE), &keyIdlen, sizeof(uint8_t));
	memcpy(request + sizeof(CK_BYTE) + sizeof(uint8_t), keyId, keyIdlen);

	memcpy(request + sizeof(uint8_t) + sizeof(CK_BYTE) + keyIdlen, &inlen, sizeof(uint8_t));
	memcpy(request + 2 * sizeof(uint8_t) + sizeof(CK_BYTE) + keyIdlen, in, inlen);

	printf("REQUEST[%d]: ", (int)requestlen);
	for(k=0;k<(int)requestlen;k++)
		printf("%02X",*(request+k));
	printf("\n");

	if((rv = C_OpenSession(slot, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL, &hSession)) != CKR_OK) 
	{
		printError("C_OpenSession", rv);
		goto end;
	}

	if((rv =  FMSC_SendReceive(hSession, fmId, request, requestlen, response, responselen, &recvlen, &fmstat)) != CKR_OK)
	{
		printError("FMSC_SendReceive", rv);
		goto end;
	}

	if(fmstat == CKR_OK)
	{
		printf("RESPONSE[%d]: ", (int)recvlen);
		for(k=0;k<(int)recvlen;k++)
			printf("%02X", *(response+k));
		printf("\n");
	}
	else
	{
		printf("FM returned: %02X\n", fmstat);
	}

end:
	if(hSession) C_CloseSession(hSession);
	if(request) free(request);
	if(response) free(response);
	return rv;
}


void printError(char *api, CK_RV rv)
{
	printf("Error in %s: %02X\n", api, (unsigned int)rv);
}

void Usage(void)
{
	printf("\nfmsecenc_test.exe <alg> [iteration] - On Windows\n");
	printf("./secfmenctest <alg> [iteration] - On all Unix based Platforms\n\n");
	printf("alg = tdes or rsa\niteration = count (numeric)\n\n");
	exit(0);
}


/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2021 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 * Author: Sorokine, Joseph
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <csa8fm.h>
#include <endyn.h>
#include <fmerr.h>
#include <hex2bin.h>
#include <md.h>

#include "usb.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#include <getopt.h>
#endif

#define MY_FM_NUMBER 0x700

#define CEIL(x, d) (((x % d != 0)? 1: 0) + x / d)

#define SET_BUFF_SIZE(msgSize) \
	(CEIL(msgSize * 2, 32) * 32 + 32)

static void Usage(void)
{
    printf("Options: -a <adapter>,\n         -n <FS_label>: Create new FS\n");
    printf("         -i: Get FS info,\n");
    printf("         -w <file_name>: Write file,\n");
    printf("         -r : Read from FS,\n");
    printf("         -p <file_name>: Append data to FS (to be developed),\n");
    printf("         -d: Destroy existing FS,\n");
    printf("         -h: Print this  help,\n");
    printf("         -t: Test data exchange between host and FM.\n");
}

static int ParseReplyBuffer (uint16_t cmd, uint8_t *replyBuffer, uint32_t replyBufferLen, uint32_t *status, char *label, uint8_t *data, uint32_t *dataLen);

static int doFmUsbSendReceive(
		int adapter,
		uint16_t cmd,
		char *label,
		uint32_t labelLen,
		uint8_t *bufReq,
		uint32_t bufReqLen,
		uint8_t *bufResp,
		uint32_t *bufRespLen)
{
	MD_RV rv;

    MD_Buffer_t request[6]   = {{0}};
    MD_Buffer_t reply[4]     = {{0}};
	uint32_t originatorID = 0;
	uint32_t recvLen = 0;
	uint32_t appState = 0;
	uint16_t localCmd = cmd;
	uint32_t localLabelLen;
	uint32_t localDataLen;

	/* Prepare the request */
	localCmd = hton_short(cmd);
    request[0].pData = (uint8_t*)&localCmd;
    request[0].length = sizeof(localCmd);

    switch(cmd) {
    case FMUSB_DATA_EXCHANGE_TEST:
	    //To HSM:   <cmd><labelLen><label><dataLen><data>
	    //From HSM: <statusLen><status><dataLen><data>
    	localLabelLen = (uint32_t)hton_long(labelLen);
        request[1].pData = (uint8_t *)&localLabelLen;
        request[1].length = sizeof(localLabelLen);
		//label:
        request[2].pData = (uint8_t *)label;
        request[2].length = labelLen;
		//
        localDataLen = hton_long(bufReqLen);
        request[3].pData = (uint8_t *)&localDataLen;
        request[3].length = sizeof(localDataLen);
		//Req buffer:
        request[4].pData = (uint8_t *)bufReq;
        request[4].length = bufReqLen;
		//
        /** Terminate our receive buffer as per earlier comment - VERY IMPORTANT */
        request[5].pData = NULL;
        request[5].length = 0;
	    /**
	     * We must allocate enough receive buffer otherwise we will receive
	     * incomplete data.
	     */
	    reply[0].pData  = bufResp;
	    reply[0].length = *bufRespLen;
	    //
	    /** Terminate our receive buffer as per earlier comment - VERY IMPORTANT */
	    reply[1].pData = NULL;
	    reply[1].length = 0;
    	break;
    case FMUSB_NEW:
    case FMUSB_DESTROY:
		//To HSM:   <cmd><labelLen><label>
	    //From HSM: <statusLen><status>
    	localLabelLen = (uint32_t)hton_long(labelLen);
        request[1].pData = (uint8_t *)&localLabelLen;
        request[1].length = sizeof(localLabelLen);
        //
        request[2].pData = (uint8_t*)label;
        request[2].length = labelLen;
        /** Terminate our receive buffer as per earlier comment - VERY IMPORTANT */
        request[3].pData = NULL;
        request[3].length = 0;
        //Reply buffer:
        /**
         * We must allocate enough receive buffer otherwise we will receive
         * incomplete data.
         */
        reply[0].pData  = bufResp;
        reply[0].length = *bufRespLen;
        /** Terminate our receive buffer as per earlier comment - VERY IMPORTANT */
        reply[1].pData = NULL;
        reply[1].length = 0;
    	break;
    case FMUSB_WRITE:
    case FMUSB_APPEND:
		//To HSM:   <cmd><labelLen><label><dataLen><data>
	    //From HSM: <statusLen><status>
        localLabelLen = (uint32_t)hton_long(labelLen);
        request[1].pData = (uint8_t *)&localLabelLen;
        request[1].length = sizeof(localLabelLen);
        //
        request[2].pData = (uint8_t*)label;
        request[2].length = labelLen;
        //
        localDataLen = (uint32_t)hton_long(bufReqLen);
        request[3].pData = (uint8_t *)&localDataLen;
        request[3].length = sizeof(localDataLen);
        //
        request[4].pData = (uint8_t*)bufReq;
        request[4].length = bufReqLen;
        /** The last MD_Buffer_t MUST be terminated in this fashion. - VERY IMPORTANT */
        request[5].pData = NULL;
        request[5].length = 0;
        //Reply Buffer:
        reply[0].pData  = bufResp;
        reply[0].length = *bufRespLen;
        /** Terminate our receive buffer as per earlier comment - VERY IMPORTANT */
        reply[1].pData = NULL;
        reply[1].length = 0;
    	break;
    case FMUSB_READ:
	    //To HSM:   <cmd><labelLen><label>
	    //From HSM: <statusLen><status><dataLen><data>
	    localLabelLen = (uint32_t)hton_long(labelLen);
	    request[1].pData = (uint8_t *)&localLabelLen;
	    request[1].length = sizeof(localLabelLen);
	    //
	    request[2].pData = (uint8_t*)label;
	    request[2].length = labelLen;
	    request[3].pData = NULL;
	    request[3].length = 0;
	    /**
	     * We must allocate enough receive buffer otherwise we will receive
	     * incomplete data.
	     */
		//Return: <statusLen><status><dataLen><data>
	    reply[0].pData  = bufResp;//if bufResp == NULL, only bufRespLen is returned.
	    reply[0].length = *bufRespLen;
	    //
	    /** Terminate our receive buffer as per earlier comment - VERY IMPORTANT */
	    reply[1].pData = NULL;
	    reply[1].length = 0;
    	break;
    case FMUSB_INFO:
        /** The last MD_Buffer_t MUST be terminated in this fashion. - VERY IMPORTANT */
        request[1].pData = NULL;
        request[1].length = 0;
        /**
         * We must allocate enough receive buffer otherwise we will receive
         * incomplete data.
         */
        //Reply buffer consists from the following fields:
        //<statusLen><status><labelLen><label><FsDataLen>
        reply[0].pData  = bufResp;
        reply[0].length = *bufRespLen;
        /** Terminate our receive buffer as per earlier comment - VERY IMPORTANT */
        reply[1].pData = NULL;
        reply[1].length = 0;
    	break;
    }//switch
    /** Send and receive our buffer via MD_SendReceive() */
    rv = MD_SendReceive( adapter,
                         originatorID,
                         MY_FM_NUMBER,
                         request,
                         RESERVED,
                         reply,
                         &recvLen,
                         &appState);
	printf("MD_SendReceive(). rv=0x%08x, recvLen=0x%x\n", rv, recvLen);
    if (rv != MDR_OK)
        *bufRespLen = 0;
    else
    {
		memdump("USB FM returns:", bufResp, recvLen);
        /** recvLen indicates how many bytes are received */
        *bufRespLen = (uint32_t)recvLen;
    }

    /**
     * MD_SendReceive() only return MD_RV. However, it does not
     * guanrentee that FM operation was successful. Only way to
     * find out is the appState. This varible holds whatever
     * value was passed by FM in SVC_SendReply()
     */
    return appState;
}

int main(int argc, char* argv[])
{
    int         rv = 0;
    MD_RV       mdRv;
    /*
     * Getopt options:
     * a - adapter
     * n <FS_label> - New
     * i - Info
     * w <file_name> - Write,
     * r <size> - Read
     * p <file_name> - Append
     * d - Destroy
     * h - Help
     * t <file_name> - test data exchange
     */
    char *options = "a:n:iw:rp:dht:";
	int opt;
    //
    uint16_t cmd = 0;
	char* fileName = NULL;
    FILE *inputFile;
    int inputFileSize = 0;
    uint8_t *inputBuffer = NULL;
    uint8_t *msg = NULL;
    int adapter = 0;
    char label[MAX_FS_LABEL_LEN + 1] = "";
    uint8_t *buffer = NULL;
    uint32_t status = 0;
    uint32_t replyLen = 0;
    int i;
    uint8_t *replyBuf = NULL;
    uint32_t dataLen;
	uint8_t *data = NULL;

	while ((opt = getopt(argc, argv, options)) != -1) {
		switch (opt) {
		case 't':
		 cmd = FMUSB_DATA_EXCHANGE_TEST;
		 fileName = optarg;//contains pointer to the argument(just use it)
		 break;
		case 'a':
	     //Slot:
		 adapter = atoi(optarg);
		 break;
		case 'n':
		 //New FS:
		   cmd = FMUSB_NEW;
		   strcpy(label, optarg);
		 break;
		case 'w':
		 cmd = FMUSB_WRITE;
		 fileName = optarg;//contains pointer to the argument(just use it)
		 break;
		case 'r':
		 cmd = FMUSB_READ;
		 break;
		case 'h':
		   Usage();
		   return 0;
		 break;
		case 'p':
		 cmd = FMUSB_APPEND;
		 fileName = optarg;
		 break;
		case 'd':
		 cmd = FMUSB_DESTROY;
         break;
		case 'i':
		 cmd = FMUSB_INFO;
		   break;
		default:
		 Usage();
		 break;
		}//switch
	}//for

	/*
	 * Get data to be written/appended:
	 */
	 if (cmd == FMUSB_WRITE || cmd == FMUSB_APPEND || cmd == FMUSB_DATA_EXCHANGE_TEST) {
		if ((inputFile = fopen(fileName, "r")) == NULL) {
		 Usage();
		 return -1;
		}
		/*
		 * Get file size:
		 */
		fseek(inputFile, 0, SEEK_END);
		inputFileSize = ftell(inputFile);
		printf("inputFileSize=%d\n", inputFileSize);
		rewind(inputFile);
		printf("Input file size: %d\n", inputFileSize);
		/*
		 * Read file into memory:
		 */
		if ((inputBuffer = malloc(inputFileSize + 20)) == NULL) {
			printf("Input file memory allocation error\n");
			fclose(inputFile);
			return 2;
		}
		for (i = 0; i < inputFileSize; i++) {
			if( 1 != fread(inputBuffer + i, 1, 1, inputFile))
				break;
		}
		fclose(inputFile);
		msg = inputBuffer;
	 }
    mdRv = MD_Initialize();
    if (mdRv != MDR_OK) {
        printf("ERROR: MD_Initialize() returned %d.\n", mdRv);
        exit(0);
    }
    switch (cmd) {
    case FMUSB_DATA_EXCHANGE_TEST:
	{
		//To HSM:   <cmd><dataLen><data>
		//From HSM: <statusLen><status><dataLen><data>
		//char msg[] = "String to be sent";
		//char buf[128] = "";
		uint8_t *buf = NULL;
		char label[MAX_FS_LABEL_LEN] = "test****";

		printf("Entering FMUSB_DATA_EXCHANGE_TEST...\n");
		replyLen = SET_BUFF_SIZE(inputFileSize);
		buf = calloc(replyLen, 1);
		rv = doFmUsbSendReceive(adapter,
								cmd,
								label, strlen(label),
								msg, inputFileSize,
								buf,
								&replyLen);
		if  (rv != 0) {
			goto done;
		}
		//allocate memory for data:
		if ((data = malloc(replyLen)) == NULL) {
			printf("data allocation error\n");
			return -1;
		}
		ParseReplyBuffer(cmd, buf, replyLen, &status, NULL, data, &dataLen);
		printf("FMUSB_DATA_EXCHANGE_TEST: status =0x%08x\n", status);
	}
	break;
    case FMUSB_NEW:
	{
		//To HSM:   <cmd><labelLen><label>
	    //From HSM: <statusLen><status>
		uint8_t replyBuf[32];//OK. Reply buffer must be larger of total ret data saze by (32 - sizeof(uint32_t) * 2) = 24!
		replyLen = sizeof(replyBuf);
    	rv = doFmUsbSendReceive(adapter, FMUSB_NEW, label, strlen(label) + 1, NULL, 0, replyBuf, &replyLen);
		if  (rv != 0) {
			goto done;
		}
		ParseReplyBuffer(cmd, replyBuf, replyLen, &status, NULL, data, &dataLen);
		printf("FMUSB_NEW: status =0x%08x\n", status);
    	break;
	}
    case FMUSB_WRITE:
	{
		//To HSM:   <cmd><labelLen><label><dataLen><data>
	    //From HSM: <statusLen><status>
		char label[MAX_FS_LABEL_LEN] = "";
		uint8_t replyBuf[32];//OK. Reply buffer must be larger of total ret data saze by (32 - sizeof(uint32_t) * 2) = 24!
		replyLen = sizeof(replyBuf);
		rv = doFmUsbSendReceive(adapter, FMUSB_WRITE, label, strlen(label), msg, inputFileSize, replyBuf, &replyLen);
		if  (rv != 0) {
			goto done;
		}
		ParseReplyBuffer(cmd, replyBuf, replyLen, &status, NULL, NULL, &dataLen);
		printf("FMUSB_WRITE: status =0x%08x\n", status);
    	break;
	}
    case FMUSB_READ:
	{
		char label[MAX_FS_LABEL_LEN] = "";
		//FMUSB_READ Return: <statusLen><status><dataLen><data>
		replyLen = SET_BUFF_SIZE(sizeof(uint32_t) * 4 + MAX_FS_LABEL_LEN);
		if ((replyBuf = calloc(replyLen, 1)) == NULL) {
    		printf("Memory allocation error\n");
    		goto done;
    	}
    	rv = doFmUsbSendReceive(adapter, FMUSB_INFO, label, strlen(label), NULL, 0, replyBuf, &replyLen);
		if  (rv != 0) {
			goto done;
		}
		ParseReplyBuffer(FMUSB_INFO, replyBuf, replyLen, &status, label, data, &dataLen);
		if (replyBuf) {
			free(replyBuf);
			replyBuf = NULL;
		}
    	//Memory allocation:
		replyLen = SET_BUFF_SIZE(dataLen);
    	if ((replyBuf = calloc(replyLen, 1)) == NULL) {
    		printf("Memory allocation error\n");
    		goto done;
    	}
    	rv = doFmUsbSendReceive(adapter, FMUSB_READ, label, 0, NULL, 0, replyBuf, &replyLen);
		if  (rv != 0) {
			goto done;
		}
    	if ((data = calloc(replyLen, 1)) == NULL) {
    		printf("Memory allocation error\n");
    		goto done;
    	}
		ParseReplyBuffer(FMUSB_READ, replyBuf, replyLen, &status, NULL, data, &dataLen);
    	//Parse the following reply buffer fileds:<status><FsDataLen><FsData>
    	printf("status=0x%08x, FS Data len=%d\n", status, dataLen);
    	memdump("Received:", data, dataLen);
		if (data) {
			free(data);
			data = NULL;
		}
    	break;
	}
    case FMUSB_DESTROY:
	{
		//To HSM:   <cmd><labelLen><label>
	    //From HSM: <statusLen><status>
		char label[MAX_FS_LABEL_LEN] = "";
		uint8_t replyBuf[SET_BUFF_SIZE(sizeof(uint8_t) * 2)];
		replyLen = sizeof(replyBuf);
    	rv = doFmUsbSendReceive(adapter, FMUSB_DESTROY, label, strlen(label), NULL, 0, replyBuf, &replyLen);
		if  (rv != 0) {
			goto done;
		}
		ParseReplyBuffer(cmd, replyBuf, replyLen, &status, NULL, NULL, &dataLen);
		printf("FMUSB_DESTROY: status =0x%08x\n", status);
    	break;
	}
    case FMUSB_INFO:
	{
        //Reply buffer consists from the following fields:
        //<statusLen><status><labelLen><label><FsDataLen>
		char label[MAX_FS_LABEL_LEN] = {0};
		uint8_t replyBuf[SET_BUFF_SIZE(sizeof(uint32_t) * 4 + MAX_FS_LABEL_LEN )];

		replyLen = sizeof(replyBuf);
    	rv = doFmUsbSendReceive(adapter, FMUSB_INFO, label, strlen(label), NULL, 0, replyBuf, &replyLen);
		if  (rv != 0) {
			printf("Something wrong. rv=0x%08x\n", rv);
			goto done;
		}
		ParseReplyBuffer(cmd, replyBuf, replyLen, &status, label, NULL, &dataLen);
    	//Parse the following reply buffer fields: <labelLen><label><FsDataLen>
    	printf("status=0x%08x, FS Label=%s, FS data size=0x%x\n", status, label, dataLen);
    	break;
	}
    default:
    	printf("Command unsupported(%d)\n", cmd);
    	return -1;
	}//switch

done:
	printf("Return code=0x%08x, USB status=0x%x\n", rv, status);
	if (buffer) free(buffer);
	if (replyBuf) free(replyBuf);
    MD_Finalize();

    return rv;
}

static int ParseReplyBuffer (uint16_t cmd, uint8_t *replyBuffer, uint32_t replyBufferLen, uint32_t *status, char *label, uint8_t *data, uint32_t *dataLen)
{
	uint32_t labelLen = 0;
	int offset = 0;

	switch (cmd) {
		case FMUSB_DATA_EXCHANGE_TEST:
			//From HSM: <statusLen><status><dataLen><data>
			offset = sizeof(uint32_t);
			memcpy(&status, replyBuffer + offset, sizeof(uint32_t));
			offset += sizeof(uint32_t);
			memcpy((uint8_t*)dataLen, replyBuffer + offset, sizeof(uint32_t));
			offset += sizeof(uint32_t);
			memcpy(data, replyBuffer + offset, replyBufferLen - sizeof(uint32_t) * 3);
			break;
		case FMUSB_NEW:
		case FMUSB_DESTROY:
		case FMUSB_WRITE:
		case FMUSB_APPEND:
			//From HSM: <statusLen><status>
			offset = sizeof(uint32_t);
			memcpy(&status, replyBuffer + offset, sizeof(uint32_t));
			break;
		case FMUSB_READ:
			//Return: <statusLen><status><dataLen><data>
			offset = sizeof(uint32_t);
			memcpy(&status, replyBuffer + offset, sizeof(uint32_t));
			offset += sizeof(uint32_t);
			memcpy((uint8_t*)dataLen, replyBuffer + offset, sizeof(uint32_t));
			*dataLen = hton_long(*dataLen);
			offset += sizeof(uint32_t);
			memcpy(data, replyBuffer + offset, replyBufferLen - sizeof(uint32_t) * 3);
		break;
		case FMUSB_INFO:
			//<statusLen><status><labelLen><label><FsDataLen>
			offset = sizeof(uint32_t);
			memcpy(&status, replyBuffer + offset, sizeof(uint32_t));
			offset += sizeof(uint32_t);

			memcpy((uint8_t*)&labelLen, replyBuffer + offset, sizeof(uint32_t));
			labelLen = ntoh_long(labelLen);

			offset += sizeof(uint32_t);
			if (labelLen != 0) {
				memcpy(label, replyBuffer + offset, labelLen);
			}
			label[labelLen] = 0;
			offset += labelLen;
			memcpy((uint8_t*)dataLen, replyBuffer + offset, sizeof(uint32_t));
			*dataLen = hton_long(*dataLen);
		break;
	}
	return 0;
}

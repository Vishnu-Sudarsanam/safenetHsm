/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2021 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 * Author: Sorokine, Joseph
 */

#include <stdlib.h>
#include <stdio.h>
#include <cryptoki.h>
#include <cprovtbl.h>
#include <cprovpch.h>
#include <csa8hiface.h>
#include <fm.h>
#include <fmsw.h>
#include <fmdebug.h>
#include <fmusbdefs.h>
#include <fmusb.h>
#include "usb.h"

#define MY_FM_NUMBER 0x700

#define FN "FM_USB_Control: "
static void FM_USB_Control (HI_MsgHandle token, void *reqBuffer, uint32_t reqLength)
{
	void *ctx = NULL;
	void *handle = NULL;
	uint32_t n = 0;
	int r;
	int kernelDriverAttachedFlag = 1;/* by default */
	uint8_t *buffer = NULL;
	uint32_t len = BLOCK_SIZE_M;
	dev_properties_t dp;
	capacity_t cap;
	uint8_t *header = NULL;
	char label[MAX_FS_LABEL_LEN] = "";
	uint8_t *msg = NULL;
	void *replyBuf;
	unsigned int replyLen;
	int offsetReq = 0, offsetResp = 0;
	uint16_t cmd;
	uint8_t *pReply = NULL;
	uint32_t labelLen;
	//uint32_t labelLenLen = 0;
	uint32_t dataLen = 0;
	uint32_t uint32T = 0;
	uint32_t outLen = 0;

	cmd = (uint16_t) ntoh_short(*(uint16_t*)reqBuffer);
	offsetReq += sizeof(cmd);
	if (cmd != FMUSB_INFO) {
		labelLen = (uint32_t) ntoh_long(*(uint32_t*)(reqBuffer + offsetReq));
		if (labelLen > MAX_FS_LABEL_LEN) {
			replyLen = SVC_GetUserReplyBufLen(token);
			replyBuf = SVC_GetReplyBuffer(token, replyLen);
			r = CKR_USB_FS_NOT_PRESENT;
			goto end;
		}
		offsetReq += sizeof(labelLen);
		if (labelLen != 0) {
			memcpy(label, reqBuffer + offsetReq, labelLen);
			label[labelLen] = 0;
			offsetReq += labelLen;
		}
	}
	/* Allocate the reply buffer. */
	replyLen = SVC_GetUserReplyBufLen(token);
	replyBuf = SVC_GetReplyBuffer(token, replyLen);
	pReply = replyBuf;
	/*
	 * The following command is always required:
	 */
	memset(&dp, 0, sizeof(dp));
	memset(&cap, 0, sizeof(cap));
	r = USBFS_Init(&ctx, &handle, &dp, &cap, &kernelDriverAttachedFlag);
	if (r) {
		outLen = sizeof(uint32_t);
		goto end;
	}
	switch(cmd) {
	case FMUSB_DATA_EXCHANGE_TEST:
		//get input data:
		dataLen = (uint32_t) ntoh_long(*(uint32_t*)(reqBuffer + offsetReq));
		offsetReq += sizeof(dataLen);
		r = 0x12345678;//returned value
		/*
		 * Fill up reply buffer:
		 */
		memset(pReply, 0, replyLen);
		uint32T = sizeof(r);
		offsetResp=0;
		memcpy(pReply + offsetResp, (uint8_t*)&uint32T, sizeof(uint32T));
		offsetResp += sizeof(uint32T);
		memcpy(pReply + offsetResp, (uint8_t*)&r, sizeof(r));
		offsetResp += sizeof(r);
		uint32T = dataLen;
		memcpy(pReply + offsetResp, &uint32T, sizeof(uint32T));
		offsetResp += sizeof(dataLen);
		memcpy(pReply + offsetResp, reqBuffer + offsetReq, dataLen);
		outLen = sizeof(uint32_t) * 3 + dataLen;
		break;
	case FMUSB_NEW:
		r = USBFS_New(handle, label, &dp, &cap, &header);
		if (r) {
			goto end;
		}
		if ((r = USBFS_Close(handle, &dp, &cap, header)) != 0) {
			printf("Close operation failed\n");
		}
		/*
		 * Fill up reply buffer and return <statusLen><status>:
		 */
		memset(pReply, 0, replyLen);
		uint32T = sizeof(r);
		offsetResp=0;
		memcpy(pReply + offsetResp, (uint8_t*)&uint32T, sizeof(uint32T));
		offsetResp += sizeof(uint32T);
		memcpy(pReply + offsetResp, (uint8_t*)&r, sizeof(r));
		outLen = sizeof(uint32_t) * 2;
		break;
	case FMUSB_WRITE:
		dataLen = (uint32_t) ntoh_long(*(uint32_t*)(reqBuffer + offsetReq));
		offsetReq += sizeof(dataLen);
		r = USBFS_Open(handle, &dp, &cap, &header);
		if (r) {
			goto end;
		}
	    n = dataLen;
	    //Do not allocate memory, get the data from request buffer:
	    msg = reqBuffer + offsetReq;
		if ((r = USBFS_WriteData(handle, &dp, &cap, msg, n, header)) != 0) {
			goto end;
		}
		if ((r = USBFS_Close(handle, &dp, &cap, header)) != 0) {
			goto end;
		}
		/*
		 * Fill up reply buffer and return <statusLen><status>:
		 */
		memset(pReply, 0, replyLen);
		uint32T = sizeof(r);
		offsetResp=0;
		memcpy(pReply + offsetResp, (uint8_t*)&uint32T, sizeof(uint32T));
		offsetResp += sizeof(uint32T);
		memcpy(pReply + offsetResp, (uint8_t*)&r, sizeof(r));
		outLen = sizeof(uint32_t) * 2;
		break;
	case FMUSB_READ:
		/*
		 * FM expects that requestBuf contains the following fields:
		 * <cmd><labelLen><label> and reply buffer:
		 * <statusLen><status><dataLen><data>
		 */
		{
			r = USBFS_Open(handle, &dp, &cap, &header);
			if (r) {
				goto end;
			}
			//Skipping 3 first field in pPreply buffer and write the FS data:
			offsetResp = sizeof(uint32_t) * 3;
			memcpy(&len, header, sizeof(uint32_t));
			r = USBFS_ReadData(handle, &dp, &cap, pReply + offsetResp, &len, header);
			if (r) {
				goto end;
			}
			/*
			 * Fill up <stausLen><status><dataLen> fields of reply buffer:
			 */
			uint32T = sizeof(r);
			offsetResp=0;
			memcpy(pReply + offsetResp, (uint8_t*)&uint32T, sizeof(uint32T));//status len
			offsetResp += sizeof(uint32T);
			memcpy(pReply + offsetResp, (uint8_t*)&r, sizeof(r));//status value
			offsetResp += sizeof(r);
			uint32T = ntoh_long(len);
			memcpy(pReply + offsetResp, &uint32T, sizeof(uint32T));//data len
			offsetResp += sizeof(uint32_t);
			outLen = sizeof(uint32_t) * 3 + len;
		}
		break;
	case FMUSB_DESTROY:
		r = USBFS_Open(handle, &dp, &cap, &header);
		if (r) {
			goto end;
		}
		r = USBFS_Destroy(handle, &dp, &cap, &header);
		/*
		 * Fill up reply buffer and return <statusLen><status>:
		 */
		memset(pReply, 0, replyLen);
		uint32T = sizeof(r);
		offsetResp=0;
		memcpy(pReply + offsetResp, (uint8_t*)&uint32T, sizeof(uint32T));
		offsetResp += sizeof(uint32T);
		memcpy(pReply + offsetResp, (uint8_t*)&r, sizeof(r));
		outLen = sizeof(uint32_t) * 2;
		break;
	case FMUSB_INFO:
	default:
		{
			uint32_t labelLenTrans = 0;
			unsigned char label[MAX_FS_LABEL_LEN] = "";
			/*
			 * Returns the following mesage:
			 * <statusLen><status><labelLen><label><fsDataLen>
			 */
			offsetResp = 0;
			r = USBFS_Open(handle, &dp, &cap, &header);
			if (r) {
				goto end;
			}
			n = cap.block_size;
			r = USBFS_GetInfo(handle, &dp, &cap, &n, label, header);
			if (r != 0) {
				goto end;
			}
			//Return status len:
			memset(pReply, 0, replyLen);
			offsetResp = 0;
			uint32T = sizeof(r);
			memcpy(pReply + offsetResp, (uint8_t*)&uint32T, sizeof(uint32_t));
			offsetResp += sizeof(uint32_t);
			//Return status:
			memcpy(pReply + offsetResp, (uint8_t*)&r, sizeof(r));
			offsetResp += sizeof(r);
			//Return label length:
			labelLen = strlen((char*)label) + 1;//including last 0
			labelLenTrans = ntoh_long(labelLen);
			memcpy(pReply + offsetResp, &labelLenTrans, sizeof(uint32_t));
			offsetResp += sizeof(uint32_t);
			//Return label:
			memcpy(pReply + offsetResp, label, labelLen);
			offsetResp += labelLen;
			//return FS data length:
			uint32T = ntoh_long(*((uint32_t*)header));
			memcpy(pReply + offsetResp, &uint32T, sizeof(uint32_t));
			outLen = sizeof(uint32_t) * 4 + labelLen;
		}
		break;
	}//switch
end:
	/* shrink reply buffer is needed */
	if(outLen < replyLen) {
		if(SVC_ResizeReplyBuffer(token, outLen) == NULL) r = CKR_DEVICE_MEMORY;
	}
	/* send reply back */
	SVC_SendReply(token, (uint32_t) r);
	/*
	 * The following command is always required:
	 */
	r = USBFS_Finalize(ctx, handle, &kernelDriverAttachedFlag, &header);
	if (0 != r)
	{
		printf( "Error USBFS_Finalize.\n");
	}
	if (r != 0) {
		SVC_SendReply(token, (uint32_t) r); /* send error reply back and stop processing */
	} else {
		SVC_SendReply(token, (uint32_t) CKR_OK); /* send success reply back and stop processing */
	}
	if (buffer) {
		free(buffer);
		buffer = NULL;
	}
}

/* FM Startup function */
FM_RV Startup(void)
{
	FM_RV rv = 0;
	rv = FMSW_RegisterDispatch(MY_FM_NUMBER, FM_USB_Control);
	return rv;
}

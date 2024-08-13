/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: samples/smfs/fm/smfs.c
 */

/**
 * @file
 *    SMFS DEMO program : This FM demonstrates the use of the Secure Memory File System
 *    The FM provides host 
 */

#include <stdlib.h>
#include <stdio.h>
#include <cryptoki.h>
#include <cprovtbl.h>
#include <cprovpch.h>
#include <csa8hiface.h>
#include <string.h>
#include <fmsw.h>
#include <fm.h>
#include <fmdebug.h>
#include <fmsmfs.h>

extern CprovFnTable_t *FM_GetCprovFuncs(void);

#define FMCMD_WRITE_FILE     0x0001 /* Create AND write the file */
#define FMCMD_READ_FILE      0x0002
#define FMCMD_DELETE_FILE    0x0003
#define KEYVALSIZE              24 /* DES3 key */

#define SMF_MAX_PATH         100

#define CRYPTOKI_ROOT "/ck"

#define MY_FM_NUMBER 0x500

/* validate filename
 * Return SM error code
 */
int CheckFileName(char *fileName)
{
    char * p;
    int    len = strlen(fileName);

    /* not too big - not too small - not just '/' (root) */
    if ( len > SMF_MAX_PATH )
        return SMFS_ERR_NAME_TOO_LONG;

    if ( len < 2)
        return SMFS_ERR_FILE_TYPE;

    /* ensure path is absolute */
    if( *fileName != '/' )
        return SMFS_ERR_FILE_TYPE;

    /* get pointer to terminating character of root directory name */    
    for ( p = fileName + 1, len = 1; *p && *p != '/'; ++p, ++len )
        ;

    /* ensure path is not a reserved directory */
    if ( memcmp(fileName, CRYPTOKI_ROOT, len) == 0)
        return SMFS_ERR_FILE_TYPE;

    /* otherwise OK */
    return 0;

}



int WriteFileFM(char *fileName, char *in, unsigned int inLen)
{
    int rv = 0;
    SMFS_HANDLE fileHandle = -1;

    if ( (rv = CheckFileName(fileName)) != 0 )
        return rv; 

    /* First see if the file exists. If it doesn't we need to create it */
    rv = SmFsOpenFile(&fileHandle, fileName);
    if (rv == SMFS_ERR_NOT_FOUND)
    {
        /* File does not exist, create it */
        rv = SmFsCreateFile(fileName, inLen);

        if (rv)
        {
            /* If the file could not be created, exit */
            goto exit;
        }

        /* Now that we've created the file, open it */
        rv = SmFsOpenFile(&fileHandle, fileName);
        if (rv)
        {
            /* If the file could still not be opened, error */
            goto exit;
        }
    }
    else if (rv)
    {
        goto exit;
    }

    /* We now have the file open - write the contents */
    rv = SmFsWriteFile(fileHandle, 0, in, inLen);
    if (rv) 
    {
        goto exit;
    }

exit:

    if ( fileHandle != -1 )
        SmFsCloseFile(fileHandle);

    return rv;
}

int ReadFileFM(char *fileName, char *outBuf, int outBufLen)
{
    int rv = 0;
    SMFS_HANDLE fileHandle;

    if ( (rv = CheckFileName(fileName)) != 0 )
        return rv; 

    /* Open the file */
    rv = SmFsOpenFile(&fileHandle, fileName);
    if (rv) goto exit;

    /* Read the file into the output buffer */
    rv = SmFsReadFile(fileHandle, 0, outBuf, outBufLen);
    if (rv) goto exit;

exit:
    
    SmFsCloseFile(fileHandle);

    return rv;
}

int DeleteFile(char *fileName)
{
    int rv = 0;

    if ( (rv = CheckFileName(fileName)) != 0 )
        return rv; 

    /* Delete the given filename */
    rv = SmFsDeleteFile(fileName);
    if (rv) goto exit;

exit:

    return rv;
}

/* command handler entry point */
static void SmFsFM_HandleMessage(
    HI_MsgHandle token,            
    void *reqBuffer,            
    uint32_t reqLength)            
{
    char *fileName = NULL, 
         *in = NULL,
         *parg = NULL;
    unsigned short cmd, fileName_len;
    unsigned int inLen;
    int rv = 0;

    /* Argument sanity check */
    if (reqLength < (3 * sizeof(unsigned short)) )
    {
        /* Ensure the request is long enough to contain at least the 
           cmd + length of fileName + length of buffer */ 
        return;
    }

    /* parse command */
    cmd = (unsigned short) ntoh_short(*(unsigned short *)reqBuffer); 
    parg = (char*)reqBuffer + sizeof(unsigned short);
    reqLength -= sizeof(unsigned short);

    /* command switch, only one command */
    switch(cmd) {
    case FMCMD_WRITE_FILE:
        debug(printf("CMD == WRITE_FILE");)

        /* parse len of fileName */
        memcpy(&fileName_len, parg, sizeof(fileName_len));
        fileName_len = (unsigned short)ntoh_short(fileName_len);
        parg += sizeof(unsigned short);
        reqLength -= sizeof(unsigned short);
        if ( fileName_len > reqLength )
        {
            SVC_SendReply(token, (uint32_t) SMFS_ERR_PARAMETER);
            break;
        }

        /* parse fileName, it's zero terminated string */
        fileName = malloc(fileName_len+1);
        if ( !fileName )
        {
            SVC_SendReply(token, (uint32_t) SMFS_ERR_RESOURCES);
            break;
        }
        memcpy(fileName,parg,fileName_len);
        fileName[fileName_len] = 0;        
        parg += fileName_len;
        reqLength -= fileName_len;

        /* parse length of the buffer */
        inLen = ntoh_long(*(unsigned long *)parg); 
        parg += sizeof(unsigned long);

        if ( inLen > reqLength )
        {
            SVC_SendReply(token, (uint32_t) SMFS_ERR_PARAMETER);
            break;
        }

        /*  allocate buffer */
        in = malloc(inLen);
        if ( !in )
        {
            SVC_SendReply(token, (uint32_t) SMFS_ERR_RESOURCES);
            break;
        }
        memcpy(in,parg,inLen);

        /* call WriteFileFM fuction */
        rv = WriteFileFM(fileName, in, inLen);

        /* send reply back */
        SVC_SendReply(token, (uint32_t) rv);
        break;

    case FMCMD_READ_FILE : 
    case FMCMD_DELETE_FILE:
        debug(if (cmd == FMCMD_READ_FILE) printf("CMD == READ_FILE");)
        debug(if (cmd == FMCMD_DELETE_FILE) printf("CMD == DELETE_FILE");)

        /* parse len of fileName */
        memcpy(&fileName_len, parg, sizeof(fileName_len));
        fileName_len = (unsigned short)ntoh_short(fileName_len);
        parg += sizeof(unsigned short);
        reqLength -= sizeof(unsigned short);
        if ( fileName_len > reqLength )
        {
            SVC_SendReply(token, (uint32_t) SMFS_ERR_PARAMETER);
            break;
        }

        /* parse fileName, it's zero terminated string */
        fileName = malloc(fileName_len+1);
        if ( !fileName )
        {
            SVC_SendReply(token, (uint32_t) SMFS_ERR_RESOURCES);
            break;
        }
        memcpy(fileName,parg,fileName_len);
        fileName[fileName_len] = 0;        
        parg += fileName_len;
        reqLength -= fileName_len;

        if (cmd == FMCMD_READ_FILE)
        {
            char *outBuf = NULL;
            uint32_t outBufLen = 0;

            /* Get the size of the output Buffer */
            outBufLen = SVC_GetUserReplyBufLen(token);

            /* Get the reply buffer */
            outBuf = SVC_GetReplyBuffer(token, outBufLen);
            if ( !outBuf )
            {
                SVC_SendReply(token, (uint32_t) SMFS_ERR_RESOURCES);
                break;
            }

            rv = ReadFileFM(fileName, outBuf, outBufLen);
        }
        else if (cmd == FMCMD_DELETE_FILE) 
        {
            rv = DeleteFile(fileName);
        }

        /* Send reply back */
        SVC_SendReply(token, (uint32_t) rv);

        break;

    default:
        SVC_SendReply(token, (uint32_t) CKR_FUNCTION_NOT_SUPPORTED);
        break;
    }

    /* Clean up */
    if (fileName) free(fileName);
    if (in) free(in);
}

/* FM Startup function */
FM_RV Startup(void) 
{
    FM_RV rv = 0;

    /* registar handler for our new API */
    debug(printf("Registering dispatch function ... ");)
    rv = FMSW_RegisterDispatch(MY_FM_NUMBER, SmFsFM_HandleMessage);
    debug(printf("registered. Return Code = 0x%x", rv);)

    return rv;
}

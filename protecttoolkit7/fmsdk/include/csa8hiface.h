/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 1997-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: csa8hiface.h
 */
#ifndef INC_CSA8HIFACE_H
#define INC_CSA8HIFACE_H

#include <stdint.h>

typedef void *HI_MsgHandle;

/**
 * This function is used by the called applications to receive a reply
 * buffer from the Service module.
 *
 * @param token
 *     A token indentifying the request.
 *
 * @param size
 *     Length of the reply buffer.
 *
 * @return
 *     @li If there is already a reply buffer, NULL is returned.
 *     @li If there is not enough memory to allocate the requested amount of
 *         reply buffer, @c NULL is returned.
 *     @li Otherwise, a pointer to the reply buffer is returned.
 */
void *SVC_GetReplyBuffer(HI_MsgHandle token, uint32_t size);

/**
 * This function is used to reuse the request buffer as the reply buffer. This
 * call may cause a memcopy when the reply is being posted back to the host
 * system.
 *
 * @param token
 *    A token indentifying the request.
 *
 * @return
 *    @li If there is already a reply buffer, NULL is returned.
 *    @li Otherwise, pointer to the reply buffer is returned. The reply buffer
 *        is not guaranteed to be at the same address as the request buffer.
 *        However, it will contain the request buffer contents.
 */
void *SVC_ConvertReqToReply(HI_MsgHandle token);

/**
 * This function is called by the request handling function when the reply is
 * ready to be sent back to the host. The function may perform operations after
 * this function is called, but it should not use the token in further Service
 * Module functions.
 *
 * @param token
 *    A token indentifying the request.
 *
 * @param status
 *    Application status to be returned to host.
 */
void SVC_SendReply(HI_MsgHandle token, uint32_t status);

/**
 * This function is used to resize the reply buffer.
 *
 * @param token
 *    A token indentifying the request.
 *
 * @param replyLength
 *    New length of the reply buffer.
 *
 * @return
 *    @li If there is not a reply buffer, NULL is returned.
 *    @li If there is not enough memory to allocate a reply buffer, NULL is
 *    returned.
 *    @li Otherwise, pointer to a reply buffer is returned. The new reply buffer
 *    will contain the data in the old reply buffer.
 */
void *SVC_ResizeReplyBuffer(HI_MsgHandle token, uint32_t replyLength);

/**
 * This function discards the current reply buffer.
 *
 * @param token
 *    A token indentifying the request.
 */
void SVC_DiscardReplyBuffer(HI_MsgHandle token);

/**
 * This function is used to learn the reply buffer length specified by the host
 * system.
 *
 * @param token
 *    A token indentifying the request.
 *
 * @return
 *    Length of the reply buffer on the host system.
 */
uint32_t SVC_GetUserReplyBufLen(HI_MsgHandle token);

/**
 * This function retrieves the Pid recorded in the request. The Pid is the
 * Process Id of the host application that originated the request.
 *
 * @param token
 *    A token indentifying the request.
 *
 * @return
 *    The Process identifier recorded in the request is returned.
 */
uint32_t SVC_GetPid(HI_MsgHandle token);

/**
 * This function retrieves the Oid recorded in the request. The Oid is a value
 * passed in from the host application.
 *
 * @param token
 *    A token indentifying the request.
 *
 * @return
 *    The Originator identifier recorded in the request is returned.
 */
uint32_t SVC_GetOid(HI_MsgHandle token);

/**
 * This function overrides the Pid recorded in the request. The Pid is
 * the Process Id of the host application that originated the request.
 *
 * @param token
 *    A token indentifying the request.
 *
 * @param pid
 *    The new pid value.
 */
void SVC_SetPid(HI_MsgHandle token, uint32_t pid);

/**
 * This function overrides the Oid recorded in the request. The Oid is a value
 * passed in from the host application.
 *
 * @param token
 *    A token indentifying the request.
 *
 * @param oid
 *    The new oid value.
 */
void SVC_SetOid(HI_MsgHandle token, uint32_t oid);

/**
 * This function retrieves the address of request data in the token.
 *
 * @param token
 *    A token indentifying the request.
 *
 * @return
 *    The request buffer address in the token is returned.
 */
void *SVC_GetRequest(HI_MsgHandle token);

/**
 * This function retrieves the length of request data in the token.
 *
 * @param token
 *    A token indentifying the request.
 *
 * @return
 *    The length of the request buffer in the token is returned.
 */
uint32_t SVC_GetRequestLength(HI_MsgHandle token);

/**
 * This function retrieves the address of current reply buffer.
 *
 * @param token
 *    A token indentifying the request.
 *
 * @return
 *    The address of the current reply buffer in the token is returned.
 */
void *SVC_GetReply(HI_MsgHandle token);

/**
 * This function retrieves the length of reply data in number of bytes.
 *
 * @param token
 *    A token indentifying the request.
 *
 * @return
 *    The length of the current reply buffer in the token is returned.
 */
uint32_t SVC_GetReplyLength(HI_MsgHandle token);

/**
 * This function retrieves the usage level of the HSM as a load percentage.
 *
 * @return
 *    The rolling average of the usage level of the HSM.
 */
unsigned long SVC_GetHsmUsageLevel(void);

#endif /* INC_CSA8HIFACE_H */

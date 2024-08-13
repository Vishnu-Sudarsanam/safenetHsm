/*
 * Copyright (c) 2013-2017 Safenet.  All rights reserved.
 */
#ifndef FWCBRC_H
#define FWCBRC_H

/* This file is duplicated in several places in various MKS trees */

/* This file defines callback mechanizm errors understandable by the
 * firmware. If host side callback implementation defines a new error
 * code that it might return to the HSM, both fwrc.h and this file must
 * be updated. Host side callback implementation is free to define it's
 * own CB_RET_* error codes that it never sends to HSM. Such error
 * codes must not overlap with the ones below. For example, a callback
 * library that interfaces callback handlers with the HSM via driver
 * may add codes CB_RET_PROTOCOL_NOT_SUPPORTED or CB_RET_HSM_IS_NOT_PRESENT.
 * These are not visible to the HSM, but still belong to the callback
 * mechanizm errors space
 */

#include "fwrc.h"

typedef UInt CB_RET;

/* The follwoing errors can be duplicated (different codes) by OS / firmware */

#define CB_RET_OK                            LUNA_RET_OK

/* Parameter(s) of some function invalid */
#define CB_RET_PARAM_INVALID                 LUNA_RET_CB_PARAM_INVALID

/* CB mechanizm is not supported */
#define CB_RET_NOT_SUPPORTED                 LUNA_RET_CB_NOT_SUPPORTED

/* No memory, system. Win: STATUS_NO_MEMORY, Unix: ENOMEM */
#define CB_RET_NO_MEMORY                     LUNA_RET_CB_NO_MEMORY

/* Read or write request timeout, system: Win: STATUS_IO_TIMEOUT, Unix: ETIMEDOUT */
#define CB_RET_TIMEOUT                       LUNA_RET_CB_TIMEOUT

/* Busy, user should retry later. This is not supported yet. 
 * Win: ERROR_IO_PENDING for overlapped ops, Unix: EAGAIN
 */
#define CB_RET_RETRY                         LUNA_RET_CB_RETRY

/* Signal received while waiting for request completion */
#define CB_RET_ABORTED                       LUNA_RET_CB_ABORTED

/* Unspecified OS/FW error. */
#define CB_RET_SYS_ERROR                     LUNA_RET_CB_SYS_ERROR


/* Callback HSM I/O Stream (or System) error codes */

/* Invalid handle of an HSM i/o stream */
#define CB_RET_HIOS_HANDLE_INVALID           LUNA_RET_CB_HIOS_HANDLE_INVALID

/* Invalid id of an HSM i/o stream */
#define CB_RET_HIOS_ID_INVALID               LUNA_RET_CB_HIOS_ID_INVALID

/* HSM i/o stream was closed by the HSM, or even never existed */
#define CB_RET_HIOS_CLOSED                   LUNA_RET_CB_HIOS_CLOSED

/* HSM i/o stream was canceled by the user */
#define CB_RET_HIOS_CANCELED                 LUNA_RET_CB_HIOS_CANCELED

/* Unspecified error in communication between HSM and HOST */ 
#define CB_RET_HIOS_IO_ERROR                 LUNA_RET_CB_HIOS_IO_ERROR

/* Timeout sending data to the destination (HOST or HSM) when timely
 * delivery is guaranteed by the receiving party by virtue of HIOS
 * design. It is more specific CB_RET_HIOS_IO_ERROR.
 *
 * NOTE: similar looking CB_RET_TIMEOUT is used when a receiving
 * party does not provide any guarantees and may not even exist.
 * Example: a callback handler does not run on a HOST system which
 * is why the HSM cannot send data to it. It could retry later,
 * though.
 */
#define CB_RET_HIOS_SEND_TIMEOUT             LUNA_RET_CB_HIOS_SEND_TIMEOUT

/* Timeout receiving data from the source (HSM or HOST) when timely
 * delivery is guaranteed by the sending party by virtue of HIOS
 * design. It is more specific CB_RET_HIOS_IO_ERROR.
 *
 * NOTE: similar looking CB_RET_TIMEOUT is used when a receiving
 * party does not provide any guarantees and may not even exist.
 * Example: a callback handler does not run on a HOST system which
 * is why the HSM cannot send data to it. It could retry later,
 * though.
 */
#define CB_RET_HIOS_RECV_TIMEOUT             LUNA_RET_CB_HIOS_RECV_TIMEOUT

/* State of the HSM I/O stream is incorrect for the attempted operation (message) */
#define CB_RET_HIOS_STATE_INVALID            LUNA_RET_CB_HIOS_STATE_INVALID

/* HIOS could not write data to a user provided receiving buffer
 * in host memory. This is HIOS I/O protocol error
 */
#define CB_RET_HIOS_OUTPUT_BUFFER_TOO_SMALL  LUNA_RET_CB_HIOS_OUTPUT_BUFFER_TOO_SMALL

/* HIOS could not write data to a receiving buffer in the HSM.
 * This is HIOS I/O protocol error.
 */
#define CB_RET_HIOS_INPUT_BUFFER_TOO_SMALL   LUNA_RET_CB_HIOS_INPUT_BUFFER_TOO_SMALL

/* Error codes for the callback protocol */

/* Invalid callback handle */
#define CB_RET_HANDLE_INVALID                LUNA_RET_CB_HANDLE_INVALID

/* Invalid callback id */
#define CB_RET_ID_INVALID                    LUNA_RET_CB_ID_INVALID

/* A callback session was abruptly aborted by a peer */
#define CB_RET_REMOTE_ABORT                  LUNA_RET_CB_REMOTE_ABORT

/* A callback session was closed by the peer */
#define CB_RET_REMOTE_CLOSED                 LUNA_RET_CB_REMOTE_CLOSED

/* A callback session was abandoned by a peer. The session does not
 * seem to exist anymore, however there were no notification from
 * the peer about its termination.
 */
#define CB_RET_REMOTE_ABANDONED              LUNA_RET_CB_REMOTE_ABANDONED

/* cb_write() failed to send data to a peer, because the peer itself
 * is sending data at the same time. Data being sent by the opposite
 * party should be received via cb_read(), if possible. If not, the
 * callback session should be closed via cb_close(). The most often
 * reason for this error is a broken data exchange protocol for a
 * specific callback by one of the sides. 
 */
#define CB_RET_MUST_READ                     LUNA_RET_CB_MUST_READ

/* cb_read() failed to receive data from a peer, because the peer
 * itself is receiving data at the same time. The most often reason
 * for this error is a broken data exchange protocol for a specific
 * callback by one of the sides..
 */
#define CB_RET_MUST_WRITE                    LUNA_RET_CB_MUST_WRITE

/* A user call cb_write() or cb_read() after he/she already
 * closed the callback session.
 */
#define CB_RET_INVALID_CALL_FOR_THE_STATE    LUNA_RET_CB_INVALID_CALL_FOR_THE_STATE

/* Internal callback protocol error. Unexpected data was
 * received by the callback protocol state machine.
 */
#define CB_RET_SYNC_ERROR                    LUNA_RET_CB_SYNC_ERROR

/* Internal callback protocol state machine error. The payload
 * of the packet is incorrect
 */
#define CB_RET_PROT_DATA_INVALID             LUNA_RET_CB_PROT_DATA_INVALID


#endif /* FWCBRC_H */

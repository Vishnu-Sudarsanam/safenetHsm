/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 1998-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: serial.h
 */

/**
 * @file This module contains serial port support routines.
*/

#ifndef _SERIAL_H
#define _SERIAL_H

typedef enum _SERIAL_Parity {
	SERIAL_PARITY_NONE,
	SERIAL_PARITY_ODD,
	SERIAL_PARITY_EVEN,
	SERIAL_PARITY_ONE,
	SERIAL_PARITY_ZERO
} SERIAL_Parity;

/* Handshake mode */
typedef enum _SERIAL_HSMode {
	SERIAL_HS_NONE,
	SERIAL_HS_HW,
	SERIAL_HS_XONXOFF
} SERIAL_HSMode;

/**************************************************************************

    Description:
        SERIAL_SendData() function is used to send a character array over
		a serial port.

    Parameters:
		port: serial port number (0 based)
		buf: pointer to an array of bytes to be sent
		bufLen: length of the buffer, in bytes
		timeout: #milliseconds to wait for a character to be sent. A
		timeout of -1 will use the default timeout

    Return Code:
		0: The characters were sent successfully.
		-1: There was an error.

    Comments:

**************************************************************************/
int SERIAL_SendData(int port, unsigned char *buf, int bufLen, long timeout);

/**************************************************************************

    Description:
        SERIAL_ReceiveData() function is used to receive an arbitrary
		length of characters from the serial port.

    Parameters:
		port: serial port number (0 based)
		buf: pointer to an array of bytes, which will hold the received
		data.
		len: pointer to an integer which will hold the actual number of
		characters received.
		bufLen: Both the maximum amount of data, in bytes, of the buffer,
		and the number of bytes requested from the serial port.
		timeout: #milliseconds to wait for a character to appear. A
		timeout of -1 will use the default timeout

    Return Code:
		0: Requested number of bytes has been received.
		-1: Less than the requested number of bytes have been received.

    Comments:

**************************************************************************/
int SERIAL_ReceiveData(int port, unsigned char *buf, int *len, int bufLen,
		long timeout);

/**************************************************************************

    Description:
        SERIAL_WaitData() function waits for a character to appear on the
		serial port.

    Parameters:
		port: serial port number (0 based)

    Return Code:
		0: There is a character at the serial port.
		-1: Timeout occured, and no data appeared.

    Comments:
		This function does nothing

**************************************************************************/
int SERIAL_WaitReply( int port );

void SERIAL_FlushRX( int port );

int SERIAL_GetNumPorts(void);

int SERIAL_InitPort(int port);
/* Timeout in milliseconds */
void SERIAL_SetRXTimeout(int port, unsigned long t );

#define MCL_DSR 0x01
#define MCL_DTR 0x02
#define MCL_RTS 0x04
#define MCL_CTS 0x08
#define MCL_DCD 0x10
#define MCL_RI  0x20

#define MCL_OP_SET 1
#define MCL_OP_CLEAR 2

/**************************************************************************

    Description:
        This function reads the current state of the control lines, and
		writes a bitmap into the address pointed to by 'val'. Only the
		input bits (CTS, DSR, DCD, RI) reflec the current status of
		control lines.

    Parameters:
		port: serial port number (0 based)
		bitmap: Pointer to a character, which will have the resulting bitmap

    Return Code:
		0: The function succeeded
		-1: The function failed. The value in the bitmap is not valid

    Comments:

**************************************************************************/
int SERIAL_GetControlLines(int port, unsigned char *bitmap);

/**************************************************************************

    Description:
        This function is used to modify the control lines (DTR/RTS).

    Parameters:
		port: serial port number (0 based)
		bitmap: bitmap of control lines to be modified. Input control
  			lines are silently ignored.
		op: One of MCL_OP_SET/MCL_OP_CLEAR to set/clear the control lines
			specified in the bitmap parameter

    Return Code:
		0: The function succeeded
		-1: The function failed

    Comments:
        [Any additional information that may be of interest including
        references to other documentation.]

**************************************************************************/
int SERIAL_SetControlLines(int port, unsigned char bitmap, int op);

/**************************************************************************

    Description:
        Used to set the serial port communication parameters.

    Parameters:
		port: port number
		baud: baud rate.
		numBits: Number of bits in a character. Should be 7 or 8
		parity: One of the following
			SERIAL_PARITY_NONE
			SERIAL_PARITY_ODD
			SERIAL_PARITY_EVEN
			SERIAL_PARITY_ONE
			SERIAL_PARITY_ZERO
		numStop: Number of stop bits in a character. Should be 1 or 2
		hs: Handshake type. Should be one of the following
			SERIAL_HS_NONE
			SERIAL_HS_RTSCTS
			SERIAL_HS_XON_XOFF

    Return Code:
		 0: Mode changed successfully
		-1: There was an error

    Comments:

**************************************************************************/
int SERIAL_SetMode(int port, int baud, int numBits, SERIAL_Parity parity,
		int numStop, SERIAL_HSMode hs);

/**************************************************************************

    Description:
        Gets ownership(!) of the port. Subsequent calls to this function
		with the same parameter will fail unless SERIAL_ClosePort() is
		called for the same port.

    Parameters:
		port: port number

    Return Code:
		0: Port opened successfully
		otherwise: there was an error

    Comments:
		This function in no way guarantees safe sharing of the ports.
		Anyone can call SERIAL_ClosePort() to get the access. Or anyone
		can use SERIAL functions without opening the port first. The
		SERIAL library must be modified to enforce resource sharing rules.

**************************************************************************/
int SERIAL_Open(int port);

/**************************************************************************

    Description:
        This function is used to release ownership of the serial port.

    Parameters:
		port: port number

    Return Code:
        -

    Comments:
		See SERIAL_OpenPort

**************************************************************************/
void SERIAL_Close(int port);


/*
 * related usb reader functions 
 */

int UsbReader_GetMaxSptNumReaders(void);
int UsbReader_GetNumReaders(void);

#endif /* _SERIAL_H */

/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2005-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: fmdebug.h
 */
/** @file
 *  FMDEBUG - Provides debug functions to FM writers. Debug is performed by
 *  claiming serial port 1 (driver 0) of the adapter and writing all debug to 
 * that port.
 * <BR>
 *  <B>Note : This debug library is available on the ProtectServer Orange only,  
 *        the ProtectHost Orange does not support debug using this library </B>
 */

#ifndef INC_FMDEBUG_H
#define INC_FMDEBUG_H

#include <string.h>
#include <stdio.h>

#include "serial.h"

/* ------------------------ DEBUG FUNCTION PROTOTYPES -------------------- */

/**
 * This function dumps the hex values of each byte in a buffer to serial
 * port 1 (driver 0) of the PSO. 
 *
 * @param desc
 *  Describes the buffer being dumped. This string is dumped immediately before
 *  the buffer.
 *
 * @param data
 *  This is a pointer to the buffer to be dumped.
 *
 * @param len
 *  The length of the buffer to be dumped.
 */
void dump(char *desc, unsigned char *data, short len);

/**
 * This function formats and dumps the given string to 
 * serial port 1 (driver 0) of the PSO.
 * Its use mirrors that of the c function printf.
 *
 * @param format
 *  Format of the string to print. This argument is followed by the values
 *  to place inside the format string.
 *
 * @return 0 for success, -1 for failure
 */
int dbg_print(char *format, ...);

/* -------------------------- DEBUG INFORMATION MACROS ------------------- */
#ifdef DEBUG
#   define debug(x) x
#   ifdef EMUL
#       define dbg_init();      /* Function not supported in emulation mode */
#       define dbg_final();     /* Function not supported in emulation mode */
#       define dbg_str(x)       fprintf(stdout,"%s",x)
#       define dbg(x,y);        /* Function not supported in emulation mode */
#       define dump(x,y,z) \
            { \
                int i = 0; \
                fprintf(stdout, "%s", x); \
                for (i = 0; i < z; i ++) fprintf(stdout, "%02x", *(y + i)); \
                fprintf(stdout, "\n"); \
            }
#   else /* NOT EMULATION */
/**
 * This macro is used to initialise the debug library and claim serial port 
 * 1 of the PSO. The port is also moded up for (115200, 8, none, 1) serial mode
 * operations.
 * NOTE - Serial port 1 as indicated in the Install Guide and 
 * PPO Programmers guide is connected to Serial Driver 0 (and Serial 
 * port 2 is driver 1).
 */
#       define dbg_init() \
            {          \
                    SERIAL_Open(0); \
                    SERIAL_SetMode(0, 115200, 8, SERIAL_PARITY_NONE, 1, \
                                   SERIAL_HS_NONE); \
            }

/**
 * This macro is used to finalise the debug library and release serial port 
 * 1 of the PSO.
 */
#       define dbg_final() \
            { \
                SERIAL_Close(0); \
            }

/**
 * This macro is used to dump a null terminated string to serial port 1 of the PSO
 *
 * @param str
 *  The string to dump to the serial port
 */
#       define dbg_str(str)       SERIAL_SendData(0, (unsigned char *)str, strlen(str), 1000)

/**
 * This macro is used to dump a non terminated string to serial port 1 of the PSO
 *
 * @param buf
 *  The buffer to dump to the serial port
 *
 * @param len
 * Length of buf
 */
#       define dbg(buf, len)         SERIAL_SendData(0, (unsigned char *)buf, len, 1000)
#   endif  /* EMUL */
#else /* NOT DEBUG */
#   define debug(x)
#endif /* DEBUG */

#endif /* INC_FMDEBUG_H */

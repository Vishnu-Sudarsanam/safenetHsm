/*
 *  This file is provided as part of the SafeNet Protect Toolkit SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 */

#pragma once

#include <stdint.h>
#include "csa8fm.h"

/* ELF Header section where the FM Header will be stored */
#define FM_HEADER_SECTION ".fm.header"

/* Functionality module number type. Each FM loaded to the system has a unique
   FM number. These numbers are also used as the major numbers for the HIFACE
   communication.
*/
typedef uint16_t FmNumber_t;

/* Functionality module version type.*/
typedef uint16_t FmVersion_t;

/* Version of the FM_Header_t format. The initial version is 0, and it is
   incremented by 1 every time it is changed in such a way that it is no longer
   compatible with the older versions. */
typedef uint32_t FM_FormatVersion_t;

/* The SerialNumber is set to 64bits to fill in the
padding created by using a 64-bit timestamp
If we did not care about the year 2038 problem, we could just use
a 32-bit timestamp, and save 8 bytes in the header.
If resizing the serial number is a big issue, add a padding field in the header*/
/* Serial number of an FM. */
typedef uint64_t FM_SerialNumber_t;

/*
  In FM SDK 7, productionDate is stored as a time_t integer, using a uint64_t variable
  Any APIs that report the value will convert it internally
  to the existing format for compatibility.
*/
typedef uint64_t FM_Timestamp_t;

/* FM completely written, and can be used */
#define FM_IN_USE0 0xFFFF0000U

/* Sector not in use */
#define FM_NOT_USED 0xFFFFFFFFU

#define FM_FORMAT_VERSION 3
#define FM_HEADER  _FM_Header_

#define xstr(s) #s
#define str(s) xstr(s)
#define FM_HEADER_NAME str(FM_HEADER)


typedef struct FM_Header_st {
	/* The version of the FM Header format */
	FM_FormatVersion_t formatVersion;

	/* FM Number of the functionality module */
	FmNumber_t number;

	/* Version of the FM */
	union {
		FmVersion_t version;
		struct {
			uint8_t version_major;
			uint8_t version_minor;
		};
	};

	/* Serial number of FM */
	FM_SerialNumber_t serialNo;

	/* Production Date/Time of the FM */
	FM_Timestamp_t productionDate;

	/* Space padded Manufacturer ID (zero terminator not required) */
	uint8_t manufacturerId[32];

	/* Space Padded name of the FM (zero terminator not required) */
	uint8_t productId[16];

} FM_Header_t;
extern const FM_Header_t FM_HEADER;

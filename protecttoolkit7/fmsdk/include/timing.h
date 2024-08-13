/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: timing.h
 */

#ifndef INC_TIMING_H
#define INC_TIMING_H
#include <stdint.h>

/* Structure used to store timing information */
typedef struct THR_TIME {
	uint32_t secs;	/* Number of seconds */
	uint32_t ns;		/* Number of nanoseconds */
} THR_TIME;

/**
 * This function can be used to start a high-resolution timing operation. The
 * timing resolution is 20 ns, and the accuracy of the timer is about 1
 * microsecond.
 *
 * @param start
 *     Address of the THR_TIME structure, which will keep the information
 *     needed to measure the timing interval.
 */
void THR_BeginTiming(
		THR_TIME *start
);

/**
 * This function is used to update the timing operation. Since the start
 * structure is not modified, it can be used multiple times with the same set
 * of parameters.
 *
 * @param start
 *     Address of the THR_TIME structure that was passed to the
 *     THR_BeginTiming() function. The contents of the structure will not be
 *     modified.
 * @param elapsed
 *     Address of the THR_TIME structure, which will contain the elapsed time
 *     since THR_BeginTiming() was called. The contents of this structure will
 *     be overwritten.
 */
void THR_UpdateTiming(
		const THR_TIME *start,
		THR_TIME *elapsed
);

#endif /* INC_TIMING_H */

/*
 * Copyright (c) 2018 SafeNet Inc.
 */
#include <mkfmhdr.h>

#define MY_FM_NUMBER 0x700

DEFINE_FM_HEADER(MY_FM_NUMBER,
        FM_MAKE_VERSION(4,2),
		0,
		"Safenet Inc.",
		"USB Port IF");

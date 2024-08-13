#ifndef _FM_USB_DEFS_
#define _FM_USB_DEFS_

#include <stdint.h>

typedef struct _capacity {
	uint32_t max_lba_msb;    //used for 'Read Capacity 16'. Contains MSB of max block number.
	uint32_t max_lba;        //max number of logical block on the device for 'Read Capacity 10'
	                         //or LSB of max number of logical block for 'Read Capacity 16'.
	uint32_t block_size;
	uint32_t device_size;    //Contains device size in Gb. 32 bits are capable to hold the capacity of 4G.
} capacity_t;

typedef struct _dev_properties {
	uint16_t vendorId;
	uint16_t productId;
	uint8_t lun;
	uint8_t endpoint_in;
	uint8_t endpoint_out;
} dev_properties_t;

#endif

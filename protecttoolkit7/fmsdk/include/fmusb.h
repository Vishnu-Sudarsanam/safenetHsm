#ifndef _USBFSAPI_
#define _USBFSAPI_

#include <fmusbdefs.h>

#define BLOCK_SIZE_M  512 /* default value */

#define CKR_USB_VENDOR_DEFINED  0x80000000
#define CKR_USB_OK              0
#define CKR_USB_GENERAL_ERROR   CKR_USB_VENDOR_DEFINED + 0x100
#define CKR_USB_INITIALIZED	    CKR_USB_VENDOR_DEFINED + 0x101
#define CKR_USB_NO_DEVICES	    CKR_USB_VENDOR_DEFINED + 0x102
#define CKR_USB_TRANSFER	    CKR_USB_VENDOR_DEFINED + 0x103
#define CKR_USB_FS_EXISTS	    CKR_USB_VENDOR_DEFINED + 0x104
#define CKR_USB_MEMORY		    CKR_USB_VENDOR_DEFINED + 0x105
#define CKR_USB_FS_NOT_PRESENT  CKR_USB_VENDOR_DEFINED + 0x106
#define CKR_USB_FS_NOT_OPENED   CKR_USB_VENDOR_DEFINED + 0x107

/*
 * Prototypes:
 */
int USBFS_Init(void *ctxv, void **handlev, dev_properties_t *dp, capacity_t *cap, int *kernelDriverAttachedFlag);
int USBFS_Finalize(void *ctx, void *handlev, int *kernelDriverAttachedFlag, uint8_t **header);
int USBFS_New(void *handle, char * label, dev_properties_t *dp, capacity_t *cap, uint8_t **header);
int USBFS_Open(void *handle, dev_properties_t *dp, capacity_t *cap, uint8_t **header);
int USBFS_Close(void *handlev, dev_properties_t *dp, capacity_t *cap, uint8_t *header);
int USBFS_GetInfo(void *handle, dev_properties_t *dp, capacity_t *cap, uint32_t *dataLen, uint8_t *label, uint8_t *header);
int USBFS_WriteData(void *handle, dev_properties_t *dp, capacity_t *cap, uint8_t *data, uint32_t dataLen, uint8_t *header);
int USBFS_Append (void *handlev, dev_properties_t *dp, capacity_t *cap, uint8_t *data, uint32_t dataLen, uint8_t *header);
int USBFS_ReadData(void *handle, dev_properties_t *dp, capacity_t *cap, uint8_t *data, uint32_t *dataLen, uint8_t *header);
int USBFS_Destroy(void *handle, dev_properties_t *dp, capacity_t *cap, uint8_t **header);

#endif

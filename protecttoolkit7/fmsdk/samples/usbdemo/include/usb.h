/*
 * Copyright (c) 2018 SafeNet Inc.
 */

#ifndef INC_UP_CMDS_H
#define INC_UP_CMDS_H

#include <stdint.h>

#define MAX_FS_LABEL_LEN 32

#define RESERVED        0

/*
 * The commands that can be sent to the API test FM. */
typedef enum UP_Cmd_et
{
	FMUSB_NEW = 1,
	FMUSB_INFO,
	FMUSB_WRITE,
	FMUSB_READ,
	FMUSB_APPEND,
	FMUSB_DESTROY,
	FMUSB_DATA_EXCHANGE_TEST
} UP_Cmd_t;

/*
 * Request message structure:
 * <cmd><labelLen><label><dataLen><data>
  * The following field contains the following data for different commands:
 * FMUSB_NEW => <cmd><labelLen><label>
 *           <= <statusLen><status>
 * FMUSB_INFO => <cmd>,
 *            <= <statusLen><status><labelLen><label><FsDataLen>
 * FMUSB_WRITE => <cmd><labelLen><label><FsDataLen><FsData>,
 *             <= <statusLen><status>
 * FMUSB_APPEND => <cmd><labelLen><label><FsDataLen><FsData>,
 *              <= <status>
 * FMUSB_READ => <cmd><labelLen><label><FsDataLen>,
 *               <= <statusLen><status><FsDataLen><FsData>
 * FMUSB_DESTROY => the field contains NULL.
 *               >= <statusLen><status>
 */

#endif /* INC_UP_CMDS_H */

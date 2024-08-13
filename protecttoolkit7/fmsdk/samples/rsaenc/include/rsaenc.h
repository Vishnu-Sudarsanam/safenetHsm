/*
 *
 * Copyright (c) 2000,2001 ERACOM Pty. Ltd.
 * All Rights Reserved - Proprietary Information of ERACOM Pty. Ltd.
 * Not to be Construed as a Published Work.
 *
 */

/*
 * This header file contains the function declarations and type definitions for
 * the RSA_ENC custom API.
 */
#ifndef INC_RSAENC_H
#define INC_RSAENC_H

/*
 * Description:
 *    Encrypt a message using the RSA key stored in token in slot 0. The key
 *    must  have the CKA_LABEL attribute value equal to the string specified in
 *    the parameter 'id'.
 *
 * Parameters:
 *    id: The label of the key to be used.
 *    in: Address of the buffer that contains the data to be encrypted.
 *    inLen: Number of bytes in the input buffer 'in'.
 *    out: The buffer which will receive the encrypted data.
 *    outLen: Address of the variable that holds the number of available bytes
 *    in the buffer 'out' before the function call, and the number of bytes
 *    availabel after the function returns successfully.
 */
int RSA_Enc(char *id, char *in, int inLen, char *out, int *outLen);

#endif /* INC_RSAENC_H */

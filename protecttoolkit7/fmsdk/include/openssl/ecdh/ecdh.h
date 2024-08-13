/***************************************************************************\
 * This file is protected by laws protecting trade secrets and confidential
 * information, as well as copyright laws and international treaties.
 * Copyright (C) 2003 Chrysalis-ITS Incorporated and its licensors.
 * All rights reserved.
\***************************************************************************/

/* crypto/ecdh/ecdh.h */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * The Elliptic Curve Public-Key Crypto Library (ECC Code) included
 * herein is developed by SUN MICROSYSTEMS, INC., and is contributed
 * to the OpenSSL project.
 *
 * The ECC Code is licensed pursuant to the OpenSSL open source
 * license provided below.
 *
 * In addition, Sun covenants to all licensees who provide a reciprocal
 * covenant with respect to their own patents if any, not to sue under
 * current and future patent claims necessarily infringed by the making,
 * using, practicing, selling, offering for sale and/or otherwise
 * disposing of the ECC Code as delivered hereunder (or portions thereof),
 * provided that such covenant shall not apply:
 *  1) for code that a licensee deletes from the ECC Code;
 *  2) separates from the ECC Code; or
 *  3) for infringements caused by:
 *       i) the modification of the ECC Code or
 *      ii) the combination of the ECC Code with other software or
 *          devices where such combination causes the infringement.
 *
 * The ECDH software is originally written by Douglas Stebila of
 * Sun Microsystems Laboratories.
 *
 */
/* ====================================================================
 * Copyright (c) 2000-2002 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
#ifndef HEADER_ECDH_H
#define HEADER_ECDH_H

#include "../bn/bn.h"
#include "../ec/ec.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ecdh_method 
{
	const char *name;
	int32_t (*compute_key)(unsigned char *key, uint32_t keyBufLen, const EC_POINT *pub_key, EC_KEY *ecdh, uint8_t cofactor);
	EC_POINT* (*compute_point)(EC_POINT* r, const EC_POINT *pub_key, EC_KEY *ecdh, uint8_t cofactor);
	int32_t (*compute_point2oct)(unsigned char *to, uint32_t toBufLen, const EC_POINT *pub_key, EC_KEY *ecdh, uint8_t cofactor);
} ECDH_METHOD;

typedef struct ecdh_data_st {
	/* EC_KEY_METH_DATA part */
	int32_t (*init)(EC_KEY *);
	void (*finish)(EC_KEY *);
	/* method specific part */
	const ECDH_METHOD *meth;
} ECDH_DATA; 

/* ECDH_DATA functions */
ECDH_DATA *ECDH_DATA_new(ECDH_DATA *ret);
void ECDH_DATA_free(ECDH_DATA *);

ECDH_DATA *ecdh_start(ECDH_DATA *ecdh, EC_KEY *key);
ECDH_DATA *ecdh_check(EC_KEY *);


const ECDH_METHOD *ECDH_OpenSSL(void);

int32_t ECDH_size(const EC_KEY *);
int32_t ECDH_compute_key(unsigned char *key, uint32_t keyBufLen, const EC_POINT *pub_key, EC_KEY *ecdh, uint8_t cofactor);
EC_POINT* ECDH_compute_point(EC_POINT *r, const EC_POINT *pub_key, EC_KEY *ecdh, uint8_t cofactor);
int32_t ECDH_compute_point2oct(unsigned char *to, uint32_t toBufLen, const EC_POINT *pub_key, EC_KEY *ecdh, uint8_t cofactor);



/* BEGIN ERROR CODES */

/* Reason codes. */
#define ECDH_R_NO_PRIVATE_VALUE				 100
#define ECDH_R_POINT_ARITHMETIC_FAILURE			 101
#define ECDH_R_SHA1_DIGEST_FAILED			 102

#ifdef  __cplusplus
}
#endif
#endif



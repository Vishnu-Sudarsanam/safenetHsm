/* crypto/ecdsa/ecdsa.h */
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
#ifndef HEADER_ECDSA_H
#define HEADER_ECDSA_H

#include "../bn/bn.h"
#include "../ec/ec.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ECDSA_SIG_st
{
	BIGNUM *r;
	BIGNUM *s;
	BN_DeclareInStructure(myR, EC_BN_MAX_BITS);
	BN_DeclareInStructure(myS, EC_BN_MAX_BITS);
} ECDSA_SIG;

typedef struct ecdsa_method 
{
	const char *name;
	int (*ecdsa_do_sign)(ECDSA_SIG *ret, const unsigned char *dgst, int dgst_len,
			EC_KEY *eckey, const unsigned char *rnd);
	int (*ecdsa_sign_setup)(const unsigned char *rnd, EC_KEY *eckey, BN_CTX *ctx, BIGNUM *kinv, 
			BIGNUM *r);
	int (*ecdsa_do_verify)(const unsigned char *dgst, int dgst_len, 
			ECDSA_SIG *sig, EC_KEY *eckey);
} ECDSA_METHOD;

typedef struct ecdsa_data_st {
	/* EC_KEY_METH_DATA part */
	int (*init)(EC_KEY *);
	void (*finish)(EC_KEY *);
	/* method specific part */
	BIGNUM	*kinv;	/* signing pre-calc */
	BIGNUM	*r;	/* signing pre-calc */
	BN_DeclareInStructure(myKinv, EC_BN_MAX_BITS);
	BN_DeclareInStructure(myR, EC_BN_MAX_BITS);
	const ECDSA_METHOD *meth;
} ECDSA_DATA; 

/* signature functions */
ECDSA_SIG *ECDSA_SIG_new(ECDSA_SIG *ret);
void	  ECDSA_SIG_free(ECDSA_SIG *a);

/* ECDSA_DATA functions */
ECDSA_DATA *ECDSA_DATA_new(ECDSA_DATA *);
void ECDSA_DATA_free(ECDSA_DATA *);

ECDSA_DATA *ecdsa_check(EC_KEY *);
ECDSA_DATA *ecdsa_start(ECDSA_DATA *, EC_KEY *);

int   ECDSA_do_sign(ECDSA_SIG *ret, const unsigned char *dgst, int dgst_len, EC_KEY *, const unsigned char *rnd);
int	  ECDSA_do_verify(const unsigned char *dgst, int dgst_len, ECDSA_SIG *sig, EC_KEY* eckey);

const ECDSA_METHOD *ECDSA_OpenSSL(void);

int ECDSA_size(const EC_KEY *);
int ECDSA_sign_setup(const unsigned char *rnd, EC_KEY *eckey, BN_CTX *ctx, BIGNUM *kinv, BIGNUM *r);
int ECDSA_sign(const unsigned char *dgst, int dgst_len, unsigned char *sig, unsigned int *siglen, EC_KEY *eckey, const unsigned char *rnd);
int ECDSA_verify(const unsigned char *dgst, int dgst_len, 
		const unsigned char *sig, int sig_len, EC_KEY *eckey);

/* Error codes for the ECDSA functions. */

/* Reason codes. */
#define ECDSA_R_BAD_SIGNATURE                   100
#define ECDSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE     101
#define ECDSA_R_ERR_EC_LIB                      102
#define ECDSA_R_MISSING_PARAMETERS              103
#define ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED 104
#define ECDSA_R_SIGNATURE_MALLOC_FAILED         105

#ifdef  __cplusplus
}
#endif
#endif


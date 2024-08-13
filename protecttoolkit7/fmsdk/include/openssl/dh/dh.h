/***************************************************************************\
 * This file is protected by laws protecting trade secrets and confidential
 * information, as well as copyright laws and international treaties.
 * Copyright (C) 2003 Chrysalis-ITS Incorporated and its licensors.
 * All rights reserved.
\***************************************************************************/

/* crypto/dh/dh.h */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#ifndef HEADER_DH_H
#define HEADER_DH_H

#ifdef NO_DH
#error DH is disabled.
#endif

#include "../bn/bn.h"               /* BIGNUM library */

#define OSSL_DH_PART_ALLOC_BITS     2048
#define OSSL_DH_MAX_PART_BITS       2048
#define OSSL_DH_MAX_PART_LEN        BYTES_IN_BITS(OSSL_DH_MAX_PART_BITS)

#define DH_FLAG_CACHE_MONT_P	0x01

#ifdef  __cplusplus
extern "C" {
#endif


typedef struct DH_COMP_st    OSSL_DH_COMP;
typedef struct dh_st         OSSL_DH_CTX;

typedef struct dh_domain_st  OSSL_DH_DOMAIN;
typedef struct dh_pub_key_st OSSL_DH_PUB_KEY;
typedef struct dh_pri_key_st OSSL_DH_PRI_KEY;

struct DH_COMP_st
   {
   BN_DeclareInStructure(Y, OSSL_DH_PART_ALLOC_BITS);
   BN_DeclareInStructure(k, OSSL_DH_PART_ALLOC_BITS);
   };

struct dh_domain_st
   {
   BN_DeclareInStructure(p, OSSL_DH_PART_ALLOC_BITS);
   BN_DeclareInStructure(g, OSSL_DH_PART_ALLOC_BITS);
   BN_MONT_CTX    method_mont_p;
   };

struct dh_pub_key_st
   {
   BN_DeclareInStructure(key, OSSL_DH_PART_ALLOC_BITS);  /* y public key */
   };

struct dh_pri_key_st
   {
   BN_DeclareInStructure(key, OSSL_DH_PART_ALLOC_BITS);   /* x private key */
   };

struct dh_st
   {
   struct dh_domain_st*  dom;
   struct dh_pub_key_st* pub;
   struct dh_pri_key_st* pri;
   int fw_unlock;
   };


void OSSL_DH_comp_init(OSSL_DH_COMP *comp);
void OSSL_DH_comp_release(OSSL_DH_COMP *comp);

void OSSL_DH_dom_init(OSSL_DH_DOMAIN *dom);
void OSSL_DH_dom_precompute(OSSL_DH_DOMAIN *dom);
void OSSL_DH_dom_copy(OSSL_DH_DOMAIN *to, OSSL_DH_DOMAIN *from);
void OSSL_DH_dom_release(OSSL_DH_DOMAIN *dom);
void OSSL_DH_dom_release_clean(OSSL_DH_DOMAIN *dom);

void OSSL_DH_pri_key_init(OSSL_DH_PRI_KEY *key);
void OSSL_DH_pri_key_copy(OSSL_DH_PRI_KEY *to, OSSL_DH_PRI_KEY *from);
void OSSL_DH_pri_key_release(OSSL_DH_PRI_KEY *key);
void OSSL_DH_pri_key_release_clean(OSSL_DH_PRI_KEY *key);

void OSSL_DH_pub_key_init(OSSL_DH_PUB_KEY *key);
void OSSL_DH_pub_key_copy(OSSL_DH_PUB_KEY *to, OSSL_DH_PUB_KEY *from);
void OSSL_DH_pub_key_release(OSSL_DH_PUB_KEY *key);
void OSSL_DH_pub_key_release_clean(OSSL_DH_PUB_KEY *key);

void OSSL_DH_ctx_init(OSSL_DH_CTX *dh, OSSL_DH_DOMAIN *dom, OSSL_DH_PUB_KEY *pub, OSSL_DH_PRI_KEY *pri, int fw_unlock);
void OSSL_DH_ctx_copy(OSSL_DH_CTX *to, OSSL_DH_CTX *from);
void OSSL_DH_ctx_release(OSSL_DH_CTX *dh);
void OSSL_DH_ctx_release_clean(OSSL_DH_CTX *dh);


#define OSSL_DH_GENERATOR_2		2
/* #define OSSL_DH_GENERATOR_3	3 */
#define OSSL_DH_GENERATOR_5		5

/* DH_check error codes */
#define OSSL_DH_CHECK_P_NOT_PRIME           0x01
#define OSSL_DH_CHECK_P_NOT_SAFE_PRIME      0x02
#define OSSL_DH_UNABLE_TO_CHECK_GENERATOR   0x04
#define OSSL_DH_NOT_SUITABLE_GENERATOR      0x08

/* primes p where (p-1)/2 is prime too are called "safe"; we define
   this for backward compatibility: */
#define DH_CHECK_P_NOT_STRONG_PRIME	DH_CHECK_P_NOT_SAFE_PRIME

OSSL_DH_CTX *OSSL_DH_generate_parameters(OSSL_DH_CTX *dh, int prime_len, int generator,
		void (*callback)(int,int,void *),void *cb_arg);
int	   OSSL_DH_check(OSSL_DH_CTX *dh,int *codes);
int	   OSSL_DH_generate_key(OSSL_DH_CTX *dh, int bits);
int      OSSL_DH_compute_key(OSSL_DH_CTX *dh, OSSL_DH_COMP *comp);


/* BEGIN ERROR CODES */

/* Error codes for the DH functions. */

/* Function codes. */
#define DH_F_DHPARAMS_PRINT            100
#define DH_F_DHPARAMS_PRINT_FP         101
#define DH_F_DH_COMPUTE_KEY            102
#define DH_F_DH_GENERATE_KEY           103
#define DH_F_DH_GENERATE_PARAMETERS    104
#define DH_F_DH_NEW                    105

/* Reason codes. */
#define DH_R_BAD_GENERATOR             101
#define DH_R_NO_PRIVATE_VALUE          100

#ifdef  __cplusplus
}
#endif
#endif

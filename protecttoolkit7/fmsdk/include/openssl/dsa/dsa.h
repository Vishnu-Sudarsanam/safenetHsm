/***************************************************************************\
 * This file is protected by laws protecting trade secrets and confidential
 * information, as well as copyright laws and international treaties.
 * Copyright (C) 2003 Chrysalis-ITS Incorporated and its licensors.
 * All rights reserved.
\***************************************************************************/

/* crypto/dsa/dsa.h */
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

/*
 * The DSS routines are based on patches supplied by
 * Steven Schoch <schoch@sheba.arc.nasa.gov>.  He basically did the
 * work and I have just tweaked them a little to fit into my
 * stylistic vision for SSLeay :-) */


/*
 * To avoid name conflicts all publicly visible names were prepended with "OSSL"
 * prefix. Infrastructure providing means for dynamic "attachment" of different
 * long math engines and different algorithms implementations was removed. I/O
 * was removed too.
*/

#ifndef HEADER_DSA_H
#define HEADER_DSA_H

#ifdef NO_DSA
#error DSA is disabled.
#endif

#include "../bn/bn.h"

#define OSSL_DSA_P_ALLOC_BITS       3072
#define OSSL_DSA_Q_ALLOC_BITS       (256 + sizeof(BN_ULONG)*8)

#define OSSL_DSA_MAX_P_SIZE_BITS    OSSL_DSA_P_ALLOC_BITS
#define OSSL_DSA_MAX_Q_SIZE_BITS    256

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct DSA_SIG_st     OSSL_DSA_SIG;
typedef struct dsa_st         OSSL_DSA_CTX;

typedef struct dsa_domain_st  OSSL_DSA_DOMAIN;
typedef struct dsa_pub_key_st OSSL_DSA_PUB_KEY;
typedef struct dsa_pri_key_st OSSL_DSA_PRI_KEY;

struct DSA_SIG_st
   {
   BN_DeclareInStructure(r, OSSL_DSA_Q_ALLOC_BITS);
   BN_DeclareInStructure(s, OSSL_DSA_Q_ALLOC_BITS);
   };

struct dsa_domain_st
   {
   BN_DeclareInStructure(p, OSSL_DSA_P_ALLOC_BITS);
   BN_DeclareInStructure(q, OSSL_DSA_Q_ALLOC_BITS);
   BN_DeclareInStructure(g, OSSL_DSA_P_ALLOC_BITS);
   BN_MONT_CTX    method_mont_p;
   };

struct dsa_pub_key_st
   {
   BN_DeclareInStructure(key, OSSL_DSA_P_ALLOC_BITS);  /* y public key */
   };

struct dsa_pri_key_st
   {
   BN_DeclareInStructure(key, OSSL_DSA_Q_ALLOC_BITS);     /* x private key */
   };

struct dsa_st
   {
   int fw_unlock;
   struct dsa_domain_st*  dom;
   struct dsa_pub_key_st* pub;
   struct dsa_pri_key_st* pri;
   BN_DeclareInStructure(kinv, OSSL_DSA_Q_ALLOC_BITS);   /* Signing pre-calc */
   BN_DeclareInStructure(r, OSSL_DSA_Q_ALLOC_BITS);      /* Signing pre-calc */
   };


void OSSL_DSA_sig_init(OSSL_DSA_SIG *sig);
void OSSL_DSA_sig_release(OSSL_DSA_SIG *sig);

void OSSL_DSA_dom_init(OSSL_DSA_DOMAIN *dom);
void OSSL_DSA_dom_precompute(OSSL_DSA_DOMAIN *dom);
void OSSL_DSA_dom_copy(OSSL_DSA_DOMAIN *to, OSSL_DSA_DOMAIN *from);
void OSSL_DSA_dom_release(OSSL_DSA_DOMAIN *dom);
void OSSL_DSA_dom_release_clean(OSSL_DSA_DOMAIN *dom);

void OSSL_DSA_pri_key_init(OSSL_DSA_PRI_KEY *key);
void OSSL_DSA_pri_key_copy(OSSL_DSA_PRI_KEY *to, OSSL_DSA_PRI_KEY *from);
void OSSL_DSA_pri_key_release(OSSL_DSA_PRI_KEY *key);
void OSSL_DSA_pri_key_release_clean(OSSL_DSA_PRI_KEY *key);

void OSSL_DSA_pub_key_init(OSSL_DSA_PUB_KEY *key);
void OSSL_DSA_pub_key_copy(OSSL_DSA_PUB_KEY *to, OSSL_DSA_PUB_KEY *from);
void OSSL_DSA_pub_key_release(OSSL_DSA_PUB_KEY *key);
void OSSL_DSA_pub_key_release_clean(OSSL_DSA_PUB_KEY *key);

void OSSL_DSA_ctx_init(OSSL_DSA_CTX *dsa, OSSL_DSA_DOMAIN *dom, OSSL_DSA_PUB_KEY *pub, OSSL_DSA_PRI_KEY *pri, int fw_unlock);
void OSSL_DSA_ctx_copy(OSSL_DSA_CTX *to, OSSL_DSA_CTX *from);
void OSSL_DSA_ctx_release(OSSL_DSA_CTX *dsa);
void OSSL_DSA_ctx_release_clean(OSSL_DSA_CTX *dsa);

int  OSSL_DSA_sign_setup(OSSL_DSA_CTX *dsa, const unsigned char *random_opt);

OSSL_DSA_SIG*     OSSL_DSA_sign(OSSL_DSA_CTX *dsa,
                            OSSL_DSA_SIG *sig,
                            const unsigned char *dgst, int dlen,
                            const unsigned char *random_opt);

int               OSSL_DSA_verify(OSSL_DSA_CTX *dsa,
                              const unsigned char *dgst,
                              int dgst_len,
                              OSSL_DSA_SIG *sig);

OSSL_DSA_CTX *OSSL_DSA_generate_parameters(OSSL_DSA_CTX *dsa,
                                           unsigned int L,
                                           unsigned int N,
                                           unsigned char *seed,
                                           unsigned int seedLen,
                                           unsigned int *counter_ret,
                                           unsigned int *h_ret);

int               OSSL_DSA_generate_key(OSSL_DSA_CTX *dsa);


/* Primality test according to FIPS PUB 186[-3], Table C.1 */
#define OSSL_DSS_prime_checks_for_size(b) ((b) >= 3072 ?  64 : \
                                           (b) >= 2048 ?  56 : 50) // This should be 40 but it's upped
                                                                   // to 50 to conform with FIPS 186-2
#define OSSL_DSA_is_prime(n, callback, cb_arg, fw_unlock) \
   BN_is_prime(n, OSSL_DSS_prime_checks_for_size(BN_num_bits(n)), callback, NULL, cb_arg, fw_unlock)


/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */

/* Error codes for the DSA functions. */

/* Function codes. */
#define DSA_F_D2I_DSA_SIG             110
#define DSA_F_DSAPARAMS_PRINT             100
#define DSA_F_DSAPARAMS_PRINT_FP          101
#define DSA_F_DSA_DO_SIGN             112
#define DSA_F_DSA_DO_VERIFY             113
#define DSA_F_DSA_NEW                103
#define DSA_F_DSA_PRINT                104
#define DSA_F_DSA_PRINT_FP             105
#define DSA_F_DSA_SIGN                106
#define DSA_F_DSA_SIGN_SETUP             107
#define DSA_F_DSA_SIG_NEW             109
#define DSA_F_DSA_VERIFY             108
#define DSA_F_I2D_DSA_SIG             111

/* Reason codes. */
#define DSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE       100
#define DSA_R_MISSING_PARAMETERS          101

#ifdef  __cplusplus
}
#endif
#endif

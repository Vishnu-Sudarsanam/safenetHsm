/***************************************************************************\
 * This file is protected by laws protecting trade secrets and confidential
 * information, as well as copyright laws and international treaties.
 * Copyright (C) 2003 Chrysalis-ITS Incorporated and its licensors.
 * All rights reserved.
\***************************************************************************/

/* crypto/rsa/rsa.h */
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

#ifndef HEADER_RSA_H
#define HEADER_RSA_H

#include "../bn/bn.h"                     /* Large number engine */

#ifdef NO_RSA
#error OSSL_RSA_CTX is disabled.
#endif

#ifdef  __cplusplus
extern "C" {
#endif

/* Common max size in bits for n, e, and d components.
 * This accounts for BN library behaviour, which often expands
 * operands one word larger than their final size, in order
 * to complete computations. Use these values to allocate BIGNUM components.
 * DON'T use these values for verifying key geometry. Use the constants
 * from ca_expor.h instead.
*/
#define OSSL_RSA_PART_ALLOC_BITS       (8192 + 32)

/* Common max and min sizes in bits for p, q, exp_p, exp_q, coeff.
 * The same as above applies to this constant too.
*/
#define OSSL_RSA_SUB_PART_ALLOC_BITS   (((8192*115)/200) & ~7)


struct rsa_pub_key
   {
   BN_DeclareInStructure(n,      OSSL_RSA_PART_ALLOC_BITS);
   BN_DeclareInStructure(e,      OSSL_RSA_PART_ALLOC_BITS);
   /* Used to cache montgomery values */
   BN_MONT_CTX _method_mod_n;
   };

/*
* WARNING!
* It is critical that the first three fields are the
* exact copy of the struct rsa_pub_key, so we can
* cast struct rsa_pri_key to struct rsa_pub_key.
*/
struct rsa_pri_key
   {
   BN_DeclareInStructure(n,      OSSL_RSA_PART_ALLOC_BITS);
   BN_DeclareInStructure(e,      OSSL_RSA_PART_ALLOC_BITS);
   BN_MONT_CTX _method_mod_n;

   BN_DeclareInStructure(d,      OSSL_RSA_PART_ALLOC_BITS);
   BN_DeclareInStructure(p,      OSSL_RSA_SUB_PART_ALLOC_BITS);
   BN_DeclareInStructure(q,      OSSL_RSA_SUB_PART_ALLOC_BITS);
   BN_DeclareInStructure(dmp1,   OSSL_RSA_SUB_PART_ALLOC_BITS);
   BN_DeclareInStructure(dmq1,   OSSL_RSA_SUB_PART_ALLOC_BITS);
   BN_DeclareInStructure(iqmp,   OSSL_RSA_SUB_PART_ALLOC_BITS);
   /* Used to cache montgomery values */
   BN_MONT_CTX _method_mod_p;
   BN_MONT_CTX _method_mod_q;
   };


struct rsa_st
   {
   struct rsa_pri_key* key;

   int flags;
   int fw_unlock;

   /* former   BN_BLINDING *blinding: blinding cache */
   BN_DeclareInStructure(A,  OSSL_RSA_PART_ALLOC_BITS);
   BN_DeclareInStructure(Ai, OSSL_RSA_PART_ALLOC_BITS);
   };


typedef struct rsa_pub_key   OSSL_RSA_PUB_KEY;
typedef struct rsa_pri_key   OSSL_RSA_PRI_KEY;
typedef struct rsa_st        OSSL_RSA_CTX;


struct RSAKeyGenTestParam
{
   // in
   BN_DeclareInStructure(xp,     OSSL_RSA_SUB_PART_ALLOC_BITS);
   BN_DeclareInStructure(xp1,    OSSL_RSA_SUB_PART_ALLOC_BITS);
   BN_DeclareInStructure(xp2,    OSSL_RSA_SUB_PART_ALLOC_BITS);
   // in
   BN_DeclareInStructure(xq,     OSSL_RSA_SUB_PART_ALLOC_BITS);
   BN_DeclareInStructure(xq1,    OSSL_RSA_SUB_PART_ALLOC_BITS);
   BN_DeclareInStructure(xq2,    OSSL_RSA_SUB_PART_ALLOC_BITS);
   // out
   BN_DeclareInStructure(n,      OSSL_RSA_PART_ALLOC_BITS);
   BN_DeclareInStructure(d,      OSSL_RSA_PART_ALLOC_BITS);
   BN_DeclareInStructure(p,      OSSL_RSA_SUB_PART_ALLOC_BITS);
   BN_DeclareInStructure(p1,     OSSL_RSA_SUB_PART_ALLOC_BITS);
   BN_DeclareInStructure(p2,     OSSL_RSA_SUB_PART_ALLOC_BITS);
   BN_DeclareInStructure(q,      OSSL_RSA_SUB_PART_ALLOC_BITS);
   BN_DeclareInStructure(q1,     OSSL_RSA_SUB_PART_ALLOC_BITS);
   BN_DeclareInStructure(q2,     OSSL_RSA_SUB_PART_ALLOC_BITS);
};

#define RSA_3                       0x3L
#define RSA_F4                      0x10001L

#define RSA_METHOD_FLAG_NO_CHECK    0x01 /* don't check pub/private match */

#define RSA_FLAG_CACHE_PUBLIC       0x02
#define RSA_FLAG_CACHE_PRIVATE      0x04
#define RSA_FLAG_BLINDING           0x08

#define RSA_PKCS1_PADDING              1
#define RSA_SSLV23_PADDING             2
#define RSA_NO_PADDING                 3
#define RSA_PKCS1_OAEP_PADDING         4

#define RSA_PKCS1_PADDING_SIZE         11

OSSL_RSA_PUB_KEY* OSSL_RSA_key_init_pub(OSSL_RSA_PUB_KEY *key);
OSSL_RSA_PUB_KEY* OSSL_RSA_key_precompute_pub(OSSL_RSA_PUB_KEY *key);
OSSL_RSA_PUB_KEY* OSSL_RSA_key_release_pub(OSSL_RSA_PUB_KEY *key);
OSSL_RSA_PUB_KEY* OSSL_RSA_key_release_clean_pub(OSSL_RSA_PUB_KEY *key);

OSSL_RSA_PRI_KEY* OSSL_RSA_key_init_pri(OSSL_RSA_PRI_KEY *key);
OSSL_RSA_PRI_KEY* OSSL_RSA_key_precompute_pri(OSSL_RSA_PRI_KEY *key);
OSSL_RSA_PRI_KEY* OSSL_RSA_key_release_pri(OSSL_RSA_PRI_KEY *key);
OSSL_RSA_PRI_KEY* OSSL_RSA_key_release_clean_pri(OSSL_RSA_PRI_KEY *key);

OSSL_RSA_CTX*     OSSL_RSA_ctx_init_pub(OSSL_RSA_CTX *rsa, OSSL_RSA_PUB_KEY *key, int fw_unlock);
OSSL_RSA_CTX*     OSSL_RSA_ctx_init_pri(OSSL_RSA_CTX *rsa, OSSL_RSA_PRI_KEY *key, int fw_unlock);
OSSL_RSA_CTX*     OSSL_RSA_ctx_release(OSSL_RSA_CTX *rsa);
OSSL_RSA_CTX*     OSSL_RSA_ctx_release_clean(OSSL_RSA_CTX *rsa);


// Added two primitive functions
int OSSL_RSA_public_exp(int flen, unsigned char *from,
	     unsigned char *to, int *tlen, OSSL_RSA_CTX *rsa);
int OSSL_RSA_private_exp(int flen, unsigned char *from,
	     unsigned char *to, int *tlen, OSSL_RSA_CTX *rsa);



OSSL_RSA_CTX * OSSL_RSA_generate_key_e_value(OSSL_RSA_CTX *, int bits, unsigned long e,
        OSSL_CALLBACK callback, void *cb_arg);

OSSL_RSA_CTX * OSSL_RSA_generate_key(OSSL_RSA_CTX *rsa, int bits, const unsigned char *e, int e_len,
        OSSL_CALLBACK callback, void *cb_arg);

OSSL_RSA_CTX * OSSL_RSA_generate_key_X9_31(OSSL_RSA_CTX *rsa, int bits, const unsigned char *e, int e_len,
        OSSL_CALLBACK callback, void *cb_arg, struct RSAKeyGenTestParam *testParam);

OSSL_RSA_CTX *rsa_generate_key_186_3_prime(OSSL_RSA_CTX *rsa, int bits,
        OSSL_CALLBACK callback, void *cb_arg);

int rsa_no_generate_key_186_3_prime_only_verify(BIGNUM *ret, BIGNUM *e, int bits, int fw_unlock);

int  OSSL_RSA_no_generate_key_186_3_Prime_Only_Verify(OSSL_RSA_CTX *rsa, int bits,
         const unsigned char *e, int e_len, struct RSAKeyGenTestParam *testParam);

OSSL_RSA_CTX *OSSL_RSA_generate_key_186_3_Prime(OSSL_RSA_CTX *rsa, int bits,
        const unsigned char *e, int e_len,
        OSSL_CALLBACK callback, void *cb_arg);

OSSL_RSA_CTX *rsa_generate_key_186_3_aux_prime(OSSL_RSA_CTX *rsa, int bits,
        OSSL_CALLBACK callback, void *cb_arg, struct RSAKeyGenTestParam *testParam);

OSSL_RSA_CTX *OSSL_RSA_generate_key_186_3_Aux_Prime(OSSL_RSA_CTX *rsa, int bits,
        const unsigned char *e, int e_len,
        OSSL_CALLBACK callback, void *cb_arg, struct RSAKeyGenTestParam *testParam);

int   OSSL_RSA_check_key(OSSL_RSA_CTX *);

int   OSSL_RSA_flags(OSSL_RSA_CTX *r);

void  OSSL_RSA_blinding_on(OSSL_RSA_CTX *rsa);
void  OSSL_RSA_blinding_off(OSSL_RSA_CTX *rsa);

void  OSSL_RSA_fw_unlock_on(OSSL_RSA_CTX *rsa);
void  OSSL_RSA_fw_unlock_off(OSSL_RSA_CTX *rsa);

int   OSSL_RSA_blinding_convert(OSSL_RSA_CTX *rsa, BIGNUM *v);
int   OSSL_RSA_blinding_invert(OSSL_RSA_CTX *rsa, BIGNUM *v);


/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */

/* Error codes for the OSSL_RSA_CTX functions. */

/* Function codes. */
#define RSA_F_MEMORY_LOCK                       100
#define RSA_F_RSA_CHECK_KEY                     123
#define RSA_F_RSA_EAY_PRIVATE_DECRYPT           101
#define RSA_F_RSA_EAY_PRIVATE_ENCRYPT           102
#define RSA_F_RSA_EAY_PUBLIC_DECRYPT            103
#define RSA_F_RSA_EAY_PUBLIC_ENCRYPT            104
#define RSA_F_RSA_GENERATE_KEY                  105
#define RSA_F_RSA_NEW_METHOD                    106
#define RSA_F_RSA_NULL                          124
#define RSA_F_RSA_PADDING_ADD_NONE              107
#define RSA_F_RSA_PADDING_ADD_PKCS1_OAEP        121
#define RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_1      108
#define RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_2      109
#define RSA_F_RSA_PADDING_ADD_SSLV23            110
#define RSA_F_RSA_PADDING_CHECK_NONE            111
#define RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP      122
#define RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1    112
#define RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2    113
#define RSA_F_RSA_PADDING_CHECK_SSLV23          114
#define RSA_F_RSA_PRINT                         115
#define RSA_F_RSA_PRINT_FP                      116
#define RSA_F_RSA_SIGN                          117
#define RSA_F_RSA_SIGN_ASN1_OCTET_STRING        118
#define RSA_F_RSA_VERIFY                        119
#define RSA_F_RSA_VERIFY_ASN1_OCTET_STRING      120

/* Reason codes. */
#define RSA_R_ALGORITHM_MISMATCH                100
#define RSA_R_BAD_E_VALUE                       101
#define RSA_R_BAD_FIXED_HEADER_DECRYPT          102
#define RSA_R_BAD_PAD_BYTE_COUNT                103
#define RSA_R_BAD_SIGNATURE                     104
#define RSA_R_BLOCK_TYPE_IS_NOT_01              106
#define RSA_R_BLOCK_TYPE_IS_NOT_02              107
#define RSA_R_DATA_GREATER_THAN_MOD_LEN         108
#define RSA_R_DATA_TOO_LARGE                    109
#define RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE       110
#define RSA_R_DATA_TOO_LARGE_FOR_MODULUS        132
#define RSA_R_DATA_TOO_SMALL                    111
#define RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE       122
#define RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY        112
#define RSA_R_DMP1_NOT_CONGRUENT_TO_D           124
#define RSA_R_DMQ1_NOT_CONGRUENT_TO_D           125
#define RSA_R_D_E_NOT_CONGRUENT_TO_1            123
#define RSA_R_INVALID_MESSAGE_LENGTH            131
#define RSA_R_IQMP_NOT_INVERSE_OF_Q             126
#define RSA_R_KEY_SIZE_TOO_SMALL                120
#define RSA_R_NULL_BEFORE_BLOCK_MISSING         113
#define RSA_R_N_DOES_NOT_EQUAL_P_Q              127
#define RSA_R_OAEP_DECODING_ERROR               121
#define RSA_R_PADDING_CHECK_FAILED              114
#define RSA_R_P_NOT_PRIME                       128
#define RSA_R_Q_NOT_PRIME                       129
#define RSA_R_RSA_OPERATIONS_NOT_SUPPORTED      130
#define RSA_R_SSLV3_ROLLBACK_ATTACK             115
#define RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD 116
#define RSA_R_UNKNOWN_ALGORITHM_TYPE            117
#define RSA_R_UNKNOWN_PADDING_TYPE              118
#define RSA_R_WRONG_SIGNATURE_LENGTH            119


#ifdef  __cplusplus
}
#endif
#endif

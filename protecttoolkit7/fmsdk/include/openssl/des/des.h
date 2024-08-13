/***************************************************************************\
 * This file is protected by laws protecting trade secrets and confidential
 * information, as well as copyright laws and international treaties.
 * Copyright (C) 2003 Chrysalis-ITS Incorporated and its licensors.
 * All rights reserved.
\***************************************************************************/

/* crypto/des/des.h */
/* Copyright (C) 1995-1997 Eric Young (eay@cryptsoft.com)
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

#ifndef HEADER_DES_H
#define HEADER_DES_H

#ifdef NO_DES
#error DES is disabled.
#endif


/* Taken from <openssl/opensslconf.h> */
#define DES_LONG unsigned long

#ifdef  __cplusplus
extern "C" {
#endif

typedef unsigned char des_cblock[8];
typedef /* const */ unsigned char const_des_cblock[8];
/* With "const", gcc 2.8.1 on Solaris thinks that des_cblock *
 * and const_des_cblock * are incompatible pointer types. */

typedef struct des_ks_struct
	{
	union	{
		des_cblock cblock;
		/* make sure things are correct size on machines with
		 * 8 byte longs */
		DES_LONG deslong[2];
		} ks;
	int weak_key;
	} des_key_schedule[16];

#define DES_KEY_SZ 	(sizeof(des_cblock))
#define DES_SCHEDULE_SZ (sizeof(des_key_schedule))

#define DES_ENCRYPT	1
#define DES_DECRYPT	0

#define des_ecb2_encrypt(i,o,k1,k2,e) \
	des_ecb3_encrypt((i),(o),(k1),(k2),(k1),(e))

void des_ecb3_encrypt(const_des_cblock *input, des_cblock *output,
		      des_key_schedule ks1,des_key_schedule ks2,
		      des_key_schedule ks3, int enc);



void des_ecb_encrypt(const_des_cblock *input,des_cblock *output,
		     des_key_schedule ks,int enc);

/* 	This is the DES encryption function that gets called by just about
	every other DES routine in the library.  You should not use this
	function except to implement 'modes' of DES.  I say this because the
	functions that call this routine do the conversion from 'char *' to
	long, and this needs to be done to make sure 'non-aligned' memory
	access do not occur.  The characters are loaded 'little endian'.
	Data is a pointer to 2 unsigned long's and ks is the
	des_key_schedule to use.  enc, is non zero specifies encryption,
	zero if decryption. */
void des_encrypt1(DES_LONG *data,des_key_schedule ks, int enc);

/* 	This functions is the same as des_encrypt1() except that the DES
	initial permutation (IP) and final permutation (FP) have been left
	out.  As for des_encrypt1(), you should not use this function.
	It is used by the routines in the library that implement triple DES.
	IP() des_encrypt2() des_encrypt2() des_encrypt2() FP() is the same
	as des_encrypt1() des_encrypt1() des_encrypt1() except faster :-). */
void des_encrypt2(DES_LONG *data,des_key_schedule ks, int enc);

void des_encrypt3(DES_LONG *data, des_key_schedule ks1,
	des_key_schedule ks2, des_key_schedule ks3);
void des_decrypt3(DES_LONG *data, des_key_schedule ks1,
	des_key_schedule ks2, des_key_schedule ks3);


void des_set_odd_parity(des_cblock *key);
int des_check_key_parity(const_des_cblock *key);
void des_set_key_unchecked(const_des_cblock *key, des_key_schedule schedule);


#ifdef  __cplusplus
}
#endif

#endif

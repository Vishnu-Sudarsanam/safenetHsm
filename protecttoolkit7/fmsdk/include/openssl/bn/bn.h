/***************************************************************************\
 * This file is protected by laws protecting trade secrets and confidential
 * information, as well as copyright laws and international treaties.
 * Copyright (C) 2003 Chrysalis-ITS Incorporated and its licensors.
 * All rights reserved.
\***************************************************************************/

/* crypto/bn/bn.h */
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by 
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the Eric Young open source
 * license provided above.
 *
 * In addition, Sun covenants to all licensees who provide a reciprocal
 * covenant with respect to their own patents if any, not to sue under
 * current and future patent claims necessarily infringed by the making,
 * using, practicing, selling, offering for sale and/or otherwise
 * disposing of the Contribution as delivered hereunder 
 * (or portions thereof), provided that such covenant shall not apply:
 *  1) for code that a licensee deletes from the Contribution;
 *  2) separates from the Contribution; or
 *  3) for infringements caused by:
 *       i) the modification of the Contribution or
 *      ii) the combination of the  Contribution with other software or
 *          devices where such combination causes the infringement.
 *
 * The binary polynomial arithmetic software is originally written by 
 * Sheueling Chang Shantz and Douglas Stebila of Sun Microsystems Laboratories.
 *
 */

#ifndef HEADER_BN_H
#define HEADER_BN_H

#include <stddef.h>
#include <stdint.h>

#if (_MSC_VER <=1600)
#define inline __inline
#endif

#define BYTES_IN_BITS( n )      ( ( (n) +    7 )  >>  3 )

#ifndef BITS_PER_BYTE
#define BITS_PER_BYTE           8
#endif

#define BITS_IN_BYTES( n )      ( (n) <<  3 )

static inline uint32_t mszbits_u32(uint32_t val)
{
   uint32_t count;
   for(count = 32; val; count--) val >>= 1;
   return count;
}

/* Returns number of most significant 0-bits in the byte value */
static inline uint32_t mszbits_u8(uint8_t v)
{
   return mszbits_u32(v) - 24;
}

#  define false 0
#  define true  !false

/* OSSL_CALLBACK is an application callback */
typedef void (* OSSL_CALLBACK)(
  int value1,
  int value2,
  void *buffer
);

// These files is an interface of the BN library to our environment

#define THIRTY_TWO_BIT // NEV

#ifdef  __cplusplus
extern "C" {
#endif

#ifdef OPENSSL_SYS_VMS
#undef BN_LLONG /* experimental, so far... */
#endif

#define BN_MUL_COMBA
#define BN_SQR_COMBA
//#define BN_RECURSION
#if defined(__arm)
#define BN_MUL_ASSEMBLY
#endif

/* This next option uses the C libraries (2 word)/(1 word) function.
 * If it is not defined, I use my C version (which is slower).
 * The reason for this flag is that when the particular C compiler
 * library routine is used, and the library is linked with a different
 * compiler, the library is missing.  This mostly happens when the
 * library is built with gcc and then linked using normal cc.  This would
 * be a common occurrence because gcc normally produces code that is
 * 2 times faster than system compilers for the big number stuff.
 * For machines with only one compiler (or shared libraries), this should
 * be on.  Again this in only really a problem on machines
 * using "long long's", are 32bit, and are not using my assembler code. */
#if defined(OPENSSL_SYS_MSDOS) || defined(OPENSSL_SYS_WINDOWS) || \
    defined(OPENSSL_SYS_WIN32) || defined(linux)
# ifndef BN_DIV2W
#  define BN_DIV2W
# endif
#endif

/* assuming long is 64bit - this is the DEC Alpha
 * unsigned long long is only 64 bits :-(, don't define
 * BN_LLONG for the DEC Alpha */
#ifdef SIXTY_FOUR_BIT_LONG
#define BN_ULLONG	unsigned long long
#define BN_ULONG	unsigned long
#define BN_LONG		long
#define BN_BITS		128
#define BN_BYTES	8
#define BN_BITS2	64
#define BN_BITS4	32
#define BN_MASK		(0xffffffffffffffffffffffffffffffffLL)
#define BN_MASK2	(0xffffffffffffffffL)
#define BN_MASK2l	(0xffffffffL)
#define BN_MASK2h	(0xffffffff00000000L)
#define BN_MASK2h1	(0xffffffff80000000L)
#define BN_TBIT		(0x8000000000000000L)
#define BN_DEC_CONV	(10000000000000000000UL)
#define BN_DEC_FMT1	"%lu"
#define BN_DEC_FMT2	"%019lu"
#define BN_DEC_NUM	19
#endif

/* This is where the long long data type is 64 bits, but long is 32.
 * For machines where there are 64bit registers, this is the mode to use.
 * IRIX, on R4000 and above should use this mode, along with the relevant
 * assembler code :-).  Do NOT define BN_LLONG.
 */
#ifdef SIXTY_FOUR_BIT
#undef BN_LLONG
#undef BN_ULLONG
#define BN_ULONG	unsigned long long
#define BN_LONG		long long
#define BN_BITS		128
#define BN_BYTES	8
#define BN_BITS2	64
#define BN_BITS4	32
#define BN_MASK2	(0xffffffffffffffffLL)
#define BN_MASK2l	(0xffffffffL)
#define BN_MASK2h	(0xffffffff00000000LL)
#define BN_MASK2h1	(0xffffffff80000000LL)
#define BN_TBIT		(0x8000000000000000LL)
#define BN_DEC_CONV	(10000000000000000000ULL)
#define BN_DEC_FMT1	"%llu"
#define BN_DEC_FMT2	"%019llu"
#define BN_DEC_NUM	19
#endif

#ifdef THIRTY_TWO_BIT
#if defined(OPENSSL_SYS_WIN32) && !defined(__GNUC__)
#define BN_ULLONG	unsigned _int64
#else
#define BN_ULLONG	unsigned long long
#endif
#define BN_ULONG	unsigned int
#define BN_LONG		int
#define BN_BITS		64
#define BN_BYTES	4
#define BN_BITS2	32
#define BN_BITS4	16
#ifdef OPENSSL_SYS_WIN32
/* VC++ doesn't like the LL suffix */
#define BN_MASK		(0xffffffffffffffffL)
#else
#define BN_MASK		(0xffffffffffffffffLL)
#endif
#define BN_MASK2	(0xffffffffL)
#define BN_MASK2l	(0xffff)
#define BN_MASK2h1	(0xffff8000L)
#define BN_MASK2h	(0xffff0000L)
#define BN_TBIT		(0x80000000L)
#define BN_DEC_CONV	(1000000000L)
#define BN_DEC_FMT1	"%lu"
#define BN_DEC_FMT2	"%09lu"
#define BN_DEC_NUM	9
#endif

#ifdef SIXTEEN_BIT
#ifndef BN_DIV2W
#define BN_DIV2W
#endif
#define BN_ULLONG	unsigned long
#define BN_ULONG	unsigned short
#define BN_LONG		short
#define BN_BITS		32
#define BN_BYTES	2
#define BN_BITS2	16
#define BN_BITS4	8
#define BN_MASK		(0xffffffff)
#define BN_MASK2	(0xffff)
#define BN_MASK2l	(0xff)
#define BN_MASK2h1	(0xff80)
#define BN_MASK2h	(0xff00)
#define BN_TBIT		(0x8000)
#define BN_DEC_CONV	(100000)
#define BN_DEC_FMT1	"%u"
#define BN_DEC_FMT2	"%05u"
#define BN_DEC_NUM	5
#endif

#ifdef EIGHT_BIT
#ifndef BN_DIV2W
#define BN_DIV2W
#endif
#define BN_ULLONG	unsigned short
#define BN_ULONG	unsigned char
#define BN_LONG		char
#define BN_BITS		16
#define BN_BYTES	1
#define BN_BITS2	8
#define BN_BITS4	4
#define BN_MASK		(0xffff)
#define BN_MASK2	(0xff)
#define BN_MASK2l	(0xf)
#define BN_MASK2h1	(0xf8)
#define BN_MASK2h	(0xf0)
#define BN_TBIT		(0x80)
#define BN_DEC_CONV	(100)
#define BN_DEC_FMT1	"%u"
#define BN_DEC_FMT2	"%02u"
#define BN_DEC_NUM	2
#endif

#define BN_DEFAULT_BITS	1280

/* Use the size one word larger than maximum operand size to cover for many cases
 * when one word expansion is required
*/
#define BN_MAX_BITS	   (8192 + 32)

#ifdef BIGNUM
#undef BIGNUM
#endif

typedef struct bignum_st
	{	
	int neg;	/* one if the number is negative */
	int dmax;	/* Size of the d array. */
	int top;	/* Index of last used d +1. */	
	BN_ULONG d[1];	/* value of the BIGNUM, least significant BN_BITS2 first */
	} BIGNUM;

#define BN_ULONGS_IN_BITS(bits)  ((BYTES_IN_BITS((bits))+sizeof(BN_ULONG)-1)/sizeof(BN_ULONG))

/* Macro to declare a local BIGNUM *variable on the stack.
 * We always allocate one word more than requested to account for
 * BIGNUM library behaviour: it often expands operands of the BN_xxx()
 * functions for one word.
 */

#define BN_Declare(variableName, sizeInBits) \
   struct \
   { \
      BIGNUM bigNum; \
      BN_ULONG d[BN_ULONGS_IN_BITS((sizeInBits)) > 1 ? BN_ULONGS_IN_BITS((sizeInBits)) : 1]; \
   } variableName##Space; \
   BIGNUM *variableName = &variableName##Space.bigNum

// function to declare a local BIGNUM [] variable on the stack
#define BN_DeclareArray(variableName, sizeInBits, arraySize) \
   typedef struct \
   { \
      BIGNUM bigNum; \
      BN_ULONG d[BN_ULONGS_IN_BITS((sizeInBits)) > 1 ? BN_ULONGS_IN_BITS((sizeInBits)) : 1]; \
   } variableName##Space; \
   variableName##Space variableName[arraySize]

// function to declare a BIGNUM variable within a structure
#define BN_DeclareInStructure(variableName, sizeInBits) \
   BIGNUM variableName; \
   struct \
   { \
      BN_ULONG d[BN_ULONGS_IN_BITS((sizeInBits)) > 1 ? BN_ULONGS_IN_BITS((sizeInBits)) : 1]; \
   } variableName##Space

// function to get the word size of a BIGNUM
#define BN_GetWordSize(variableName) (sizeof(variableName##Space.d) / sizeof(BN_ULONG) + 1)

/* Used for temp variables (declaration hidden in bn_lcl.h) */
typedef struct bignum_ctx BN_CTX;

typedef struct bn_blinding_st
	{
	int init;
	BN_DeclareInStructure(A, BN_MAX_BITS);
	BN_DeclareInStructure(Ai, BN_MAX_BITS);
	BIGNUM *mod; /* just a reference */
	} BN_BLINDING;


/* Used for montgomery multiplication */
typedef struct bn_mont_ctx_st
	{
	int ri;                          /* number of bits in R */
	BN_DeclareInStructure(RR, BN_MAX_BITS*2+1);/* used to convert to montgomery form */
	BN_DeclareInStructure(N, BN_MAX_BITS);     /* The modulus */
	BN_DeclareInStructure(Ni, BN_MAX_BITS);    /* R*(1/R mod N) - N*Ni = 1
	                                  * (Ni is only stored for bignum algorithm) */
	BN_ULONG n0;                     /* least significant word of Ni */
	} BN_MONT_CTX;

/* Used for reciprocal division/mod functions
 * It cannot be shared between threads
 */
typedef struct bn_recp_ctx_st
	{
	BN_DeclareInStructure(N,BN_MAX_BITS);	/* the divisor */
	BN_DeclareInStructure(Nr,BN_MAX_BITS);	/* the reciprocal */
	int num_bits;
	int shift;
	} BN_RECP_CTX;

#define BN_prime_checks 0 /* default: select number of iterations
			     based on the size of the number */

/* number of Miller-Rabin iterations for an error rate  of less than 2^-80
 * for random 'b'-bit input, b >= 100 (taken from table 4.4 in the Handbook
 * of Applied Cryptography [Menezes, van Oorschot, Vanstone; CRC Press 1996];
 * original paper: Damgaard, Landrock, Pomerance: Average case error estimates
 * for the strong probable prime test. -- Math. Comp. 61 (1993) 177-194) */
#define BN_prime_checks_for_size(b) ((b) >= 1300 ?  2 : \
                                (b) >=  850 ?  3 : \
                                (b) >=  650 ?  4 : \
                                (b) >=  550 ?  5 : \
                                (b) >=  450 ?  6 : \
                                (b) >=  400 ?  7 : \
                                (b) >=  350 ?  8 : \
                                (b) >=  300 ?  9 : \
                                (b) >=  250 ? 12 : \
                                (b) >=  200 ? 15 : \
                                (b) >=  150 ? 18 : \
                                /* b >= 100 */ 27)
 
#define BN_num_bytes(a)	((BN_num_bits(a)+7)/8)

/* Note that BN_abs_is_word does not work reliably for w == 0 */
#define BN_abs_is_word(a,w) (((a)->top == 1) && ((a)->d[0] == (BN_ULONG)(w)))
#define BN_is_zero(a)       (((a)->top == 0) || BN_abs_is_word(a,0))
#define BN_is_one(a)        (BN_abs_is_word((a),1) && !(a)->neg)
#define BN_is_word(a,w)     ((w) ? BN_abs_is_word((a),(w)) && !(a)->neg : \
                                   BN_is_zero((a)))
#define BN_is_odd(a)	    (((a)->top > 0) && ((a)->d[0] & 1))
#define BN_make_it_odd(a)	    (((a)->d[0]) = ((a)->d[0]) ^ (0x00000001))

#define BN_one(a)	(BN_set_word((a),1))
#define BN_zero(a)	(BN_set_word((a),0))

/*#define BN_ascii2bn(a)	BN_hex2bn(a) */
/*#define BN_bn2ascii(a)	BN_bn2hex(a) */

const BIGNUM *BN_value_one(void);
const BIGNUM *BN_value_two(void);
const BIGNUM *BN_value_64K_plus_1(void);
const BIGNUM *BN_value_2_pow_256(void);
char *	BN_options(void);
int     BN_rand(BIGNUM *rnd, int bits, int top,int bottom);
int     BN_pseudo_rand(BIGNUM *rnd, int bits, int top,int bottom);
int	BN_rand_range(BIGNUM *rnd, const BIGNUM *range);
int	BN_pseudo_rand_range(BIGNUM *rnd, const BIGNUM *range);
int	BN_num_bits(const BIGNUM *a);
int	BN_num_bits_word(BN_ULONG);
void BN_Constructor(BIGNUM *a, int size);
void BN_Destructor(BIGNUM *a);
void BN_DestructorClean(BIGNUM *a);
BIGNUM *BN_copy(BIGNUM *to, const BIGNUM *from);
//void	BN_swap(BIGNUM *a, BIGNUM *b);
void	BN_swap(BIGNUM **a, BIGNUM **b);

BIGNUM *BN_bin2bn(const unsigned char *s,int len,BIGNUM *ret);
int   BN_bn2bin_safe(const BIGNUM *a, unsigned char *to, int length);
int   BN_bn2bin(const BIGNUM *a, unsigned char *to);
int   BN_bn_2_fixed_len_bin(const BIGNUM *a, unsigned char *to, unsigned int fixedLength);
int   BN_bn2binLE(const BIGNUM *a, unsigned char *to);
int   BN_bn2binLE_safe(const BIGNUM *a, unsigned char *to, int length);


#define BN_PREPARE_WITH_STATIC_WORD_VALUE(bn, val) \
        static bVisited##bn = false;\
        if (!bVisited##bn) {\
           BN_Constructor(bn, BN_GetWordSize(bn));\
           BN_set_word(bn,val);\
           bVisited##bn = true;\
        }
  
#define BN_bn2be        BN_bn2bin
#define BN_bn2be_safe   BN_bn2bin_safe
#define BN_bn2be_fixed  BN_bn_2_fixed_len_bin
#define BN_bn2le        BN_bn2binLE
#define BN_bn2le_safe   BN_bn2binLE_safe
BIGNUM *BN_mpi2bn(const unsigned char *s,int len,BIGNUM *ret);
int	BN_bn2mpi(const BIGNUM *a, unsigned char *to);
int	BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int	BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int	BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int	BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int	BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int	BN_sqr(BIGNUM *r, const BIGNUM *a,BN_CTX *ctx);

int	BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d,
	BN_CTX *ctx);

#define BN_mod(rem,m,d,ctx) BN_div(NULL,(rem),(m),(d),(ctx))

int	BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx);
int	BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
int	BN_mod_add_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m);
int	BN_mod_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
int	BN_mod_sub_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m);
int	BN_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
	const BIGNUM *m, BN_CTX *ctx);
int	BN_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
int	BN_mod_lshift1(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
int	BN_mod_lshift1_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *m);
int	BN_mod_lshift(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m, BN_CTX *ctx);
int	BN_mod_lshift_quick(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m);

BN_ULONG BN_mod_word(const BIGNUM *a, BN_ULONG w);
BN_ULONG BN_div_word(BIGNUM *a, BN_ULONG w);
int	BN_mul_word(BIGNUM *a, BN_ULONG w);
int	BN_add_word(BIGNUM *a, BN_ULONG w);
int	BN_sub_word(BIGNUM *a, BN_ULONG w);
int	BN_set_word(BIGNUM *a, BN_ULONG w);
BN_ULONG BN_get_word(const BIGNUM *a);

int	BN_cmp(const BIGNUM *a, const BIGNUM *b);
int	BN_is_bit_set(const BIGNUM *a, int n);
int	BN_lshift(BIGNUM *r, const BIGNUM *a, int n);
int	BN_lshift1(BIGNUM *r, const BIGNUM *a);
int	BN_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,BN_CTX *ctx);

int	BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
	const BIGNUM *m,BN_CTX *ctx, int fw_unlock);
int	BN_mod_exp_mont(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
	const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx, int fw_unlock);
int	BN_mod_exp_mont_word(BIGNUM *r, BN_ULONG a, const BIGNUM *p,
	const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx, int fw_unlock);
int	BN_mod_exp2_mont(BIGNUM *r, const BIGNUM *a1, const BIGNUM *p1,
	const BIGNUM *a2, const BIGNUM *p2,const BIGNUM *m,
	BN_CTX *ctx,BN_MONT_CTX *m_ctx, int fw_unlock);
int	BN_mod_exp_simple(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
	const BIGNUM *m,BN_CTX *ctx, int fw_unlock);

int	BN_mask_bits(BIGNUM *a,int n);
int	BN_print(const BIGNUM *a);
int	BN_reciprocal(BIGNUM *r, const BIGNUM *m, int len, BN_CTX *ctx);
int	BN_rshift(BIGNUM *r, const BIGNUM *a, int n);
int	BN_rshift1(BIGNUM *r, const BIGNUM *a);
void	BN_clear(BIGNUM *a);
BIGNUM *BN_dup(const BIGNUM *a);
int	BN_ucmp(const BIGNUM *a, const BIGNUM *b);
int	BN_set_bit(BIGNUM *a, int n);
int	BN_clear_bit(BIGNUM *a, int n);
char *  BN_bn2hex(const BIGNUM *a, char *buf);
int 	BN_hex2bn(BIGNUM **a, const char *str);
int   BN_hex2binLE(const char *a, unsigned char *to);
int   BN_hex2binLE_safe(const char *a, unsigned char *to, int length);

int 	BN_dec2bn(BIGNUM **a, const char *str);
int	BN_gcd(BIGNUM *r,const BIGNUM *a,const BIGNUM *b,BN_CTX *ctx);
int	BN_kronecker(const BIGNUM *a,const BIGNUM *b,BN_CTX *ctx); /* returns -2 for error */
BIGNUM *BN_mod_inverse(BIGNUM *ret,
	const BIGNUM *a, const BIGNUM *n,BN_CTX *ctx);
BIGNUM *BN_mod_sqrt(BIGNUM *ret,
	const BIGNUM *a, const BIGNUM *n,BN_CTX *ctx);
BIGNUM *BN_generate_prime_MlrRbn_trials_func(BIGNUM *ret, int bits, int safe, int fermat,
	const BIGNUM *add, const BIGNUM *rem, const BIGNUM *e,
	OSSL_CALLBACK callback, void *cb_arg, int (*MlrRbn_TrialsFunc) (int prime_len), int fw_unlock);

static inline BIGNUM *BN_generate_prime(BIGNUM *ret,int bits,int safe,int fermat,
	const BIGNUM *add, const BIGNUM *rem, const BIGNUM *e,
	OSSL_CALLBACK callback,void *cb_arg, int fw_unlock)
{
   return BN_generate_prime_MlrRbn_trials_func(ret, bits, safe, fermat,
            add, rem, e, callback, cb_arg, NULL, fw_unlock);
}
 
int	BN_is_prime(const BIGNUM *p,int nchecks,
	OSSL_CALLBACK callback,
	BN_CTX *ctx,void *cb_arg, int fw_unlock);
int	BN_is_prime_fasttest(const BIGNUM *p,int nchecks,
	OSSL_CALLBACK callback,BN_CTX *ctx,void *cb_arg,
	int do_trial_division, int fw_unlock);

int BN_mod_mul_montgomery(BIGNUM *r,const BIGNUM *a,const BIGNUM *b,
	BN_MONT_CTX *mont, BN_CTX *ctx);

#define BN_to_montgomery(r,a,mont,ctx)	BN_mod_mul_montgomery((r),(a),&((mont)->RR),(mont),(ctx))
int BN_from_montgomery(BIGNUM *r,const BIGNUM *a, BN_MONT_CTX *mont, BN_CTX *ctx);

void         BN_MONT_CTX_init(BN_MONT_CTX *mont);
void         BN_MONT_CTX_release(BN_MONT_CTX *mont);
int          BN_MONT_CTX_set(BN_MONT_CTX *mont,const BIGNUM *mod,BN_CTX *ctx);
BN_MONT_CTX *BN_MONT_CTX_copy(BN_MONT_CTX *to,BN_MONT_CTX *from);
void         BN_MONT_CTX_zero(BN_MONT_CTX *mont);

void BN_set_params(int mul,int high,int low,int mont);
int BN_get_params(int which); /* 0, mul, 1 high, 2 low, 3 mont */

void BN_RECP_CTX_init(BN_RECP_CTX *recp);
int	BN_RECP_CTX_set(BN_RECP_CTX *recp,const BIGNUM *rdiv,BN_CTX *ctx);
int	BN_mod_mul_reciprocal(BIGNUM *r, const BIGNUM *x, const BIGNUM *y,
	BN_RECP_CTX *recp,BN_CTX *ctx);
int	BN_mod_exp_recp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
	const BIGNUM *m, BN_CTX *ctx, int fw_unlock);
int	BN_div_recp(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m,
	BN_RECP_CTX *recp, BN_CTX *ctx);

int BN_mod_exp_crt(BIGNUM *r, BIGNUM *a, BIGNUM *p, BIGNUM *q,
   BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp, BN_MONT_CTX *mont_p, BN_MONT_CTX *mont_q, int fw_unlock);


/* Functions for arithmetic over binary polynomials represented by BIGNUMs. 
 *
 * The BIGNUM::neg property of BIGNUMs representing binary polynomials is ignored.
 *
 * Note that input arguments are not const so that their bit arrays can
 * be expanded to the appropriate size if needed.
 */
int	BN_GF2m_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b); /* r = a + b */
#define BN_GF2m_sub(r, a, b) BN_GF2m_add(r, a, b)
int	BN_GF2m_mod(BIGNUM *r, const BIGNUM *a, const BIGNUM *p); /* r = a mod p */
int	BN_GF2m_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx); /* r = (a * b) mod p */
int	BN_GF2m_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx); /* r = (a * a) mod p */
int BN_GF2m_mod_inv(BIGNUM *r, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx); /* r = (1 / b) mod p */
int BN_GF2m_mod_div(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx); /* r = (a / b) mod p */
int BN_GF2m_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx); /* r = (a ^ b) mod p */
int BN_GF2m_mod_sqrt(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx); /* r = sqrt(a) mod p */
int BN_GF2m_mod_solve_quad(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx); /* r^2 + r = a mod p */
#define BN_GF2m_cmp(a, b) BN_ucmp((a), (b))
/* Some functions allow for representation of the irreducible polynomials
 * as an unsigned int[], say p.  The irreducible f(t) is then of the form:
 *     t^p[0] + t^p[1] + ... + t^p[k]
 * where m = p[0] > p[1] > ... > p[k] = 0.
 */
int	BN_GF2m_mod_arr(BIGNUM *r, const BIGNUM *a, const unsigned int p[]); /* r = a mod p */
int	BN_GF2m_mod_mul_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const unsigned int p[], BN_CTX *ctx); /* r = (a * b) mod p */
int	BN_GF2m_mod_sqr_arr(BIGNUM *r, const BIGNUM *a, const unsigned int p[], BN_CTX *ctx); /* r = (a * a) mod p */
int BN_GF2m_mod_inv_arr(BIGNUM *r, const BIGNUM *b, const unsigned int p[], BN_CTX *ctx); /* r = (1 / b) mod p */
int BN_GF2m_mod_div_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const unsigned int p[], BN_CTX *ctx); /* r = (a / b) mod p */
int BN_GF2m_mod_exp_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const unsigned int p[], BN_CTX *ctx); /* r = (a ^ b) mod p */
int BN_GF2m_mod_sqrt_arr(BIGNUM *r, const BIGNUM *a, const unsigned int p[], BN_CTX *ctx); /* r = sqrt(a) mod p */
int BN_GF2m_mod_solve_quad_arr(BIGNUM *r, const BIGNUM *a, const unsigned int p[], BN_CTX *ctx); /* r^2 + r = a mod p */
int BN_GF2m_poly2arr(const BIGNUM *a, unsigned int p[], int max);
int BN_GF2m_arr2poly(const unsigned int p[], BIGNUM *a);

/* library internal functions */

#define bn_expand(a,bits) ((((((bits+BN_BITS2-1))/BN_BITS2)) <= (a)->dmax) ? (a):NULL)
#define bn_wexpand(a,words) (((words) <= (a)->dmax)?(a):NULL)

#define bn_fix_top(a) \
        { \
        BN_ULONG *ftl; \
	if ((a)->top > 0) \
		{ \
		for (ftl= &((a)->d[(a)->top-1]); (a)->top > 0; (a)->top--) \
		if (*(ftl--)) break; \
		} \
	}

BN_ULONG bn_mul_add_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w);
BN_ULONG bn_mul_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w);
void     bn_sqr_words(BN_ULONG *rp, const BN_ULONG *ap, int num);
BN_ULONG bn_div_words(BN_ULONG h, BN_ULONG l, BN_ULONG d);
BN_ULONG bn_add_words(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,int num);
BN_ULONG bn_sub_words(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,int num);

#ifdef BN_DEBUG
void bn_dump1(FILE *o, const char *a, const BN_ULONG *b,int n);
# define bn_print(a) {fprintf(stderr, #a "="); BN_print_fp(stderr,a); \
   fprintf(stderr,"\n");}
# define bn_dump(a,n) bn_dump1(stderr,#a,a,n);
#else
# define bn_print(a)
# define bn_dump(a,b)
#endif

int BN_bntest_rand(BIGNUM *rnd, int bits, int top,int bottom);

/* Error codes for the BN functions. */

/* Reason codes. */
#define BN_R_ARG2_LT_ARG3				 100
#define BN_R_BAD_RECIPROCAL				 101
#define BN_R_BIGNUM_TOO_LONG				 114
#define BN_R_CALLED_WITH_EVEN_MODULUS			 102
#define BN_R_DIV_BY_ZERO				 103
#define BN_R_ENCODING_ERROR				 104
#define BN_R_EXPAND_ON_STATIC_BIGNUM_DATA		 105
#define BN_R_INPUT_NOT_REDUCED				 110
#define BN_R_INVALID_LENGTH				 106
#define BN_R_INVALID_RANGE				 115
#define BN_R_NOT_A_SQUARE				 111
#define BN_R_NOT_IMPLEMENTED				 116
#define BN_R_NOT_INITIALIZED				 107
#define BN_R_NO_INVERSE					 108
#define BN_R_P_IS_NOT_PRIME				 112
#define BN_R_TOO_MANY_ITERATIONS			 113
#define BN_R_TOO_MANY_TEMPORARY_VARIABLES		 109

#ifdef  __cplusplus
}
#endif
#endif

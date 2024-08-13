/***************************************************************************\
 * This file is protected by laws protecting trade secrets and confidential
 * information, as well as copyright laws and international treaties.
 * Copyright (C) 2002-2003 Chrysalis-ITS Incorporated and its licensors.
 * All rights reserved.
\***************************************************************************/

/*
 * Originally written by Bodo Moeller for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 1998-2002 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by 
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
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
 *      ii) the combination of the Contribution with other software or
 *          devices where such combination causes the infringement.
 *
 * The elliptic curve binary polynomial software is originally written by 
 * Sheueling Chang Shantz and Douglas Stebila of Sun Microsystems Laboratories.
 *
 */

#ifndef HEADER_EC_H
#define HEADER_EC_H

#include "../bn/bn.h"

//#define OPENSSL_EC_BIN_PT_COMP

#define EC_MAX_POINTS      32
#define EC_MAX_SEED_LEN    20
#define EC_BN_MAX_BITS	   2048

#define EC_BN_MAX_LEN      ((EC_BN_MAX_BITS+7)/8)

typedef enum {
	/* values as defined in X9.62 (ECDSA) and elsewhere */
	POINT_CONVERSION_COMPRESSED = 2,
	POINT_CONVERSION_UNCOMPRESSED = 4,
	POINT_CONVERSION_HYBRID = 6
} point_conversion_form_t;


typedef struct ec_method_st EC_METHOD;

typedef struct ec_group_st
	/*
	 EC_METHOD *meth;
	 -- field definition
	 -- curve coefficients
	 -- optional generator with associated information (order, cofactor)
	 -- optional extra data (TODO: precomputed table for fast computation of multiples of generator)
	 -- ASN1 stuff
	*/
	EC_GROUP;

typedef struct ec_point_st EC_POINT;

/*
This structure represents builtin curve data in its ascii-hex format.
*/
typedef struct ec_curve_data_st {
	int	field_type;	/* either NID_X9_62_prime_field or
				 * NID_X9_62_characteristic_two_field */
	int   degree;     /* curve degree for Koblitz curves */
    int   T;          /* basis type T for Koblitz curves */
	const char *z;		/* Coeffecient Z for twisted curves */
	const char *p;		/* either a prime number or a polynomial */
	const char *a;
	const char *b;
	const char *x;		/* the x coordinate of the generator */
	const char *y;		/* the y coordinate of the generator */
	const char *order;	/* the order of the group generated by the
				 * generator */
	const BN_ULONG cofactor;/* the cofactor */
	const unsigned char *seed;/* the seed (optional) */
	size_t	seed_len;
	const char *comment;	/* a short (less than 80 characters)
				 * description of the curve */
} EC_CURVE_DATA;

/*
This structure represents builtin curve data that has been converted from its
ascii-hex format in EC_CURVE_DATA to hex binary format.
This conversion takes place during HSM startup.
The data is formatted in a way that is most useful by the specify HSM.
See EC_InitializeCurveData() for more details.
*/
typedef struct ec_curve_data_bin_st {
	int	field_type;	         /* either NID_X9_62_prime_field or
				                  * NID_X9_62_characteristic_two_field */
	int   degree;              /* curve degree for Koblitz curves */
   int   T;                   /* basis type T for Koblitz curves */
	unsigned char z[EC_BN_MAX_LEN];		/* Coeffecient Z for twisted curves */
   uint32_t zLen;
	unsigned char p[EC_BN_MAX_LEN];		/* either a prime number or a polynomial */
   uint32_t pLen;
	unsigned char a[EC_BN_MAX_LEN];
   uint32_t aLen;
	unsigned char b[EC_BN_MAX_LEN];
   uint32_t bLen;
	unsigned char x[EC_BN_MAX_LEN];		/* the x coordinate of the generator */
   uint32_t xLen;
	unsigned char y[EC_BN_MAX_LEN];		/* the y coordinate of the generator */
   uint32_t yLen;
	unsigned char order[EC_BN_MAX_LEN];	/* the order of the group generated by the generator */
   uint32_t orderLen;
   uint32_t orderLenInBits;              /* the length without the leading zeroes */
	BN_ULONG cofactor;/* the cofactor */
	unsigned char seed[EC_BN_MAX_LEN];/* the seed (optional) */
	size_t	seed_len;
	char *comment;	/* a short (less than 80 characters)
				 * description of the curve */
} EC_CURVE_DATA_BIN;


struct ec_method_st {
	/* used by EC_METHOD_get_field_type: */
	int32_t field_type; /* a NID */

	/* used by EC_GROUP_new, EC_GROUP_free, EC_GROUP_copy: */
	int32_t (*group_init)(EC_GROUP *);
	void (*group_finish)(EC_GROUP *);
	void (*group_clear_finish)(EC_GROUP *);
	int32_t (*group_copy)(EC_GROUP *, const EC_GROUP *);

	/* used by EC_GROUP_set_curve_GFp, EC_GROUP_get_curve_GFp, */
	/* EC_GROUP_set_curve_GF2m, and EC_GROUP_get_curve_GF2m: */
	int32_t (*group_set_curve)(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
	int32_t (*group_get_curve)(const EC_GROUP *, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *);

	/* used by EC_GROUP_get_degree: */
	int32_t (*group_get_degree)(const EC_GROUP *);

	/* used by EC_GROUP_check: */
	int32_t (*group_check_discriminant)(const EC_GROUP *, BN_CTX *);

	/* used by EC_POINT_new, EC_POINT_free, EC_POINT_clear_free, EC_POINT_copy: */
	int32_t (*point_init)(EC_POINT *);
	void (*point_finish)(EC_POINT *);
	void (*point_clear_finish)(EC_POINT *);
	int32_t (*point_copy)(EC_POINT *, const EC_POINT *);

	/* used by EC_POINT_set_to_infinity,
	 * EC_POINT_set_Jprojective_coordinates_GFp,
	 * EC_POINT_get_Jprojective_coordinates_GFp,
	 * EC_POINT_set_affine_coordinates_GFp,     ..._GF2m,
	 * EC_POINT_get_affine_coordinates_GFp,     ..._GF2m,
	 * EC_POINT_set_compressed_coordinates_GFp, ..._GF2m:
	 */
	int32_t (*point_set_to_infinity)(const EC_GROUP *, EC_POINT *);
	int32_t (*point_set_Jprojective_coordinates_GFp)(const EC_GROUP *, EC_POINT *,
		const BIGNUM *x, const BIGNUM *y, const BIGNUM *z, BN_CTX *);
	int32_t (*point_get_Jprojective_coordinates_GFp)(const EC_GROUP *, const EC_POINT *,
		BIGNUM *x, BIGNUM *y, BIGNUM *z, BN_CTX *);
	int32_t (*point_set_affine_coordinates)(const EC_GROUP *, EC_POINT *,
		const BIGNUM *x, const BIGNUM *y, BN_CTX *);
	int32_t (*point_get_affine_coordinates)(const EC_GROUP *, const EC_POINT *,
		BIGNUM *x, BIGNUM *y, BN_CTX *);
	int32_t (*point_set_compressed_coordinates)(const EC_GROUP *, EC_POINT *,
		const BIGNUM *x, int32_t y_bit, BN_CTX *);

	/* used by EC_POINT_point2oct, EC_POINT_oct2point: */
	size_t (*point2oct)(const EC_GROUP *, const EC_POINT *, point_conversion_form_t form,
	        unsigned char *buf, size_t len, BN_CTX *);
	int32_t (*oct2point)(const EC_GROUP *, EC_POINT *,
	        const unsigned char *buf, size_t len, BN_CTX *);

	/* used by EC_POINT_add, EC_POINT_dbl, ECP_POINT_invert: */
	int32_t (*add)(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *);
	int32_t (*dbl)(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, BN_CTX *);
	int32_t (*invert)(const EC_GROUP *, EC_POINT *, BN_CTX *);

	/* used by EC_POINTs_mul, EC_POINT_mul, EC_POINT_precompute_mult: */
	int32_t (*mul)(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
		size_t num, const EC_POINT *points[], const BIGNUM *scalars[], BN_CTX *);
	int32_t (*precompute_mult)(EC_GROUP *group, BN_CTX *);

	/* used by EC_POINT_is_at_infinity, EC_POINT_is_on_curve, EC_POINT_cmp: */
	int32_t (*is_at_infinity)(const EC_GROUP *, const EC_POINT *);
	int32_t (*is_on_curve)(const EC_GROUP *, const EC_POINT *, BN_CTX *);
	int32_t (*point_cmp)(const EC_GROUP *, const EC_POINT *a, const EC_POINT *b, BN_CTX *);

	/* used by EC_POINT_make_affine, EC_POINTs_make_affine: */
	int32_t (*make_affine)(const EC_GROUP *, EC_POINT *, BN_CTX *);
	int32_t (*points_make_affine)(const EC_GROUP *, size_t num, EC_POINT *[], BN_CTX *);


	/* internal functions */

	/* 'field_mul', 'field_sqr', and 'field_div' can be used by 'add' and 'dbl' so that
	 * the same implementations of point operations can be used with different
	 * optimized implementations of expensive field operations: */
	int32_t (*field_mul)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
	int32_t (*field_sqr)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);
	int32_t (*field_div)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *);

	int32_t (*field_encode)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *); /* e.g. to Montgomery */
	int32_t (*field_decode)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *); /* e.g. from Montgomery */
	int32_t (*field_set_to_one)(const EC_GROUP *, BIGNUM *r, BN_CTX *);
} /* EC_METHOD */;

struct ec_point_st {
	const EC_METHOD *meth;

	/* All members except 'meth' are handled by the method functions,
	 * even if they appear generic */

	BN_DeclareInStructure(X,EC_BN_MAX_BITS);
	BN_DeclareInStructure(Y,EC_BN_MAX_BITS);
	BN_DeclareInStructure(Z,EC_BN_MAX_BITS); /* Jacobian projective coordinates:
	                                                         * (X, Y, Z)  represents  (X/Z^2, Y/Z^3)  if  Z != 0 */
	int32_t Z_is_one; /* enable optimized point arithmetics for special case */
} /* EC_POINT */;

struct ec_group_st {
	const EC_METHOD *meth;

	EC_POINT myGenerator, *generator; /* optional */
	BN_DeclareInStructure(order,EC_BN_MAX_BITS);
	BN_DeclareInStructure(cofactor,EC_BN_MAX_BITS);

	int32_t curve_name;/* optional NID for named curve */
	point_conversion_form_t asn1_form;

	unsigned char seed[ EC_MAX_SEED_LEN ]; /* optional seed for parameters (appears in ASN1) */
	size_t seed_len;

	/* The following members are handled by the method functions,
	 * even if they appear generic */

	BN_DeclareInStructure(field,EC_BN_MAX_BITS); /* Field specification.
																 * For curves over GF(p), this is the modulus;
																 * for curves over GF(2^m), this is the 
																 * irreducible polynomial defining the field.
	                                                             */

	uint32_t poly[5]; /* Field specification for curves over GF(2^m).
	                       * The irreducible f(t) is then of the form:
	                       *     t^poly[0] + t^poly[1] + ... + t^poly[k]
	                       * where m = poly[0] > poly[1] > ... > poly[k] = 0.
	                       */

	BN_DeclareInStructure(a, EC_BN_MAX_BITS);
	BN_DeclareInStructure(b, EC_BN_MAX_BITS); /* Curve coefficients.
															 * (Here the assumption is that BIGNUMs can be used
															 * or abused for all kinds of fields, not just GF(p).)
															 * For characteristic  > 3,  the curve is defined
															 * by a Weierstrass equation of the form
															 *     y^2 = x^3 + a*x + b.
															 * For characteristic  2,  the curve is defined by
															 * an equation of the form
															 *     y^2 + x*y = x^3 + a*x^2 + b.
	                                                         */

	BN_DeclareInStructure(a_unexpanded, EC_BN_MAX_BITS);
	BN_DeclareInStructure(b_unexpanded, EC_BN_MAX_BITS); 
                                             /* Curve coefficients.
                                                The values stored in "a" and "b" are expanded for acceleration (I assume).
                                                When offoading operations to HW, we need the original values.
                                                So we store the original "a" and "b" here.
                                             */

	int32_t a_is_minus3; /* enable optimized point arithmetics for special case */

	void *field_data1; /* method-specific (e.g., Montgomery structure) */
	void *field_data2; /* method-specific */

	BN_MONT_CTX mont;
	BN_DeclareInStructure(montBigNum, EC_BN_MAX_BITS );

} /* EC_GROUP */;


int EC_Initialize();

/* EC_METHODs for curves over GF(p).
 * EC_GFp_simple_method provides the basis for the optimized methods.
 */
const EC_METHOD *EC_GFp_simple_method(void);
const EC_METHOD *EC_GFp_mont_method(void);

/* EC_METHOD for curves over GF(2^m).
 */
const EC_METHOD *EC_GF2m_simple_method(void);


EC_GROUP *EC_GROUP_new(EC_GROUP *, const EC_METHOD *);
void EC_GROUP_free(EC_GROUP *);
int32_t EC_GROUP_copy(EC_GROUP *, const EC_GROUP *);

const EC_METHOD *EC_GROUP_method_of(const EC_GROUP *);
int32_t EC_METHOD_get_field_type(const EC_METHOD *);

int32_t EC_GROUP_set_generator(EC_GROUP *, const EC_POINT *generator, const BIGNUM *order, const BIGNUM *cofactor);
EC_POINT *EC_GROUP_get0_generator(const EC_GROUP *);
int32_t EC_GROUP_get_order(const EC_GROUP *, BIGNUM *order, BN_CTX *);
int32_t EC_GROUP_get_cofactor(const EC_GROUP *, BIGNUM *cofactor, BN_CTX *);

void EC_GROUP_set_nid(EC_GROUP *, int32_t); /* curve name */
int32_t EC_GROUP_get_nid(const EC_GROUP *);

void EC_GROUP_set_asn1_flag(EC_GROUP *, int32_t flag);
int32_t EC_GROUP_get_asn1_flag(const EC_GROUP *);

void EC_GROUP_set_point_conversion_form(EC_GROUP *, point_conversion_form_t);
point_conversion_form_t EC_GROUP_get_point_conversion_form(const EC_GROUP *);

unsigned char *EC_GROUP_get0_seed(const EC_GROUP *);
size_t EC_GROUP_get_seed_len(const EC_GROUP *);
size_t EC_GROUP_set_seed(EC_GROUP *, const unsigned char *, size_t len);

int32_t EC_GROUP_set_curve_GFp(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
int32_t EC_GROUP_get_curve_GFp(const EC_GROUP *, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *);
int32_t EC_GROUP_set_curve_GF2m(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
int32_t EC_GROUP_get_curve_GF2m(const EC_GROUP *, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *);

int32_t EC_GROUP_get_degree(const EC_GROUP *);

/* EC_GROUP_check() returns 1 if 'group' defines a valid group, 0 otherwise */
int32_t EC_GROUP_check(const EC_GROUP *group, BN_CTX *ctx);
/* EC_GROUP_check_discriminant() returns 1 if the discriminant of the
 * elliptic curve is not zero, 0 otherwise */
int32_t EC_GROUP_check_discriminant(const EC_GROUP *, BN_CTX *);

/* EC_GROUP_new_GF*() calls EC_GROUP_new() and EC_GROUP_set_GF*()
 * after choosing an appropriate EC_METHOD */
EC_GROUP *EC_GROUP_new_curve_GFp(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
EC_GROUP *EC_GROUP_new_curve_GF2m(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);

/* EC_GROUP_new_by_nid() creates a EC_GROUP structure specified by a NID */
EC_GROUP *EC_GROUP_new_by_nid(EC_GROUP *, int nid);
EC_GROUP *EC_GROUP_new_from_params(EC_GROUP *, unsigned char *, unsigned int );
int EC_GetCurveInfoFromEcParams(unsigned char *params, unsigned int paramsLen, 
		                            unsigned char *order,
                                    uint32_t *pwOrderLenInBits, 
                                    uint32_t *pwFieldLen, 
                                    int *pwFieldType);


/* handling of internal curves */
typedef struct { 
	int32_t nid;
	const char *comment;
	} EC_builtin_curve;
/* EC_builtin_curves(EC_builtin_curve *r, size_t size) returns number 
 * of all available curves or zero if a error occurred. 
 * In case r ist not zero nitems EC_builtin_curve structures 
 * are filled with the data of the first nitems internal groups */
size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems);
int   EC_oid2nid(const unsigned char *oid, const int32_t oidLen);
const EC_CURVE_DATA* EC_oid2CurveData(const unsigned char *oid, const int32_t oidLen);
const EC_CURVE_DATA* EC_oid2CurveDataAndOIDptr(const unsigned char *oid, const int32_t oidLen, unsigned char **pOid);
EC_CURVE_DATA_BIN* EC_oid2CurveDataBin(const unsigned char *oid, const int32_t oidLen, int32_t *pwNID);
EC_CURVE_DATA_BIN* EC_nid2CurveDataBin(int nid);

/* EC_POINT functions */

EC_POINT *EC_POINT_new(EC_POINT *, const EC_GROUP *);
void EC_POINT_free(EC_POINT *);
int32_t EC_POINT_copy(EC_POINT *, const EC_POINT *);
 
const EC_METHOD *EC_POINT_method_of(const EC_POINT *);
void EC_POINT_set_method(EC_POINT *point, const EC_GROUP *group);

int32_t EC_POINT_set_to_infinity(const EC_GROUP *, EC_POINT *);
int32_t EC_POINT_set_Jprojective_coordinates_GFp(const EC_GROUP *, EC_POINT *,
	const BIGNUM *x, const BIGNUM *y, const BIGNUM *z, BN_CTX *);
int32_t EC_POINT_get_Jprojective_coordinates_GFp(const EC_GROUP *, const EC_POINT *,
	BIGNUM *x, BIGNUM *y, BIGNUM *z, BN_CTX *);
int32_t EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *, EC_POINT *,
	const BIGNUM *x, const BIGNUM *y, BN_CTX *);
int32_t EC_POINT_get_affine_coordinates_GFp(const EC_GROUP *, const EC_POINT *,
	BIGNUM *x, BIGNUM *y, BN_CTX *);
int32_t EC_POINT_set_compressed_coordinates_GFp(const EC_GROUP *, EC_POINT *,
	const BIGNUM *x, int32_t y_bit, BN_CTX *);

int32_t EC_POINT_set_affine_coordinates_GF2m(const EC_GROUP *, EC_POINT *,
	const BIGNUM *x, const BIGNUM *y, BN_CTX *);
int32_t EC_POINT_get_affine_coordinates_GF2m(const EC_GROUP *, const EC_POINT *,
	BIGNUM *x, BIGNUM *y, BN_CTX *);
int32_t EC_POINT_set_compressed_coordinates_GF2m(const EC_GROUP *, EC_POINT *,
	const BIGNUM *x, int32_t y_bit, BN_CTX *);

size_t EC_POINT_point2oct(const EC_GROUP *, const EC_POINT *, point_conversion_form_t form,
        unsigned char *buf, size_t len, BN_CTX *);
int32_t EC_POINT_oct2point(const EC_GROUP *, EC_POINT *,
        const unsigned char *buf, size_t len, BN_CTX *);

/* other interfaces to point2oct/oct2point: */
BIGNUM *EC_POINT_point2bn(const EC_GROUP *, const EC_POINT *,
	point_conversion_form_t form, BIGNUM *, BN_CTX *);
EC_POINT *EC_POINT_bn2point(const EC_GROUP *, const BIGNUM *,
	EC_POINT *, BN_CTX *);
char *EC_POINT_point2hex(const EC_GROUP *, const EC_POINT *,
	point_conversion_form_t form, BN_CTX *, char *);
EC_POINT *EC_POINT_hex2point(const EC_GROUP *, const char *,
	EC_POINT *, BN_CTX *);

int32_t EC_POINT_add(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *);
int32_t EC_POINT_dbl(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, BN_CTX *);
int32_t EC_POINT_invert(const EC_GROUP *, EC_POINT *, BN_CTX *);

int32_t EC_POINT_is_at_infinity(const EC_GROUP *, const EC_POINT *);
int32_t EC_POINT_is_on_curve(const EC_GROUP *, const EC_POINT *, BN_CTX *);
int32_t EC_POINT_cmp(const EC_GROUP *, const EC_POINT *a, const EC_POINT *b, BN_CTX *);

int32_t EC_POINT_make_affine(const EC_GROUP *, EC_POINT *, BN_CTX *);
int32_t EC_POINTs_make_affine(const EC_GROUP *, size_t num, EC_POINT *[], BN_CTX *);


int32_t EC_POINTs_mul(const EC_GROUP *, EC_POINT *r, const BIGNUM *, size_t num, const EC_POINT *[], const BIGNUM *[], BN_CTX *);
int32_t EC_POINT_mul(const EC_GROUP *, EC_POINT *r, const BIGNUM *, const EC_POINT *, const BIGNUM *, BN_CTX *, int);
int32_t EC_GROUP_precompute_mult(EC_GROUP *, BN_CTX *);

/* the EC_KEY stuff */
typedef struct ec_key_st EC_KEY;

typedef struct ec_key_meth_data_st {
	int32_t (*init)(EC_KEY *);
	void (*finish)(EC_KEY *);
	} EC_KEY_METH_DATA;

struct ec_key_st {
	EC_GROUP myGroup, *group;

	EC_POINT myPub_key, *pub_key;
	BIGNUM *priv_key;
	BN_DeclareInStructure(myPriv_key, EC_BN_MAX_BITS);

	point_conversion_form_t conv_form;

	EC_KEY_METH_DATA *meth_data;
	}/* EC_KEY */;

EC_KEY *EC_KEY_new( EC_KEY * );
EC_KEY *EC_KEY_reset_pointers( EC_KEY *ret );
void EC_KEY_free(EC_KEY *);
EC_KEY *EC_KEY_copy(EC_KEY *, const EC_KEY *);

/* EC_KEY_generate_key() creates a ec private (public) key */
int32_t EC_KEY_generate_key(EC_KEY *, int);
int32_t EC_KEY_generate_key_w_extra_bits(EC_KEY *eckey, int);
/* EC_KEY_check_key() */
int32_t EC_KEY_check_key(const EC_KEY *);
int32_t EC_KEY_Partial_PKV(int32_t nid, const void *pEcPoint, uint32_t ecPointLen, unsigned char *pEcParams, int32_t nEcParamLen);


/* Error codes for the EC functions. */

/* Reason codes. */
#define EC_R_ASN1_ERROR					 115
#define EC_R_ASN1_UNKNOWN_FIELD				 116
#define EC_R_BUFFER_TOO_SMALL				 100
#define EC_R_D2I_ECPKPARAMETERS_FAILURE			 117
#define EC_R_DISCRIMINANT_IS_ZERO			 118
#define EC_R_EC_GROUP_NEW_BY_NAME_FAILURE		 119
#define EC_R_GROUP2PKPARAMETERS_FAILURE			 120
#define EC_R_I2D_ECPKPARAMETERS_FAILURE			 121
#define EC_R_INCOMPATIBLE_OBJECTS			 101
#define EC_R_INVALID_ARGUMENT				 112
#define EC_R_INVALID_COMPRESSED_POINT			 110
#define EC_R_INVALID_COMPRESSION_BIT			 109
#define EC_R_INVALID_ENCODING				 102
#define EC_R_INVALID_FIELD				 103
#define EC_R_INVALID_FORM				 104
#define EC_R_INVALID_GROUP_ORDER			 122
#define EC_R_INVALID_PRIVATE_KEY			 123
#define EC_R_MISSING_PARAMETERS				 124
#define EC_R_MISSING_PRIVATE_KEY			 125
#define EC_R_NOT_IMPLEMENTED				 126
#define EC_R_NOT_INITIALIZED				 111
#define EC_R_NO_SUCH_EXTRA_DATA				 105
#define EC_R_PKPARAMETERS2GROUP_FAILURE			 127
#define EC_R_POINT_AT_INFINITY				 106
#define EC_R_POINT_IS_NOT_ON_CURVE			 107
#define EC_R_SLOT_FULL					 108
#define EC_R_UNDEFINED_GENERATOR			 113
#define EC_R_UNDEFINED_ORDER				 128
#define EC_R_UNKNOWN_GROUP				 129
#define EC_R_UNKNOWN_ORDER				 114
#define EC_R_UNSUPPORTED_FIELD				 131
#define EC_R_WRONG_ORDER				 130


// Codes from err.h

/* library */
#define ERR_LIB_NONE		1
#define ERR_LIB_SYS		2
#define ERR_LIB_BN		3
#define ERR_LIB_RSA		4
#define ERR_LIB_DH		5
#define ERR_LIB_EVP		6
#define ERR_LIB_BUF		7
#define ERR_LIB_OBJ		8
#define ERR_LIB_PEM		9
#define ERR_LIB_DSA		10
#define ERR_LIB_X509		11
/* #define ERR_LIB_METH         12 */
#define ERR_LIB_ASN1		13
#define ERR_LIB_CONF		14
#define ERR_LIB_CRYPTO		15
#define ERR_LIB_EC		16
#define ERR_LIB_SSL		20
/* #define ERR_LIB_SSL23        21 */
/* #define ERR_LIB_SSL2         22 */
/* #define ERR_LIB_SSL3         23 */
/* #define ERR_LIB_RSAREF       30 */
/* #define ERR_LIB_PROXY        31 */
#define ERR_LIB_BIO		32
#define ERR_LIB_PKCS7		33
#define ERR_LIB_X509V3		34
#define ERR_LIB_PKCS12		35
#define ERR_LIB_RAND		36
#define ERR_LIB_DSO		37
#define ERR_LIB_ENGINE		38
#define ERR_LIB_OCSP            39
#define ERR_LIB_UI              40
#define ERR_LIB_COMP            41
#define ERR_LIB_ECDSA		42
#define ERR_LIB_ECDH		43

#define ERR_LIB_USER		128

/* reasons */
#define ERR_R_SYS_LIB	ERR_LIB_SYS       /* 2 */
#define ERR_R_BN_LIB	ERR_LIB_BN        /* 3 */
#define ERR_R_RSA_LIB	ERR_LIB_RSA       /* 4 */
#define ERR_R_DH_LIB	ERR_LIB_DH        /* 5 */
#define ERR_R_EVP_LIB	ERR_LIB_EVP       /* 6 */
#define ERR_R_BUF_LIB	ERR_LIB_BUF       /* 7 */
#define ERR_R_OBJ_LIB	ERR_LIB_OBJ       /* 8 */
#define ERR_R_PEM_LIB	ERR_LIB_PEM       /* 9 */
#define ERR_R_DSA_LIB	ERR_LIB_DSA      /* 10 */
#define ERR_R_X509_LIB	ERR_LIB_X509     /* 11 */
#define ERR_R_ASN1_LIB	ERR_LIB_ASN1     /* 13 */
#define ERR_R_CONF_LIB	ERR_LIB_CONF     /* 14 */
#define ERR_R_CRYPTO_LIB ERR_LIB_CRYPTO  /* 15 */
#define ERR_R_EC_LIB	ERR_LIB_EC       /* 16 */
#define ERR_R_SSL_LIB	ERR_LIB_SSL      /* 20 */
#define ERR_R_BIO_LIB	ERR_LIB_BIO      /* 32 */
#define ERR_R_PKCS7_LIB	ERR_LIB_PKCS7    /* 33 */
#define ERR_R_X509V3_LIB ERR_LIB_X509V3  /* 34 */
#define ERR_R_PKCS12_LIB ERR_LIB_PKCS12  /* 35 */
#define ERR_R_RAND_LIB	ERR_LIB_RAND     /* 36 */
#define ERR_R_DSO_LIB	ERR_LIB_DSO      /* 37 */
#define ERR_R_ENGINE_LIB ERR_LIB_ENGINE  /* 38 */
#define ERR_R_OCSP_LIB  ERR_LIB_OCSP     /* 39 */
#define ERR_R_UI_LIB    ERR_LIB_UI       /* 40 */
#define ERR_R_COMP_LIB	ERR_LIB_COMP     /* 41 */
#define ERR_R_ECDSA_LIB ERR_LIB_ECDSA	 /* 42 */
#define ERR_R_ECDH_LIB  ERR_LIB_ECDH	 /* 43 */

#define ERR_R_NESTED_ASN1_ERROR			58
#define ERR_R_BAD_ASN1_OBJECT_HEADER		59
#define ERR_R_BAD_GET_ASN1_OBJECT_CALL		60
#define ERR_R_EXPECTING_AN_ASN1_SEQUENCE	61
#define ERR_R_ASN1_LENGTH_MISMATCH		62
#define ERR_R_MISSING_ASN1_EOS			63

/* fatal error */
#define ERR_R_FATAL				64
#define	ERR_R_MALLOC_FAILURE			(1|ERR_R_FATAL)
#define	ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED	(2|ERR_R_FATAL)
#define	ERR_R_PASSED_NULL_PARAMETER		(3|ERR_R_FATAL)
#define	ERR_R_INTERNAL_ERROR			(4|ERR_R_FATAL)
#define	ERR_R_DISABLED				(5|ERR_R_FATAL)

#endif





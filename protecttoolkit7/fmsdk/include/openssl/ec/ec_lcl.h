/***************************************************************************\
 * This file is protected by laws protecting trade secrets and confidential
 * information, as well as copyright laws and international treaties.
 * Copyright (C) 2003 Chrysalis-ITS Incorporated and its licensors.
 * All rights reserved.
\***************************************************************************/

/*
 * Originally written by Bodo Moeller for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
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

#ifndef HEADER_EC_LCL_H
#define HEADER_EC_LCL_H

#include "ec.h"
#include "obj_mac.h"


/* internal function: ec_group_index2nid() returns the NID of curve
 * with the given index i from the internal curve list */
int32_t ec_group_index2nid(int32_t i);


/* Structure details are not part of the exported interface,
 * so all this may change in future versions. */

// ...
// The structures had to be moved to ec.h because of changes in EC_KEY.
// ...



/* method functions in ec_mult.c */
int32_t ec_wNAF_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
	size_t num, const EC_POINT *points[], const BIGNUM *scalars[], BN_CTX *);
int32_t ec_wNAF_precompute_mult(EC_GROUP *group, BN_CTX *);

/* method functions in ecp_smpl.c */
int32_t ec_GFp_simple_group_init(EC_GROUP *);
void ec_GFp_simple_group_finish(EC_GROUP *);
int32_t ec_GFp_simple_group_copy(EC_GROUP *, const EC_GROUP *);
int32_t ec_GFp_simple_group_set_curve(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
int32_t ec_GFp_simple_group_get_curve(const EC_GROUP *, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *);
int32_t ec_GFp_simple_group_get_degree(const EC_GROUP *);
int32_t ec_GFp_simple_group_check_discriminant(const EC_GROUP *, BN_CTX *);
int32_t ec_GFp_simple_point_init(EC_POINT *);
void ec_GFp_simple_point_finish(EC_POINT *);
int32_t ec_GFp_simple_point_copy(EC_POINT *, const EC_POINT *);
int32_t ec_GFp_simple_point_set_to_infinity(const EC_GROUP *, EC_POINT *);
int32_t ec_GFp_simple_set_Jprojective_coordinates_GFp(const EC_GROUP *, EC_POINT *,
	const BIGNUM *x, const BIGNUM *y, const BIGNUM *z, BN_CTX *);
int32_t ec_GFp_simple_get_Jprojective_coordinates_GFp(const EC_GROUP *, const EC_POINT *,
	BIGNUM *x, BIGNUM *y, BIGNUM *z, BN_CTX *);
int32_t ec_GFp_simple_point_set_affine_coordinates(const EC_GROUP *, EC_POINT *,
	const BIGNUM *x, const BIGNUM *y, BN_CTX *);
int32_t ec_GFp_simple_point_get_affine_coordinates(const EC_GROUP *, const EC_POINT *,
	BIGNUM *x, BIGNUM *y, BN_CTX *);
int32_t ec_GFp_simple_set_compressed_coordinates(const EC_GROUP *, EC_POINT *,
	const BIGNUM *x, int32_t y_bit, BN_CTX *);
size_t ec_GFp_simple_point2oct(const EC_GROUP *, const EC_POINT *, point_conversion_form_t form,
	unsigned char *buf, size_t len, BN_CTX *);
int32_t ec_GFp_simple_oct2point(const EC_GROUP *, EC_POINT *,
	const unsigned char *buf, size_t len, BN_CTX *);
int32_t ec_GFp_simple_add(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *);
int32_t ec_GFp_simple_dbl(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, BN_CTX *);
int32_t ec_GFp_simple_invert(const EC_GROUP *, EC_POINT *, BN_CTX *);
int32_t ec_GFp_simple_is_at_infinity(const EC_GROUP *, const EC_POINT *);
int32_t ec_GFp_simple_is_on_curve(const EC_GROUP *, const EC_POINT *, BN_CTX *);
int32_t ec_GFp_simple_cmp(const EC_GROUP *, const EC_POINT *a, const EC_POINT *b, BN_CTX *);
int32_t ec_GFp_simple_make_affine(const EC_GROUP *, EC_POINT *, BN_CTX *);
int32_t ec_GFp_simple_points_make_affine(const EC_GROUP *, size_t num, EC_POINT *[], BN_CTX *);
int32_t ec_GFp_simple_field_mul(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
int32_t ec_GFp_simple_field_sqr(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);


/* method functions in ecp_mont.c */
int32_t ec_GFp_mont_group_init(EC_GROUP *);
int32_t ec_GFp_mont_group_set_curve(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
void ec_GFp_mont_group_finish(EC_GROUP *);
int32_t ec_GFp_mont_group_copy(EC_GROUP *, const EC_GROUP *);
int32_t ec_GFp_mont_field_mul(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
int32_t ec_GFp_mont_field_sqr(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);
int32_t ec_GFp_mont_field_encode(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);
int32_t ec_GFp_mont_field_decode(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);
int32_t ec_GFp_mont_field_set_to_one(const EC_GROUP *, BIGNUM *r, BN_CTX *);


/* method functions in ecp_recp.c */
int32_t ec_GFp_recp_group_init(EC_GROUP *);
int32_t ec_GFp_recp_group_set_curve(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
void ec_GFp_recp_group_finish(EC_GROUP *);
int32_t ec_GFp_recp_group_copy(EC_GROUP *, const EC_GROUP *);
int32_t ec_GFp_recp_field_mul(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
int32_t ec_GFp_recp_field_sqr(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);


/* method functions in ecp_nist.c */
int32_t ec_GFp_nist_group_init(EC_GROUP *);
int32_t ec_GFp_nist_group_set_curve(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
void ec_GFp_nist_group_finish(EC_GROUP *);
int32_t ec_GFp_nist_group_copy(EC_GROUP *, const EC_GROUP *);
int32_t ec_GFp_nist_field_mul(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
int32_t ec_GFp_nist_field_sqr(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);


/* method functions in ec2_smpl.c */
int32_t ec_GF2m_simple_group_init(EC_GROUP *);
void ec_GF2m_simple_group_finish(EC_GROUP *);
int32_t ec_GF2m_simple_group_copy(EC_GROUP *, const EC_GROUP *);
int32_t ec_GF2m_simple_group_set_curve(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
int32_t ec_GF2m_simple_group_get_curve(const EC_GROUP *, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *);
int32_t ec_GF2m_simple_group_get_degree(const EC_GROUP *);
int32_t ec_GF2m_simple_group_check_discriminant(const EC_GROUP *, BN_CTX *);
int32_t ec_GF2m_simple_point_init(EC_POINT *);
void ec_GF2m_simple_point_finish(EC_POINT *);
int32_t ec_GF2m_simple_point_copy(EC_POINT *, const EC_POINT *);
int32_t ec_GF2m_simple_point_set_to_infinity(const EC_GROUP *, EC_POINT *);
int32_t ec_GF2m_simple_point_set_affine_coordinates(const EC_GROUP *, EC_POINT *,
	const BIGNUM *x, const BIGNUM *y, BN_CTX *);
int32_t ec_GF2m_simple_point_get_affine_coordinates(const EC_GROUP *, const EC_POINT *,
	BIGNUM *x, BIGNUM *y, BN_CTX *);
int32_t ec_GF2m_simple_set_compressed_coordinates(const EC_GROUP *, EC_POINT *,
	const BIGNUM *x, int32_t y_bit, BN_CTX *);
size_t ec_GF2m_simple_point2oct(const EC_GROUP *, const EC_POINT *, point_conversion_form_t form,
	unsigned char *buf, size_t len, BN_CTX *);
int32_t ec_GF2m_simple_oct2point(const EC_GROUP *, EC_POINT *,
	const unsigned char *buf, size_t len, BN_CTX *);
int32_t ec_GF2m_simple_add(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *);
int32_t ec_GF2m_simple_dbl(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, BN_CTX *);
int32_t ec_GF2m_simple_invert(const EC_GROUP *, EC_POINT *, BN_CTX *);
int32_t ec_GF2m_simple_is_at_infinity(const EC_GROUP *, const EC_POINT *);
int32_t ec_GF2m_simple_is_on_curve(const EC_GROUP *, const EC_POINT *, BN_CTX *);
int32_t ec_GF2m_simple_cmp(const EC_GROUP *, const EC_POINT *a, const EC_POINT *b, BN_CTX *);
int32_t ec_GF2m_simple_make_affine(const EC_GROUP *, EC_POINT *, BN_CTX *);
int32_t ec_GF2m_simple_points_make_affine(const EC_GROUP *, size_t num, EC_POINT *[], BN_CTX *);
int32_t ec_GF2m_simple_field_mul(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
int32_t ec_GF2m_simple_field_sqr(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);
int32_t ec_GF2m_simple_field_div(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *);


/* method functions in ec2_mult.c */
int32_t ec_GF2m_mont_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
	size_t num, const EC_POINT *points[], const BIGNUM *scalars[], BN_CTX *);
int32_t ec_GF2m_mont_precompute_mult(EC_GROUP *group, BN_CTX *ctx);

#endif /* HEADER_EC_LCL_H */



/*
 *  This file is provided as part of the SafeNet Protect Toolkit SDK.
 *
 *  (c) Copyright 1992-2023 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 */
/**
 * @file ecc.h
 *
 * This file contains the type and function definitions for the ECC module.
 */
#ifndef INC_ECC_H
#define INC_ECC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup ecdsamod ECC Module Documentation
 *  @{
 */
/**
 * The minimum allowed modulus length, in number of bits, supported by the
 * ECC module.
 */
#define ECC_MIN_MOD_LEN 64

/**
 * The maximum allowed modulus length, in number of bits, supported by the
 * ECC module.
 */
#define ECC_MAX_MOD_LEN 571

/**
 * The maximum number of bytes that will be needed for buffers that hold ECC
 * related data. Although there are two types of data in these buffers (the
 * field elements, and numbers) the lengths of the numbers are always less than
 * or equal to (almost always equal to) the modulus length.
 */
#define ECC_MAX_BUF_LEN (ECC_MAX_MOD_LEN / 8 + 1)

/**
 * The Diffie-Hellman Primitives used to derive a shared secret value.
 */
typedef enum {
	/** Standard Diffie-Hellman Primitive. */
	ECC_STANDARD_DH_PRIMITIVE = 1,
	/** Modified (or Cofactor) Diffie-Hellman Primitive. */
	ECC_MODIFIED_DH_PRIMITIVE = 2
} ECC_DHP;

/**
 * Posible return values from the ECC functions.
 */
typedef enum {
	/** Operation completed successfully. */
	ECC_OK,

	/** Not enough memory to complete operation */
	ECC_NOMEM,

	/** The verify operation failed: Signature invalid. */
	ECC_ECDSA_SIGN_INVALID,

	/** At least one of the parameters passed to the function is invalid. */
	ECC_PARAM_INVALID,

	/** The named curve was not found */
	ECC_CURVE_NOT_FOUND,

	/** Generic problem */
	ECC_UNSUCCESSFUL,

	/** Internal error in the library. This error value should never be
	 * seen by the caller. */
	ECC_INTERNAL_ERROR,

	/** Pairwise consistency check failed when generating a key pair. */
	ECC_ERR_PAIRWISE,

	/** Point Verification Failure */
	ECC_POINT_INVALID
} ECC_RV;

/**
 * Possible curve types for an ECC_Curve_t structure.
 */
typedef enum ECC_FieldType_et {
	/** Identifies a curve over a field with an odd prime number of elements. */
	ECC_FT_GFP,

	/** Identifies a curve over a field of characteristic two (F_2^m). */
	ECC_FT_G2M,

	/** Identifies a prime curve that uses a Montgomery function.*/
	ECC_FT_MON,
} ECC_FieldType_t;

/**
 * This structure represents an ECDSA signature. For more information about
 * ECDSA signatures, consult either the ANSI X9.62, or FIPS 186-2 standard.
 */
typedef struct ECC_EcdsaSignature_st {
	uint8_t* sign;
	size_t sign_length;
} ECC_EcdsaSignature_t;

/**
 * This structure represents the shared secret value produced by an EC 
 * Diffie-Hellman Derive operation.
 */
typedef struct ECC_DHSecret_st {
	/** The buffer containing the shared secret value. */
	uint8_t secret[ECC_MAX_BUF_LEN];
} ECC_DHSecret_t;

/**
 * This structure represents a point on an Elliptic curve.
 *
 * The number of bits in each element is equal to the number of bits in the
 * modulus of the curve.
 *
 * Please note that without an ECC_Curve_t structure accompanying it, this
 * structure is meaningless.
 */
typedef struct ECC_Point_st {
	/** The X coordinate of the point. X is an element of the field over which
	 * the curve is defined. */
	uint8_t x[ECC_MAX_BUF_LEN];

	/** The Y coordinate of the point. Y is an element of the field over which
	 * the curve is defined. */
	uint8_t y[ECC_MAX_BUF_LEN];
} ECC_Point_t;

/**
 * This structure defines an elliptic curve.
 *
 * All the elements have the same structure for different field types, however
 * the interpretation of the bits change slightly. If the field type is
 * ECC_FT_GFP, the buffers hold large numbers in big endian format. If it is
 * ECC_FT_G2M, the buffers hold coefficients of the polynomials in the
 * field. The leftmost bit (most significant bit of first byte) is the
 * coefficient of the largest power of x, and the rightmost bit is the
 * coefficient of x^0. With these definitions, if the bit lengths are not exact
 * multiples of 8, always the leftmost bits of field elements are set to zero.
 *
 * For fields of type ECC_FT_GFP, the curve equation is @code
 *    y^2 = x^3 + a*x + b @endcode
 *
 * For fields of type ECC_FT_G2M, the curve equation is @code
 *    y^2 + x*y = x^3 + a*x^2 + b @endcode
 *
 * @note These equations are defined in ANSI X9.62 standard.
 */
typedef struct ECC_Curve_st {
	/** The field type, over which this curve is defined. */
	ECC_FieldType_t fieldType;

	/** The curve modulus. This value is the field polynomial for ECC_FT_G2M
	 * field types. */
	uint8_t modulus[ECC_MAX_BUF_LEN];

	/** The coefficient 'a' in the elliptic curve equation. */
	uint8_t a[ECC_MAX_BUF_LEN];

	/** The coefficient 'b' in the elliptic curve equation. */
	uint8_t b[ECC_MAX_BUF_LEN];

	/** The base point. */
	ECC_Point_t base;

	/** The base point order. This buffer contains a big endian large number
	 * regardless of the field type. */
	uint8_t bpOrder[ECC_MAX_BUF_LEN];

	/** The Curve OID.
	 * Set to OID_UNKNOWN (0) to autodect or when it is not a named curve*/
	uint32_t curveOID;

	/** The modulus size in bytes. Set to 0 to autodetect.*/
	uint32_t pointSize;

	/** The order size in bits. Set to 0 to autodetect.*/
	uint32_t ordBitSize;

} ECC_Curve_t;

/**
 * This structure defines an ECC Private key.
 *
 * The private key is a large number, which is used to calculate the public key
 * from the base of the curve. The equation used for this calculation is
 *                  P = d*G
 * where P is the public key (a point), d is the private key (a number), and G
 * is the base of the curve (a point).
 */
typedef struct ECC_PrivateKey_st {
	/** The buffer containing the private key. The private key is always a
	 * big-endian large number, d, regardless of the field type of the curve.
	 */
	uint8_t d[ECC_MAX_BUF_LEN];
} ECC_PrivateKey_t;

/**
 * This structure defines an ECC Public key.
 *
 * The public key is a point on the elliptic curve.
 */
typedef struct ECC_PublicKey_st {
	/** The point P on the curve, which is calculated from the curve base and
	 * the private key. */
	ECC_Point_t p;
} ECC_PublicKey_t;

typedef struct {
	ECC_Curve_t curve;
	ECC_PrivateKey_t priKey;
} ECC_SignKey_t;

typedef struct {
	ECC_Curve_t curve;
	ECC_PublicKey_t pubKey;
} ECC_VerifyKey_t;

/**
 * This function is used to obtain Ordinal Length (n) of curve
 *
 * @param curve
 *    IN: The elliptic curve 
 * @param pOrdLen
 *    OUT: The slength in bits.
 *
 * @return
 *    @li ECC_OK: The operation was completed successfully
 */
ECC_RV ECC_GetOrdLen( 
					 const ECC_Curve_t *curve,
					 unsigned int * pOrdLen);

/**
 * This function is used to obtain Degree (p) of curve
 *
 * @param curve
 *    IN: The elliptic curve
 * @param pDegree
 *    OUT: The slength in bits.
 *
 * @return
 *    @li ECC_OK: The operation was completed successfully
 */
ECC_RV ECC_GetDegree(const ECC_Curve_t *curve, unsigned int *pOrdLen);

/**
 * This function is used to sign the data (hash) using ECDSA algorithm.
 *
 * The data usually is the output of a hash function.
 *
 * @param msg
 *    IN: Message/Hash to be signed.
 * @param msgLen
 *    Number of bytes in msg
 * @param k
 *    IN: The nonce used to sign the data
 * @param privKey
 *    IN: The private key
 * @param curve
 *    IN: The elliptic curve on which the private key is defined
 * @param sign
 *    OUT: The signature.
 *
 * @return
 *    @li ECC_OK: The operation was completed successfully
 *    @li otherwise: The operation failed. The cause of failure is indicated by
 *    the value.
 */
ECC_RV ECC_EcdsaSign(const uint8_t *msg,
					 unsigned int msgLen,
					 uint8_t* k,
					 const ECC_PrivateKey_t *privKey,
					 const ECC_Curve_t *curve,
					 ECC_EcdsaSignature_t *sign);

/**
 * This function is used to sign the data (hash) using EDDSA algorithm.
 *
 * @param msg
 *    IN: Message/Hash to be signed.
 * @param msgLen
 *    Number of bytes in msg
 * @param k
 *    IN: The nonce used to sign the data
 * @param mode
 *    IN: The Signature mode (Pure, PreHash)
 * @param privKey
 *    IN: The private key
 * @param curve
 *    IN: The elliptic curve on which the private key is defined
 * @param sign
 *    OUT: The signature.
 *
 * @return
 *    @li ECC_OK: The operation was completed successfully
 *    @li otherwise: The operation failed. The cause of failure is indicated by
 *    the value.
 */
ECC_RV ECC_EddsaSign(const uint8_t *msg,
					 unsigned int msgLen,
					 uint8_t* k,
					 uint32_t mode,
					 const ECC_PrivateKey_t *privKey,
					 const ECC_Curve_t *curve,
					 ECC_EcdsaSignature_t *sign);

/*
 * This function is used to sign the data (hash) using ECDSA algorithm.
 *
 * The data usually is the output of a hash function. It's length must always
 * be equal to 20.
 *
 * @param msg
 *    IN: Message/Hash to be signed.
 * @param msgLen
 *    Number of bytes in msg
 * @param pubKey
 *    IN: The public key
 * @param curve
 *    IN: The elliptic curve on which the key is defined
 * @param sign
 *    IN: The signature.
 *
 * @return
 *    @li ECC_OK: The operation was completed successfully. It means the
 *    signature was valid.
 *    @li ECC_ECDSA_SIGN_INVALID: The signature was invalid.
 *    @li otherwise: The operation failed. The cause of failure is indicated by
 *    the value.
 */
ECC_RV ECC_EcdsaVerify(const uint8_t *msg,
					   unsigned int msgLen,
					   const ECC_PublicKey_t *pubKey,
					   const ECC_Curve_t *curve,
					   const ECC_EcdsaSignature_t *sign);

/*
 * This function is used to sign the data (hash) using EDDSA algorithm.
 *
 * The data usually is the output of a hash function.
 *
 * @param msg
 *    IN: Message/Hash to be signed.
 * @param msgLen
 *    Number of bytes in msg
 * @param mode
 *    IN: The Signature mode (Pure, PreHash)
 * @param pubKey
 *    IN: The public key
 * @param curve
 *    IN: The elliptic curve on which the key is defined
 * @param sign
 *    IN: The signature.
 *
 * @return
 *    @li ECC_OK: The operation was completed successfully. It means the
 *    signature was valid.
 *    @li ECC_ECDSA_SIGN_INVALID: The signature was invalid.
 *    @li otherwise: The operation failed. The cause of failure is indicated by
 *    the value.
 */
ECC_RV ECC_EddsaVerify(const uint8_t *msg,
					   unsigned int msgLen,
					   uint32_t mode,
					   const ECC_PublicKey_t *pubKey,
					   const ECC_Curve_t *curve,
					   const ECC_EcdsaSignature_t *sign);

ECC_RV ECC_ValidatePublicKey(
					   const ECC_PublicKey_t *pubKey,
					   const ECC_Curve_t *curve);

/**
 * This function is used to generate a key pair defined on the specified
 * elliptic curve.
 *
 * @param curve
 *    IN: The curve for which the key pair will be generated.
 * @param pubKey
 *    OUT: The public component of the key pair.
 * @param privKey
 *    OUT: The private component of the key pair.
 *
 * @return
 *    @li ECC_OK: The operation was completed successfully
 *    @li otherwise: The operation failed. The cause of failure is indicated by
 *    the value.
 */
ECC_RV ECC_GenerateKeyPair(const ECC_Curve_t *curve,
						   ECC_PublicKey_t *pubKey,
						   ECC_PrivateKey_t *privKey);

/**
 * This function is used to derive a shared secret value, between two entities,
 * using the specified Diffie-Hellman primitive.  For more information see
 * ANSI X9.63-2001, Section 5.4, or SEC 1, Ver 1.0, Section 3.3.
 *
 * @param privKey
 *    IN: The private key from entity 1.
 * @param pubKey
 *    IN: The public key from entity 2.
 * @param curve
 *    IN: The elliptic curve on which the keys are defined.
 * @param DHprimitive
 *    IN: The Diffie-Hellman primitive to use.
 * @param secretValue
 *    OUT: The derived shared secret value.
 *
 * @return
 *    @li ECC_OK: The operation was completed successfully
 *    @li otherwise: The operation failed. The cause of failure is indicated by
 *    the value.
 */
ECC_RV ECC_DHDerive(const ECC_PrivateKey_t *privKey,
						const ECC_PublicKey_t *pubKey,
						const ECC_Curve_t *curve,
						ECC_DHP DHprimitive,
						ECC_DHSecret_t *secretValue,
						size_t *secretSize);

/**
 * This function is used for point multiplication, between two entities,
 *
 * @param privKey
 *    IN: The scalar to multiply.
 * @param pubKey
 *    IN: A point in the curve.
 * @param curve
 *    IN: The elliptic curve on which the keys are defined.
 * @param result
 *    OUT: The point resulting from the multiplication.
 *
 * @return
 *    @li ECC_OK: The operation was completed successfully
 *    @li otherwise: The operation failed. The cause of failure is indicated by
 *    the value.
 */
ECC_RV ECC_PointMultiplication(const ECC_PrivateKey_t *privKey,
						const ECC_PublicKey_t *pubKey,
						const ECC_Curve_t *curve,
						ECC_Point_t *result,
						size_t *secSize);

/** @} */
#ifdef __cplusplus
}
#endif

#endif /* INC_ECC_H */

/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 1997-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: fmciphobj.h
 */
#ifndef INCL_FMCIPHOBJ
#define INCL_FMCIPHOBJ

#include	<ciphobjpub.h>
#include	<hashobjpub.h>

#ifdef __cplusplus
extern "C" {                /* define as 'C' functions to prevent mangling */
#endif


/*
 * Ciph Objects - CipherObject cryptographic support as exported to FMs
 *  Includes hash objects as well.
 */


/* 
** constant values used to refer to a particular cipher object
** for backwards compatability do not change any of these values
*/
enum FMCO_CipherObjIndex {

	FMCO_IDX_AES		= 0,
	FMCO_IDX_CAST		= 1,
	FMCO_IDX_IDEA		= 2,
	FMCO_IDX_RC2		= 3,
	FMCO_IDX_RC4		= 4,
	FMCO_IDX_DES		= 5,
	FMCO_IDX_TRIPLEDES	= 6,

	FMCO_IDX_DSA		= 10,
	FMCO_IDX_ECDSA		= 11,

	FMCO_IDX_HMACMD2	= 20,
	FMCO_IDX_HMACMD5	= 21,
	FMCO_IDX_HMACSHA1	= 22,
	FMCO_IDX_HMACRMD128	= 23,
	FMCO_IDX_HMACRMD160	= 24,

	FMCO_IDX_RSA		= 30,
	FMCO_IDX_RSA_MD2	= 31,
	FMCO_IDX_RSA_MD5	= 32,
	FMCO_IDX_RSA_SHA1	= 33,
	FMCO_IDX_RSA_SHA256	= 34,
	FMCO_IDX_RSA_SHA384	= 35,
	FMCO_IDX_RSA_SHA512	= 36,
	FMCO_IDX_RSA_MD128	= 37,
	FMCO_IDX_RSA_MD160	= 38,
	FMCO_IDX_RSA_SHA224	= 39,
	FMCO_IDX_ARIA       = 45,

	FMCO_IDX_ECDSA_SHA1   = 46,
	FMCO_IDX_ECDSA_SHA224 = 47,
	FMCO_IDX_ECDSA_SHA256 = 48,
	FMCO_IDX_ECDSA_SHA384 = 49,
	FMCO_IDX_ECDSA_SHA512 = 50,
	FMCO_IDX_ECIES        = 51,
	FMCO_IDX_ECDSA_GBCS_SHA256 = 52,
	FMCO_IDX_ECDSA_SHA3_224 = 53,
	FMCO_IDX_ECDSA_SHA3_256 = 54,
	FMCO_IDX_ECDSA_SHA3_384 = 55,
	FMCO_IDX_ECDSA_SHA3_512 = 56,

	FMCO_IDX_RSA_SHA3_224 = 57,
	FMCO_IDX_RSA_SHA3_256 = 58,
	FMCO_IDX_RSA_SHA3_384 = 59,
	FMCO_IDX_RSA_SHA3_512 = 60,

	FMCO_INVALID    	= -1
};

typedef enum FMCO_CipherObjIndex FMCO_CipherObjIndex;


/* 
** constant values used to refer to a particular hash object
** for backwards compatability do not change any of these values
*/
enum FMCO_HashObjIndex {

	FMCO_IDX_MD2		= 0,
	FMCO_IDX_MD5		= 1,
	FMCO_IDX_RMD128		= 2,
	FMCO_IDX_RMD160		= 3,
	FMCO_IDX_SHA1		= 4,
	FMCO_IDX_SHA256		= 5,
	FMCO_IDX_SHA384		= 6,
	FMCO_IDX_SHA512		= 7,
	FMCO_IDX_SHA224		= 8
	
};
typedef enum FMCO_HashObjIndex FMCO_HashObjIndex;


/*
 * Returns the address of a cipher object for performing crypto operations.
 * Returns pointer to an initialised cipherobject or null in an error condition.
 */
CipherObj * FmCreateCipherObject(
							FMCO_CipherObjIndex index
					);

/*
 * Returns the address of a hash object for digest operations.
 * Returns pointer to an initialised hash object or null in an error condition.
 */
HashObj * FmCreateHashObject(
							FMCO_HashObjIndex index
					);


/*
 * Returns the FM's 'index' of the cipher object, if any.
 * If none, returns FMCO_INVALID.
 */
FMCO_CipherObjIndex FmCipherObjectIndex(const void *pObj);

#ifdef __cplusplus
}
#endif

#endif /* INCL_FMCIPHOBJ */

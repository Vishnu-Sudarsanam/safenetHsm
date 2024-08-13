/*
 *  This file is provided as part of the SafeNet Protect Toolkit SDK.
 *
 * CRYPTOKI.H
 * Derived from
 * PKCS-11 (CRYPTOKI) V 1.0 and V 2.01 specifications.
 */

#ifndef CRYPTOKI_INCLUDED
#define CRYPTOKI_INCLUDED

#include "ctalias.h"

#ifdef _WIN32
/*
 * Note: This is not very nice, but it is better than blowing up the compile
 * time by including windows,h.
 */
# define CK_CALLBACK __stdcall
/*
 * This was __stdcall, but this broke backwards compatability with
 * __declspec(export) DLLs.
 *
 * The default for C is __cdecl, but this can be overwritten by Compile
 * Command line option /G[drz]
 *
 * To stop potential compatability problems in the future, enforce CK_ENTRY
 * functions to be __cdecl
 */
# define CK_ENTRY   __cdecl
# pragma pack(push,cryptoki,1)
#else   /* Unix */
# define CK_ENTRY
# define CK_CALLBACK
/* No packing should be used for Unix platforms (as per PKCS#11 standard)
 *
 * Packing causes problems with interoperability with Netscape and 3rd party
 * Java PKCS#11 wrappers.
 */
#endif

#define CK_PTR *

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE (!FALSE)
#endif

/* an unsigned 8-bit value */
typedef unsigned char CK_BYTE;

/* an unsigned 8-bit character */
typedef CK_BYTE CK_CHAR;

/* a BYTE-sized Boolean flag */
typedef CK_BYTE CK_BBOOL;

/* an unsigned value, at least 16 bits long */
typedef unsigned short int CK_USHORT;

/* an unsigned value, at least 32 bits long */
typedef unsigned long int CK_ULONG;

typedef void CK_VOID;

/* at least 32 bits, each bit is a Boolean flag */
typedef CK_ULONG CK_FLAGS;

typedef CK_BYTE * CK_BYTE_PTR;
typedef CK_CHAR * CK_CHAR_PTR;
typedef CK_USHORT * CK_USHORT_PTR;
typedef CK_ULONG * CK_ULONG_PTR;
typedef CK_BBOOL * CK_BBOOL_PTR;
typedef CK_VOID * CK_VOID_PTR;
typedef CK_VOID_PTR * CK_VOID_PTR_PTR;

/* Additional definitions to avoid problems when changing to V 2.0 */
#ifdef V1COMPLIANT

typedef CK_USHORT CK_SIZE;
typedef CK_USHORT CK_COUNT;
typedef CK_USHORT CK_NUMERIC;
#define CK_VENDOR_DEFINED  0x00008000
#undef V2COMPLIANT

#else

typedef CK_ULONG CK_SIZE;
typedef CK_ULONG CK_COUNT;
typedef CK_ULONG CK_NUMERIC;
#define CK_VENDOR_DEFINED  0x80000000
#ifndef V2COMPLIANT
#define V2COMPLIANT
#endif

#endif

#define CK_VENDOR_DEFINED_V1  0x00008000
#define CK_VENDOR_DEFINED_V2  0x80000000

typedef CK_SIZE * CK_SIZE_PTR;
typedef CK_COUNT * CK_COUNT_PTR;

#define NULL_PTR ((CK_VOID_PTR)0)
typedef CK_ULONG CK_AUTH_TYPE; 
#define CKT_PIN            0x00000000

typedef CK_ULONG CK_PIN_CHAR_SET; 
#define CKP_NUMERIC    0x00000000 
#define CKP_UTF8            0x00000001
#define CKP_BINARY        0x00000002

typedef struct CK_VERSION {
	CK_BYTE major;
	CK_BYTE minor;
} CK_VERSION;
typedef CK_VERSION * CK_VERSION_PTR;

/* Non standard definitions */
#define CK_MANUFACTURER_SIZE 32
#define CK_SERIAL_NUMBER_SIZE 16
#define CK_TIME_SIZE 16
#define CK_LIB_DESC_SIZE 32
#define CK_SLOT_DESCRIPTION_SIZE 64
#define CK_SLOT_MANUFACTURER_SIZE 32
#define CK_MAX_PIN_LEN 38
#define CK_MAX_PIN_LEN_LEGACY 32
#define OTP_PIN_LENGTH 6
#define CK_TOKEN_LABEL_SIZE 32
#define CK_TOKEN_MANUFACTURER_SIZE 32
#define CK_TOKEN_MODEL_SIZE 16
#define CK_TOKEN_SERIAL_NUMBER_SIZE 16
#define CK_TOKEN_TIME_SIZE 16
#define CK_MAX_PBE_IV_SIZE	8
#define CK_AES_GCM_MAX_MESSAGE_SIZE (126*1024)
/* AES and ARIA are the largest with a 16 byte block size */
#define CK_MAX_PAD_SIZE 16
/* end Non standard definitions */

typedef struct CK_INFO {
#ifdef V1COMPLIANT
	CK_VERSION version;
#else
	CK_VERSION cryptokiVersion;
#endif
	CK_CHAR manufacturerID[CK_MANUFACTURER_SIZE];
	CK_FLAGS flags;
#ifndef V1COMPLIANT
	CK_CHAR libraryDescription[CK_LIB_DESC_SIZE];
	CK_VERSION libraryVersion;
#endif
} CK_INFO;
typedef CK_INFO * CK_INFO_PTR;

typedef CK_NUMERIC CK_NOTIFICATION;
#define CKN_SURRENDER 0
#ifdef V1COMPLIANT
#define CKN_COMPLETE 1
#define CKN_DEVICE_REMOVED 2
#endif

typedef CK_ULONG CK_SLOT_ID;
typedef CK_SLOT_ID * CK_SLOT_ID_PTR;

typedef struct CK_SLOT_INFO {
	CK_CHAR slotDescription[CK_SLOT_DESCRIPTION_SIZE];
	CK_CHAR manufacturerID[CK_SLOT_MANUFACTURER_SIZE];
	CK_FLAGS flags;
#ifndef V1COMPLIANT
	CK_VERSION hardwareVersion;
	CK_VERSION firmwareVersion;
#endif
} CK_SLOT_INFO;
typedef CK_SLOT_INFO * CK_SLOT_INFO_PTR;

typedef struct CK_TOKEN_INFO {
	CK_CHAR label[CK_TOKEN_LABEL_SIZE];
	CK_CHAR manufacturerID[CK_TOKEN_MANUFACTURER_SIZE];
	CK_CHAR model[CK_TOKEN_MODEL_SIZE];
	CK_CHAR serialNumber[CK_TOKEN_SERIAL_NUMBER_SIZE];
	CK_FLAGS flags;
	CK_COUNT maxSessionCount;
	CK_COUNT sessionCount;
	CK_COUNT maxRwSessionCount;
	CK_COUNT rwSessionCount;
	CK_SIZE maxPinLen;
	CK_SIZE minPinLen;
	CK_ULONG totalPublicMemory;
	CK_ULONG freePublicMemory;
	CK_ULONG totalPrivateMemory;
	CK_ULONG freePrivateMemory;
#ifndef V1COMPLIANT
	CK_VERSION hardwareVersion;
	CK_VERSION firmwareVersion;
	CK_CHAR utcTime[CK_TOKEN_TIME_SIZE];
#endif
} CK_TOKEN_INFO;
typedef CK_TOKEN_INFO * CK_TOKEN_INFO_PTR;

#define CK_UNAVAILABLE_INFORMATION	(~0UL)
#define CK_EFFECTIVELY_INFINITE		0

typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_SESSION_HANDLE * CK_SESSION_HANDLE_PTR;

#define CKU_SO		0    /* Security Officer */
#define CKU_USER	1   /* Normal user */
#define CKU_AUDIT	2   /*Audit User*/

typedef CK_NUMERIC CK_USER_TYPE;
typedef CK_USER_TYPE * CK_USER_TYPE_PTR;

#define CKS_RO_PUBLIC_SESSION 0
#define CKS_RO_USER_FUNCTIONS 1
#define CKS_RW_PUBLIC_SESSION 2
#define CKS_RW_USER_FUNCTIONS 3
#define CKS_RW_SO_FUNCTIONS   4
#define CKS_AUDIT_FUNCTIONS   5
typedef CK_NUMERIC CK_STATE;
typedef CK_STATE * CK_STATE_PTR;

typedef struct CK_SESSION_INFO {
	CK_SLOT_ID slotID;
	CK_STATE state;
	CK_FLAGS flags;
	CK_NUMERIC deviceError;
} CK_SESSION_INFO;
typedef CK_SESSION_INFO * CK_SESSION_INFO_PTR;

typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_OBJECT_HANDLE * CK_OBJECT_HANDLE_PTR;

#define CK_INVALID_HANDLE	0

/* slot info flags */
#define CKF_TOKEN_PRESENT			0x00000001
#define CKF_REMOVABLE_DEVICE		0x00000002
#define CKF_HW_SLOT					0x00000004

/* token info flags */
#define CKF_RNG						0x00000001
#define CKF_WRITE_PROTECTED			0x00000002
#define CKF_LOGIN_REQUIRED			0x00000004
#define CKF_USER_PIN_INITIALIZED	0x00000008
#define CKF_EXCLUSIVE_EXISTS		0x00000010
#define CKF_RESTORE_KEY_NOT_NEEDED  0x00000020
#define CKF_CLOCK_ON_TOKEN			0x00000040
#define CKF_AUDIT_PIN_INITIALIZED	0x00000080
#ifdef NAME32
#define CKF_PROTECTED_AUTHENTICATION_PA      0x00000100
#else
#define CKF_PROTECTED_AUTHENTICATION_PATH      0x00000100
#endif
#define CKF_TOKEN_INITIALIZED			0x00000400
#define CKF_DUAL_CRYPTO_OPERATIONS      0x00000200
#define CKF_SECONDARY_AUTHENTICATION	0x00000800
#define	CKF_USER_PIN_COUNT_LOW			0x00010000
#define CKF_USER_PIN_FINAL_TRY			0x00020000
#define CKF_USER_PIN_LOCKED				0x00040000
#define CKF_USER_PIN_TO_BE_CHANGED		0x00080000
#define CKF_SO_PIN_COUNT_LOW			0x00100000
#define CKF_SO_PIN_FINAL_TRY			0x00200000
#define CKF_SO_PIN_LOCKED				0x00400000
#define CKF_SO_PIN_TO_BE_CHANGED		0x00800000

#define CKF_EXCLUSIVE_SESSION   0x00000001
#define CKF_RW_SESSION          0x00000002
#define CKF_SERIAL_SESSION      0x00000004
#define CKF_AUDIT_SESSION       0x00000008

/* Mechanism information flags */
#define CKF_HW                  0x00000001

#define CKF_EXTENSION           CK_VENDOR_DEFINED

#define CKF_ENCRYPT             0x00000100
#define CKF_DECRYPT             0x00000200
#define CKF_DIGEST              0x00000400
#define CKF_SIGN                0x00000800
#define CKF_SIGN_RECOVER        0x00001000
#define CKF_VERIFY              0x00002000
#define CKF_VERIFY_RECOVER      0x00004000
#define CKF_GENERATE            0x00008000
#define CKF_GENERATE_KEY_PAIR   0x00010000
#define CKF_WRAP                0x00020000
#define CKF_UNWRAP              0x00040000
#define CKF_DERIVE              0x00080000
#define CKF_EC_F_P              0x00100000
#define CKF_EC_F_2M             0x00200000
#define CKF_EC_ECPARAMETERS     0x00400000
#define CKF_EC_NAMEDCURVE       0x00800000
#define CKF_EC_UNCOMPRESS       0x01000000
#define CKF_EC_COMPRESS         0x02000000

typedef CK_NUMERIC CK_OBJECT_CLASS;

#define CKO_DATA            0x00000000
#define CKO_CERTIFICATE     0x00000001
#define CKO_PUBLIC_KEY      0x00000002
#define CKO_PRIVATE_KEY     0x00000003
#define CKO_SECRET_KEY      0x00000004
#define CKO_HW_FEATURE      0x00000005
#define CKO_DOMAIN_PARAMETERS   0x00000006

#define CKO_VENDOR_DEFINED  CK_VENDOR_DEFINED
#define CKO_VENDOR_DEFINED_V1  CK_VENDOR_DEFINED_V1

typedef CK_ULONG CK_HW_FEATURE_TYPE;

#define CKH_MONOTONIC_COUNTER  0x00000001
#define CKH_CLOCK              0x00000002
#define CKH_VENDOR_DEFINED     0x80000000

typedef CK_NUMERIC CK_KEY_TYPE;

#define CKK_RSA             0x00000000
#define CKK_DSA             0x00000001
#define CKK_DH              0x00000002
/* CKK_ECDSA is deprecated in v2.11 */
#define CKK_ECDSA           0x00000003
#define CKK_EC              0x00000003
#define CKK_X9_42_DH        0x00000004
#define CKK_KEA             0x00000005
#define CKK_GENERIC_SECRET  0x00000010
#define CKK_RC2             0x00000011
#define CKK_RC4             0x00000012
#define CKK_RC5             0x00000019
#define CKK_DES             0x00000013
#define CKK_DES2            0x00000014
#define CKK_DES3            0x00000015
#define CKK_CAST            0x00000016
#define CKK_CAST3           0x00000017
/* CKK_CSA5 is deprecated in v2.11 */
#define CKK_CAST5           0x00000018
#define CKK_CAST128         0x00000018
#define CKK_IDEA            0x0000001a
#define CKK_SKIPJACK        0x0000001b
#define CKK_BATON           0x0000001c
#define CKK_JUNIPER         0x0000001d
#define CKK_CDMF            0x0000001e
#define CKK_AES             0x0000001f
#define CKK_ARIA            0x00000026
#define CKK_EC_EDWARDS      0x00000040
#define CKK_EC_MONTGOMERY   0x00000041

#define CKK_VENDOR_DEFINED  CK_VENDOR_DEFINED

typedef CK_NUMERIC CK_CERTIFICATE_TYPE;

#define CKC_X_509           0x00000000
#define CKC_X_509_ATTR_CERT 0x00000001 

#define CKC_VENDOR_DEFINED  CK_VENDOR_DEFINED

typedef CK_NUMERIC CK_ATTRIBUTE_TYPE;
typedef CK_ATTRIBUTE_TYPE * CK_ATTRIBUTE_TYPE_PTR;

#define CKA_CLASS              0x00000000
#define CKA_TOKEN              0x00000001
#define CKA_PRIVATE            0x00000002
#define CKA_LABEL              0x00000003
#define CKA_APPLICATION        0x00000010
#define CKA_VALUE              0x00000011
#define CKA_OBJECT_ID          0x00000012
#define CKA_CERTIFICATE_TYPE   0x00000080
#define CKA_ISSUER             0x00000081
#define CKA_SERIAL_NUMBER      0x00000082
#define CKA_AC_ISSUER          0x00000083
#define CKA_OWNER              0x00000084
#define CKA_ATTR_TYPES         0x00000085
#define CKA_TRUSTED            0x00000086
#define CKA_CHECK_VALUE        0x00000090
#define CKA_KEY_TYPE           0x00000100
#define CKA_SUBJECT            0x00000101
#define CKA_ID                 0x00000102
#define CKA_SENSITIVE          0x00000103
#define CKA_ENCRYPT            0x00000104
#define CKA_DECRYPT            0x00000105
#define CKA_WRAP               0x00000106
#define CKA_UNWRAP             0x00000107
#define CKA_SIGN               0x00000108
#define CKA_SIGN_RECOVER       0x00000109
#define CKA_VERIFY             0x0000010A
#define CKA_VERIFY_RECOVER     0x0000010B
#define CKA_DERIVE             0x0000010C
#define CKA_START_DATE         0x00000110
#define CKA_END_DATE           0x00000111
#define CKA_MODULUS            0x00000120
#define CKA_MODULUS_BITS       0x00000121
#define CKA_PUBLIC_EXPONENT    0x00000122
#define CKA_PRIVATE_EXPONENT   0x00000123
#define CKA_PRIME_1            0x00000124
#define CKA_PRIME_2            0x00000125
#define CKA_EXPONENT_1         0x00000126
#define CKA_EXPONENT_2         0x00000127
#define CKA_COEFFICIENT        0x00000128
#define CKA_PRIME              0x00000130
#define CKA_SUBPRIME           0x00000131
#define CKA_BASE               0x00000132
#define CKA_PRIME_BITS         0x00000133
#define CKA_SUB_PRIME_BITS     0x00000134
#define CKA_VALUE_BITS         0x00000160
#define CKA_VALUE_LEN          0x00000161
#define CKA_EXTRACTABLE        0x00000162
#define CKA_LOCAL              0x00000163
#define CKA_NEVER_EXTRACTABLE  0x00000164
#define CKA_ALWAYS_SENSITIVE   0x00000165
#define CKA_KEY_GEN_MECHANISM  0x00000166
#define CKA_MODIFIABLE         0x00000170
/* CKA_ECDSA_PARAMS is deprecated in v2.11 */
#define CKA_ECDSA_PARAMS       0x00000180
#define CKA_EC_PARAMS          0x00000180
#define CKA_EC_POINT           0x00000181
#define CKA_SECONDARY_AUTH     0x00000200
#define CKA_AUTH_PIN_FLAGS     0x00000201
#define CKA_HW_FEATURE_TYPE    0x00000300
#define CKA_RESET_ON_INIT      0x00000301
#define CKA_HAS_RESET          0x00000302

#define CKA_VENDOR_DEFINED     CK_VENDOR_DEFINED
#define CKA_VENDOR_DEFINED_V1     CK_VENDOR_DEFINED_V1

typedef struct CK_ATTRIBUTE {
	CK_ATTRIBUTE_TYPE type;
	CK_VOID_PTR pValue;
	CK_COUNT valueLen;
} CK_ATTRIBUTE;
typedef CK_ATTRIBUTE * CK_ATTRIBUTE_PTR;

typedef struct CK_DATE{
	CK_CHAR year[4];
	CK_CHAR month[2];
	CK_CHAR day[2];
} CK_DATE;
typedef CK_DATE * CK_DATE_PTR;

typedef CK_NUMERIC CK_MECHANISM_TYPE;
typedef CK_MECHANISM_TYPE * CK_MECHANISM_TYPE_PTR;

/* Mechanism definitions with some version 2.x methods */

#define CKM_RSA_PKCS_KEY_PAIR_GEN  0x00000000
#define CKM_RSA_PKCS               0x00000001
#define CKM_RSA_9796               0x00000002
#define CKM_RSA_X_509              0x00000003
#define CKM_MD2_RSA_PKCS           0x00000004
#define CKM_MD5_RSA_PKCS           0x00000005
#define CKM_SHA1_RSA_PKCS          0x00000006
#define CKM_RIPEMD128_RSA_PKCS     0x00000007
#define CKM_RIPEMD160_RSA_PKCS     0x00000008
#define CKM_RSA_PKCS_OAEP		   0x00000009
#define CKM_RSA_X9_31_KEY_PAIR_GEN 0x0000000A
#define CKM_RSA_X9_31	           0x0000000B
#define CKM_SHA1_RSA_X9_31	       0x0000000C
#define CKM_RSA_PKCS_PSS           0x0000000D
#define CKM_SHA1_RSA_PKCS_PSS      0x0000000E
#define CKM_DSA_KEY_PAIR_GEN       0x00000010
#define CKM_DSA                    0x00000011
#define CKM_DSA_SHA1               0x00000012
#define CKM_DSA_SHA224             0x00000013
#define CKM_DSA_SHA256             0x00000014
#define CKM_DSA_SHA384             0x00000015
#define CKM_DSA_SHA512             0x00000016
#define CKM_DH_PKCS_KEY_PAIR_GEN   0x00000020
#define CKM_DH_PKCS_DERIVE         0x00000021
#define CKM_X9_42_DH_KEY_PAIR_GEN  0x00000030
#define CKM_X9_42_DH_DERIVE        0x00000031
#define CKM_X9_42_DH_HYBRID_DERIVE 0x00000032
#define CKM_X9_42_MQV_DERIVE       0x00000033
#define CKM_SHA256_RSA_PKCS        0x00000040
#define CKM_SHA384_RSA_PKCS        0x00000041
#define CKM_SHA512_RSA_PKCS        0x00000042

#define CKM_SHA256_RSA_PKCS_PSS    0x00000043
#define CKM_SHA384_RSA_PKCS_PSS    0x00000044
#define CKM_SHA512_RSA_PKCS_PSS    0x00000045

#define CKM_SHA224_RSA_PKCS        0x00000046
#define CKM_SHA224_RSA_PKCS_PSS    0x00000047

// Not supported yet
#define CKM_SHA512_224               0x00000048
#define CKM_SHA512_224_HMAC          0x00000049
#define CKM_SHA512_224_HMAC_GENERAL  0x0000004A
#define CKM_SHA512_224_KEY_DERIVATION 0x0000004B
#define CKM_SHA512_256               0x0000004C
#define CKM_SHA512_256_HMAC          0x0000004D
#define CKM_SHA512_256_HMAC_GENERAL  0x0000004E
#define CKM_SHA512_256_KEY_DERIVATION 0x0000004F

#define CKM_SHA3_256_RSA_PKCS      0x00000060
#define CKM_SHA3_384_RSA_PKCS      0x00000061
#define CKM_SHA3_512_RSA_PKCS      0x00000062
#define CKM_SHA3_256_RSA_PKCS_PSS  0x00000063
#define CKM_SHA3_384_RSA_PKCS_PSS  0x00000064
#define CKM_SHA3_512_RSA_PKCS_PSS  0x00000065
#define CKM_SHA3_224_RSA_PKCS      0x00000066
#define CKM_SHA3_224_RSA_PKCS_PSS  0x00000067

#define CKM_RC2_KEY_GEN            0x00000100
#define CKM_RC2_ECB                0x00000101
#define CKM_RC2_CBC                0x00000102
#define CKM_RC2_MAC                0x00000103
#define CKM_RC2_MAC_GENERAL        0x00000104
#define CKM_RC2_CBC_PAD            0x00000105
#define CKM_RC4_KEY_GEN            0x00000110
#define CKM_RC4                    0x00000111
#define CKM_DES_KEY_GEN            0x00000120
#define CKM_DES_ECB                0x00000121
#define CKM_DES_CBC                0x00000122
#define CKM_DES_MAC                0x00000123
#define CKM_DES_MAC_GENERAL        0x00000124
#define CKM_DES_CBC_PAD            0x00000125
#define CKM_DES2_KEY_GEN           0x00000130
#define CKM_DES3_KEY_GEN           0x00000131
#define CKM_DES3_ECB               0x00000132
#define CKM_DES3_CBC               0x00000133
#define CKM_DES3_MAC               0x00000134
#define CKM_DES3_MAC_GENERAL       0x00000135
#define CKM_DES3_CBC_PAD           0x00000136
#define CKM_DES3_CMAC_GENERAL      0x00000137
#define CKM_DES3_CMAC              0x00000138
#define CKM_CDMF_KEY_GEN           0x00000140
#define CKM_CDMF_ECB               0x00000141
#define CKM_CDMF_CBC               0x00000142
#define CKM_CDMF_MAC               0x00000143
#define CKM_CDMF_MAC_GENERAL       0x00000144
#define CKM_CDMF_CBC_PAD           0x00000145
#define CKM_MD2                    0x00000200
#define CKM_MD2_HMAC               0x00000201
#define CKM_MD2_HMAC_GENERAL       0x00000202
#define CKM_MD5                    0x00000210
#define CKM_MD5_HMAC               0x00000211
#define CKM_MD5_HMAC_GENERAL       0x00000212
#define CKM_SHA_1                  0x00000220
#define CKM_SHA_1_HMAC             0x00000221
#define CKM_SHA_1_HMAC_GENERAL     0x00000222
#define CKM_RIPEMD128              0x00000230
#define CKM_RIPEMD128_HMAC         0x00000231
#define CKM_RIPEMD128_HMAC_GENERAL 0x00000232
#define CKM_RIPEMD160              0x00000240
#define CKM_RIPEMD160_HMAC         0x00000241
#define CKM_RIPEMD160_HMAC_GENERAL 0x00000242
#define CKM_SHA256                 0x00000250
#define CKM_SHA256_HMAC            0x00000251
#define CKM_SHA256_HMAC_GENERAL    0x00000252
#define CKM_SHA224                 0x00000255
#define CKM_SHA224_HMAC            0x00000256
#define CKM_SHA224_HMAC_GENERAL    0x00000257
#define CKM_SHA384                 0x00000260
#define CKM_SHA384_HMAC            0x00000261
#define CKM_SHA384_HMAC_GENERAL    0x00000262
#define CKM_SHA512                 0x00000270
#define CKM_SHA512_HMAC            0x00000271
#define CKM_SHA512_HMAC_GENERAL    0x00000272

#define CKM_SHA3_256               0x000002B0
#define CKM_SHA3_256_HMAC          0x000002B1
#define CKM_SHA3_256_HMAC_GENERAL  0x000002B2
#define CKM_SHA3_224               0x000002B5
#define CKM_SHA3_224_HMAC          0x000002B6
#define CKM_SHA3_224_HMAC_GENERAL  0x000002B7
#define CKM_SHA3_384               0x000002C0
#define CKM_SHA3_384_HMAC          0x000002C1
#define CKM_SHA3_384_HMAC_GENERAL  0x000002C2
#define CKM_SHA3_512               0x000002D0
#define CKM_SHA3_512_HMAC          0x000002D1
#define CKM_SHA3_512_HMAC_GENERAL  0x000002D2

#define CKM_CAST_KEY_GEN           0x00000300
#define CKM_CAST_ECB               0x00000301
#define CKM_CAST_CBC               0x00000302
#define CKM_CAST_MAC               0x00000303
#define CKM_CAST_MAC_GENERAL       0x00000304
#define CKM_CAST_CBC_PAD           0x00000305
#define CKM_CAST3_KEY_GEN          0x00000310
#define CKM_CAST3_ECB              0x00000311
#define CKM_CAST3_CBC              0x00000312
#define CKM_CAST3_MAC              0x00000313
#define CKM_CAST3_MAC_GENERAL      0x00000314
#define CKM_CAST3_CBC_PAD          0x00000315
#define CKM_CAST5_KEY_GEN          0x00000320
#define CKM_CAST5_ECB              0x00000321
#define CKM_CAST5_CBC              0x00000322
#define CKM_CAST5_MAC              0x00000323
#define CKM_CAST5_MAC_GENERAL      0x00000324
#define CKM_CAST5_CBC_PAD          0x00000325
#define CKM_CAST128_KEY_GEN        0x00000320
#define CKM_CAST128_ECB            0x00000321
#define CKM_CAST128_CBC            0x00000322
#define CKM_CAST128_MAC            0x00000323
#define CKM_CAST128_MAC_GENERAL    0x00000324
#define CKM_CAST128_CBC_PAD        0x00000325
#define CKM_RC5_KEY_GEN            0x00000330
#define CKM_RC5_ECB                0x00000331
#define CKM_RC5_CBC                0x00000332
#define CKM_RC5_MAC                0x00000333
#define CKM_RC5_MAC_GENERAL        0x00000334
#define CKM_RC5_CBC_PAD            0x00000335
#define CKM_IDEA_KEY_GEN           0x00000340
#define CKM_IDEA_ECB               0x00000341
#define CKM_IDEA_CBC               0x00000342
#define CKM_IDEA_MAC               0x00000343
#define CKM_IDEA_MAC_GENERAL       0x00000344
#define CKM_IDEA_CBC_PAD               0x00000345
#define CKM_GENERIC_SECRET_KEY_GEN     0x00000350
#define CKM_CONCATENATE_BASE_AND_KEY   0x00000360
#define CKM_CONCATENATE_BASE_AND_DATA  0x00000362
#define CKM_CONCATENATE_DATA_AND_BASE  0x00000363
#define CKM_XOR_BASE_AND_DATA          0x00000364
#define CKM_EXTRACT_KEY_FROM_KEY       0x00000365
#define CKM_SSL3_PRE_MASTER_KEY_GEN    0x00000370
#define CKM_SSL3_MASTER_KEY_DERIVE     0x00000371
#define CKM_SSL3_KEY_AND_MAC_DERIVE    0x00000372
#define CKM_SSL3_MASTER_KEY_DERIVE_DH  0x00000373
#define CKM_TLS_PRE_MASTER_KEY_GEN     0x00000374
#define CKM_TLS_MASTER_KEY_DERIVE      0x00000375
#define CKM_TLS_KEY_AND_MAC_DERIVE     0x00000376
#define CKM_TLS_MASTER_KEY_DERIVE_DH   0x00000377
#define CKM_SSL3_MD5_MAC               0x00000380
#define CKM_SSL3_SHA1_MAC              0x00000381
#define CKM_MD5_KEY_DERIVATION         0x00000390
#define CKM_MD2_KEY_DERIVATION         0x00000391
#define CKM_SHA1_KEY_DERIVATION        0x00000392
#define CKM_SHA256_KEY_DERIVATION      0x00000393
#define CKM_SHA384_KEY_DERIVATION      0x00000394
#define CKM_SHA512_KEY_DERIVATION      0x00000395
#define CKM_SHA224_KEY_DERIVATION      0x00000396

#define CKM_SHA3_256_KEY_DERIVE        0x00000397
#define CKM_SHA3_224_KEY_DERIVE        0x00000398
#define CKM_SHA3_384_KEY_DERIVE        0x00000399
#define CKM_SHA3_512_KEY_DERIVE        0x0000039A

#define CKM_PBE_MD2_DES_CBC            0x000003A0
#define CKM_PBE_MD5_DES_CBC            0x000003A1
#define CKM_PBE_MD5_CAST_CBC           0x000003A2
#define CKM_PBE_MD5_CAST3_CBC          0x000003A3
#define CKM_PBE_MD5_CAST5_CBC          0x000003A4
#define CKM_PBE_MD5_CAST128_CBC        0x000003A4
#define CKM_PBE_SHA1_CAST5_CBC         0x000003A5
#define CKM_PBE_SHA1_CAST128_CBC       0x000003A5
#define CKM_PBE_SHA1_RC4_128           0x000003A6
#define CKM_PBE_SHA1_RC4_40            0x000003A7
#define CKM_PBE_SHA1_DES3_EDE_CBC      0x000003A8
#define CKM_PBE_SHA1_DES2_EDE_CBC      0x000003A9
#define CKM_PBE_SHA1_RC2_128_CBC       0x000003AA
#define CKM_PBE_SHA1_RC2_40_CBC        0x000003AB
#define CKM_PKCS5_PBKD2				   0x000003B0
#define CKM_PBA_SHA1_WITH_SHA1_HMAC    0x000003C0
#define CKM_KEY_WRAP_LYNKS             0x00000400
#define CKM_KEY_WRAP_SET_OAEP          0x00000401
#define CKM_ARIA_KEY_GEN               0x00000560
#define CKM_ARIA_ECB                   0x00000561
#define CKM_ARIA_CBC                   0x00000562
#define CKM_ARIA_MAC                   0x00000563
#define CKM_ARIA_MAC_GENERAL           0x00000564
#define CKM_ARIA_CBC_PAD               0x00000565
#define CKM_ARIA_ECB_ENCRYPT_DATA      0x00000566
#define CKM_ARIA_CBC_ENCRYPT_DATA      0x00000567
#define CKM_SKIPJACK_KEY_GEN           0x00001000
#define CKM_SKIPJACK_ECB64             0x00001001
#define CKM_SKIPJACK_CBC64             0x00001002
#define CKM_SKIPJACK_OFB64             0x00001003
#define CKM_SKIPJACK_CFB64             0x00001004
#define CKM_SKIPJACK_CFB32             0x00001005
#define CKM_SKIPJACK_CFB16             0x00001006
#define CKM_SKIPJACK_CFB8              0x00001007
#define CKM_SKIPJACK_WRAP              0x00001008
#define CKM_SKIPJACK_PRIVATE_WRAP      0x00001009
#define CKM_SKIPJACK_RELAYX            0x0000100a
#define CKM_KEA_KEY_PAIR_GEN           0x00001010
#define CKM_KEA_KEY_DERIVE             0x00001011
#define CKM_FORTEZZA_TIMESTAMP         0x00001020
#define CKM_BATON_KEY_GEN              0x00001030
#define CKM_BATON_ECB128               0x00001031
#define CKM_BATON_ECB96                0x00001032
#define CKM_BATON_CBC128               0x00001033
#define CKM_BATON_COUNTER              0x00001034
#define CKM_BATON_SHUFFLE              0x00001035
#define CKM_BATON_WRAP                 0x00001036
/* CKM_ECDSA_KEY_PAIR_GEN is deprecated in v2.11 */
#define CKM_ECDSA_KEY_PAIR_GEN         0x00001040
#define CKM_EC_KEY_PAIR_GEN            0x00001040
#define CKM_ECDSA                      0x00001041
#define CKM_ECDSA_SHA1                 0x00001042
#define CKM_ECDH1_DERIVE_OLD           0x00001043	/* Deprecated */

#define CKM_ECDSA_SHA3_224             0x00001047
#define CKM_ECDSA_SHA3_256             0x00001048
#define CKM_ECDSA_SHA3_384             0x00001049
#define CKM_ECDSA_SHA3_512             0x0000104A

#define CKM_ECDH1_DERIVE               0x00001050
#define CKM_ECDH1_COFACTOR_DERIVE      0x00001051
#define CKM_ECMQV_DERIVE               0x00001052

#define CKM_EC_EDWARDS_KEY_PAIR_GEN    0x00001055
#define CKM_EC_MONTGOMERY_KEY_PAIR_GEN 0x00001056
#define CKM_EDDSA                      0x00001057

#define CKM_JUNIPER_KEY_GEN            0x00001060
#define CKM_JUNIPER_ECB128             0x00001061
#define CKM_JUNIPER_CBC128             0x00001062
#define CKM_JUNIPER_COUNTER            0x00001063
#define CKM_JUNIPER_SHUFFLE            0x00001064
#define CKM_JUNIPER_WRAP               0x00001065
#define CKM_FASTHASH                   0x00001070
#define CKM_AES_KEY_GEN                0x00001080
#define CKM_AES_ECB                    0x00001081
#define CKM_AES_CBC                    0x00001082
#define CKM_AES_MAC                    0x00001083
#define CKM_AES_MAC_GENERAL            0x00001084
#define CKM_AES_CBC_PAD                0x00001085
#define CKM_AES_CTR                    0x00001086
#define CKM_AES_GCM                    0x00001087
#define CKM_AES_CCM                    0x00001088
#define CKM_AES_CTS                    0x00001089  /* in PKCS11-2.4 changed from 108B */
#define CKM_AES_CMAC                   0x0000108A
#define CKM_AES_CMAC_GENERAL           0x0000108B  /* in PKCS11-2.4 changed from 1089 */
#define CKM_AES_GMAC                   0x0000108E
#define CKM_AES_KEY_WRAP               0x00002109
#define CKM_AES_KEY_WRAP_PAD           0x0000210A
#define CKM_BLOWFISH_KEY_GEN           0x00001090 /* Correct label to value, but not supported*/
#define CKM_BLOWFISH_CBC               0x00001091 /* Correct label to value, but not supported*/
#define CKM_AES_KEY_WRAP_DEPRECATED      0x00001090 /*Should be CKM_BLOWFISH_KEY_GEN */
#define CKM_AES_KEY_WRAP_PAD_DEPRECATED  0x00001091 /*Should be CKM_BLOWFISH_CBC */
#define CKM_DES_ECB_ENCRYPT_DATA       0x00001100
#define CKM_DES_CBC_ENCRYPT_DATA       0x00001101
#define CKM_DES3_ECB_ENCRYPT_DATA      0x00001102
#define CKM_DES3_CBC_ENCRYPT_DATA      0x00001103
#define CKM_AES_ECB_ENCRYPT_DATA       0x00001104
#define CKM_AES_CBC_ENCRYPT_DATA       0x00001105
#define CKM_DSA_PARAMETER_GEN          0x00002000
#define CKM_DH_PKCS_PARAMETER_GEN      0x00002001
#define CKM_X9_42_DH_PARAMETER_GEN     0x00002002
#define CKM_AES_OFB                    0x00002104

#define CKM_VENDOR_DEFINED         CK_VENDOR_DEFINED
#define CKM_VENDOR_DEFINED_V1      CK_VENDOR_DEFINED_V1

typedef struct CK_MECHANISM {
	CK_MECHANISM_TYPE mechanism;
	CK_VOID_PTR pParameter;
	CK_SIZE parameterLen;
} CK_MECHANISM;
typedef CK_MECHANISM * CK_MECHANISM_PTR;

typedef struct CK_MECHANISM_INFO {
	CK_ULONG minKeySize;
	CK_ULONG maxKeySize;
	CK_FLAGS flags;
} CK_MECHANISM_INFO;
typedef CK_MECHANISM_INFO * CK_MECHANISM_INFO_PTR;

/* CK_RC2_PARAMS provides the parameters to the CKM_RC2_ECB and
 * CKM_RC2_MAC mechanisms.  An instance of CK_RC2_PARAMS just
 * holds the effective keysize */
typedef CK_ULONG          CK_RC2_PARAMS;

typedef CK_RC2_PARAMS * CK_RC2_PARAMS_PTR;

typedef struct CK_RC2_CBC_PARAMS {
	CK_SIZE effectiveBits;
	CK_BYTE iv[8];
} CK_RC2_CBC_PARAMS;
typedef CK_RC2_CBC_PARAMS * CK_RC2_CBC_PARAMS_PTR;

typedef struct CK_PBE_PARAMS {
  CK_CHAR_PTR  pInitVector;
  CK_CHAR_PTR  pPassword;
  CK_SIZE      passwordLen;
  CK_CHAR_PTR  pSalt;
  CK_SIZE      saltLen;
  CK_SIZE      iteration;
} CK_PBE_PARAMS;

typedef CK_PBE_PARAMS * CK_PBE_PARAMS_PTR;

/* CK_KEY_WRAP_SET_OAEP_PARAMS provides the parameters to the
 * CKM_KEY_WRAP_SET_OAEP mechanism */
/* CK_KEY_WRAP_SET_OAEP_PARAMS is new for v2.0 */
typedef struct CK_KEY_WRAP_SET_OAEP_PARAMS {
  CK_BYTE       bBC;     /* block contents byte */
  CK_BYTE_PTR   pX;      /* extra data */
  CK_ULONG      XLen;    /* length of extra data in bytes */
} CK_KEY_WRAP_SET_OAEP_PARAMS;

typedef CK_KEY_WRAP_SET_OAEP_PARAMS * \
  CK_KEY_WRAP_SET_OAEP_PARAMS_PTR;

typedef struct CK_GCM_PARAMS {
	CK_BYTE_PTR pIv;
	CK_ULONG ulIvLen;/* in octets */
	CK_BYTE_PTR pAAD;
	CK_ULONG ulAADLen;/* in octets */
	CK_ULONG ulTagBits;/* in bits */
} CK_GCM_PARAMS;

typedef CK_GCM_PARAMS * CK_GCM_PARAMS_PTR;

/*
 * CK_CCM_PARAMS:
 * The fields of the structure have the following meanings, where L is the size in bytes of the
 *	data length's length (2 < L < 8):
 *	'ulDataLen' - length of the data where 0 <= ulDataLen < 28L.
 *	'pNonce' - the nonce.
 *	'ulNonceLen' - length of pNonce (<= 15-L) in bytes = {7,8,9,10,11,12,13}.
 *	'pAAD' Additional authentication data. This data is authenticated but not encrypted.
 *	'ulAADLen' - length of pAuthData in bytes.
 *	'ulMACLen' - length of the MAC (output following cipher text) in
 *	             bytes. Valid values are 4, 6, 8, 10, 12, 14, and 16.
 */
typedef struct CK_CCM_PARAMS {
	CK_ULONG    ulDataLen; /*plaintext or ciphertext*/
	CK_BYTE_PTR pNonce;
	CK_ULONG    ulNonceLen;
	CK_BYTE_PTR pAAD;
	CK_ULONG    ulAADLen;
	CK_ULONG    ulMACLen;//in octs
} CK_CCM_PARAMS;
typedef CK_CCM_PARAMS * CK_CCM_PARAMS_PTR;

typedef struct CK_AES_CTR_PARAMS {
	CK_ULONG ulCounterBits;   // how many LSB bits of cb increment
	CK_BYTE cb[16];           // counter block
} CK_AES_CTR_PARAMS;

typedef CK_AES_CTR_PARAMS * CK_AES_CTR_PARAMS_PTR;

typedef struct CK_EDDSA_PARAMS {
    CK_BBOOL    phFlag;
    CK_ULONG    ulContextDataLen;
    CK_BYTE_PTR pContextData;
} CK_EDDSA_PARAMS;
typedef struct CK_EDDSA_PARAMS *CK_EDDSA_PARAMS_PTR;

#define CKG_MGF1_SHA1 0x00000001
#define CKG_MGF1_SHA224 0x00000005
#define CKG_MGF1_SHA256 0x00000002
#define CKG_MGF1_SHA384 0x00000003
#define CKG_MGF1_SHA512 0x00000004
#define CKG_MGF1_SHA3_224 0x00000006
#define CKG_MGF1_SHA3_256 0x00000007
#define CKG_MGF1_SHA3_384 0x00000008
#define CKG_MGF1_SHA3_512 0x00000009

#define CKZ_DATA_SPECIFIED 0x00000001

typedef CK_ULONG CK_RSA_PKCS_OAEP_MGF_TYPE;
typedef CK_ULONG CK_RSA_PKCS_OAEP_SOURCE_TYPE;

typedef struct CK_RSA_PKCS_OAEP_PARAMS {
	CK_MECHANISM_TYPE hashAlg;
	CK_RSA_PKCS_OAEP_MGF_TYPE mgf;
	CK_RSA_PKCS_OAEP_SOURCE_TYPE source;
	CK_VOID_PTR pSourceData;
	CK_ULONG sourceDataLen;
} CK_RSA_PKCS_OAEP_PARAMS;

typedef CK_RSA_PKCS_OAEP_PARAMS * CK_RSA_PKCS_OAEP_PARAMS_PTR;

typedef CK_ULONG CK_RSA_PKCS_MGF_TYPE;

typedef struct CK_RSA_PKCS_PSS_PARAMS {
	CK_MECHANISM_TYPE hashAlg;	/* e.g. CKM_SHA256 */
	CK_RSA_PKCS_MGF_TYPE mgf; /* e.g. CKG_MGF1_SHA256 */
	CK_ULONG sLen;			/* salt length */
} CK_RSA_PKCS_PSS_PARAMS;

typedef CK_RSA_PKCS_PSS_PARAMS * CK_RSA_PKCS_PSS_PARAMS_PTR;

typedef struct CK_SSL3_RANDOM_DATA {
  CK_BYTE_PTR  pClientRandom;
  CK_ULONG     clientRandomLen;
  CK_BYTE_PTR  pServerRandom;
  CK_ULONG     serverRandomLen;
} CK_SSL3_RANDOM_DATA;

#ifndef NAME32
typedef struct CK_SSL3_MASTER_KEY_DERIVE_PARAMS {
  CK_SSL3_RANDOM_DATA RandomInfo;
  CK_VERSION_PTR pVersion;
} CK_SSL3_MASTER_KEY_DERIVE_PARAMS;

typedef struct CK_SSL3_MASTER_KEY_DERIVE_PARAMS * CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR;
#else
typedef struct CK_SSL3_MASTER_KEY_DERIVE_PARAM {
  CK_SSL3_RANDOM_DATA RandomInfo;
  CK_VERSION_PTR pVersion;
} CK_SSL3_MASTER_KEY_DERIVE_PARAM;
#endif

typedef struct CK_SSL3_KEY_MAT_OUT {
  CK_OBJECT_HANDLE hClientMacSecret;
  CK_OBJECT_HANDLE hServerMacSecret;
  CK_OBJECT_HANDLE hClientKey;
  CK_OBJECT_HANDLE hServerKey;
  CK_BYTE_PTR      pIVClient;
  CK_BYTE_PTR      pIVServer;
} CK_SSL3_KEY_MAT_OUT;

typedef CK_SSL3_KEY_MAT_OUT * CK_SSL3_KEY_MAT_OUT_PTR;


typedef struct CK_SSL3_KEY_MAT_PARAMS {
  CK_ULONG                macSizeInBits;
  CK_ULONG                keySizeInBits;
  CK_ULONG                IVSizeInBits;
  CK_BBOOL                bIsExport;
  CK_SSL3_RANDOM_DATA     RandomInfo;
  CK_SSL3_KEY_MAT_OUT_PTR pReturnedKeyMaterial;
} CK_SSL3_KEY_MAT_PARAMS;

typedef CK_SSL3_KEY_MAT_PARAMS * CK_SSL3_KEY_MAT_PARAMS_PTR;


typedef struct CK_ARIA_CBC_ENCRYPT_DATA_PARAMS {
  CK_BYTE      iv[16];
  CK_BYTE_PTR  pData;
  CK_ULONG     length;
} CK_ARIA_CBC_ENCRYPT_DATA_PARAMS, CK_AES_CBC_ENCRYPT_DATA_PARAMS;

typedef CK_ARIA_CBC_ENCRYPT_DATA_PARAMS * CK_ARIA_CBC_ENCRYPT_DATA_PARAMS_PTR;
/*
 * ...Similar definition for AES CBC:
 */
typedef CK_AES_CBC_ENCRYPT_DATA_PARAMS * CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR;

typedef struct CK_DES_CBC_ENCRYPT_DATA_PARAMS {
  CK_BYTE      iv[8];
  CK_BYTE_PTR  pData;
  CK_ULONG     length;
} CK_DES_CBC_ENCRYPT_DATA_PARAMS;
typedef CK_DES_CBC_ENCRYPT_DATA_PARAMS * CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR;

typedef struct CK_KEY_DERIVATION_STRING_DATA {
  CK_BYTE_PTR  pData;
  CK_ULONG     len;
} CK_KEY_DERIVATION_STRING_DATA;

#ifdef NAME32
typedef CK_KEY_DERIVATION_STRING_DATA * CK_KEY_DERIVATION_STRING_DATA_P;
#else
typedef CK_KEY_DERIVATION_STRING_DATA * CK_KEY_DERIVATION_STRING_DATA_PTR;
#endif


/* The CK_EXTRACT_PARAMS is used for the
 * CKM_EXTRACT_KEY_FROM_KEY mechanism.  It specifies which bit
 * of the base key should be used as the first bit of the
 * derived key */
/* CK_EXTRACT_PARAMS is new for v2.0 */
typedef CK_ULONG CK_EXTRACT_PARAMS;

typedef CK_EXTRACT_PARAMS * CK_EXTRACT_PARAMS_PTR;

/* EC Key Derivation Function - New for v2.11. */
typedef CK_ULONG CK_EC_KDF_TYPE;

/* DH X9.42 Key Derivation Function */
typedef CK_ULONG CK_X9_42_DH_KDF_TYPE;
/* The following EC Key Derivation Functions are defined */

#define CKD_NULL                  0x00000001	/* No KDF */
#define CKD_SHA1_KDF              0x00000002	/* KDF from ANSI X9.63. with SHA-1 */

#define CKD_SHA224_KDF            0x80000003
#define CKD_SHA256_KDF            0x80000004
#define CKD_SHA384_KDF            0x80000005
#define CKD_SHA512_KDF            0x80000006
#define CKD_RIPEMD160_KDF         0x80000007

#define CKD_SHA1_NIST_KDF         0x00000012
#define CKD_SHA224_NIST_KDF       0x80000013
#define CKD_SHA256_NIST_KDF       0x80000014
#define CKD_SHA384_NIST_KDF       0x80000015
#define CKD_SHA512_NIST_KDF       0x80000016
#define CKD_RIPEMD160_NIST_KDF    0x80000017

#define CKD_SHA1_SES_KDF          0x82000000
#define CKD_SHA224_SES_KDF        0x83000000
#define CKD_SHA256_SES_KDF        0x84000000
#define CKD_SHA384_SES_KDF        0x85000000
#define CKD_SHA512_SES_KDF        0x86000000
#define CKD_RIPEMD160_SES_KDF     0x87000000
/* KDFs from X9.42	*/
#define CKD_SHA1_KDF_ASN1         0x80200000
#define CKD_SHA224_KDF_ASN1       0x80300000
#define CKD_SHA256_KDF_ASN1       0x80400000
#define CKD_SHA384_KDF_ASN1       0x80500000
#define CKD_SHA512_KDF_ASN1       0x80600000
#define CKD_SHA1_KDF_CONCATENATE    0x80700000
#define CKD_SHA224_KDF_CONCATENATE  0x80800000
#define CKD_SHA256_KDF_CONCATENATE  0x80900000
#define CKD_SHA384_KDF_CONCATENATE  0x80a00000
#define CKD_SHA512_KDF_CONCATENATE  0x80b00000

/* counter values for TR-03111 Session Keys */
#define CKD_SES_MIN_CTR           0x00000000
#define CKD_SES_ENC_CTR           0x00000001
#define CKD_SES_AUTH_CTR          0x00000002
#define CKD_SES_ALT_ENC_CTR       0x00000003
#define CKD_SES_ALT_AUTH_CTR      0x00000004
#define CKD_SES_MAX_CTR           0x0000FFFF


typedef struct CK_ECDH1_DERIVE_PARAMS {
    CK_EC_KDF_TYPE kdf;
    CK_ULONG       ulSharedDataLen;
    CK_BYTE_PTR    pSharedData;
    CK_ULONG       ulPublicDataLen;
    CK_BYTE_PTR    pPublicData;
} CK_ECDH1_DERIVE_PARAMS;

typedef struct CK_ECDH1_DERIVE_PARAMS * CK_ECDH1_DERIVE_PARAMS_PTR;
/*
 * For ASN1 KDFs DER decoded OtherInfo structure:
 */
typedef struct X9_42_OTHER_INFO {
	CK_BYTE_PTR algorithmId;
	CK_ULONG Counter;//Should be BIG ENDIAN!!!
#if 1
	//We need all the fields to be concatenated
	CK_BYTE_PTR partyUVInfo;
#else
	CK_BYTE_PTR partyUInfo;
	//CK_ULONG partyUInfoLen;
	CK_BYTE_PTR partyVInfo;
	//CK_ULONG partyVInfoLen;
	CK_BYTE_PTR suppPubInfo;
	//CK_ULONG suppPubInfoLen;
	CK_BYTE_PTR suppPrivInfo;
	//CK_ULONG suppPrivInfoLen;
#endif
} X9_42_OTHER_INFO;

typedef struct CK_X9_42_DH1_DERIVE_PARAMS {
	CK_X9_42_DH_KDF_TYPE kdf;	//key derivation function used on the shared secret value
	CK_ULONG ulOtherInfoLen;	//the length in bytes of the other info
	CK_BYTE_PTR pOtherInfo;		//some data shared between the two parties
	CK_ULONG ulPublicDataLen;	//the length in bytes of the other party's X9.42 DH public key
	CK_BYTE_PTR pPublicData;	//pointer to other party's X9.42 DH public key value
} CK_X9_42_DH1_DERIVE_PARAMS;

typedef struct {
	CK_X9_42_DH_KDF_TYPE kdf;
	CK_ULONG ulOtherInfoLen;
	CK_BYTE_PTR  pOtherInfo;
	CK_ULONG ulPublicDataLen;
	CK_BYTE_PTR  pPublicData;
	CK_ULONG ulPrivateDataLen;
	CK_ULONG hPrivateData;
	CK_ULONG ulPublicDataLen2;
	CK_BYTE_PTR  pPublicData2;
} CK_X9_42_DH2_DERIVE_PARAMS;

/* return codes */

typedef CK_NUMERIC CK_RV;

#define CKR_OK                                0x00000000
#define CKR_CANCEL                            0x00000001
#define CKR_HOST_MEMORY                       0x00000002
#define CKR_SLOT_ID_INVALID                   0x00000003
#ifdef V1COMPLIANT
#define CKR_FLAGS_INVALID                     0x00000004
#endif
#define CKR_GENERAL_ERROR                     0x00000005
#define CKR_FUNCTION_FAILED                   0x00000006
#define CKR_ARGUMENTS_BAD                     0x00000007
#define CKR_NO_EVENT                          0x00000008
#define CKR_NEED_TO_CREATE_THREADS            0x00000009
#define CKR_CANT_LOCK                         0x0000000A
#define CKR_ATTRIBUTE_READ_ONLY               0x00000010
#define CKR_ATTRIBUTE_SENSITIVE               0x00000011
#define CKR_ATTRIBUTE_TYPE_INVALID            0x00000012
#define CKR_ATTRIBUTE_VALUE_INVALID           0x00000013
#define CKR_DATA_INVALID                      0x00000020
#define CKR_DATA_LEN_RANGE                    0x00000021
#define CKR_DEVICE_ERROR                      0x00000030
#define CKR_DEVICE_MEMORY                     0x00000031
#define CKR_DEVICE_REMOVED                    0x00000032
#define CKR_ENCRYPTED_DATA_INVALID            0x00000040
#define CKR_ENCRYPTED_DATA_LEN_RANGE          0x00000041
#define CKR_FUNCTION_CANCELED                 0x00000050
#define CKR_FUNCTION_NOT_PARALLEL             0x00000051
#ifdef V1COMPLIANT
#define CKR_FUNCTION_PARALLEL                 0x00000052
#endif
#define CKR_FUNCTION_NOT_SUPPORTED            0x00000054
#define CKR_KEY_HANDLE_INVALID                0x00000060
#ifdef V1COMPLIANT
#define CKR_KEY_SENSITIVE                     0x00000061
#endif
#define CKR_KEY_SIZE_RANGE                    0x00000062
#define CKR_KEY_TYPE_INCONSISTENT             0x00000063
#define CKR_KEY_NOT_NEEDED                    0x00000064
#define CKR_KEY_CHANGED                       0x00000065
#define CKR_KEY_NEEDED                        0x00000066
#define CKR_KEY_INDIGESTABLE                  0x00000067
#define CKR_KEY_FUNCTION_NOT_PERMITTED        0x00000068
#define CKR_KEY_NOT_WRAPPABLE                 0x00000069
#define CKR_KEY_UNEXTRACTABLE                 0x0000006A
#define CKR_KEY_PARAMS_INVALID                0x0000006B
#define CKR_KEYLEN_INVALID                    0x0000006C
#define CKR_MECHANISM_INVALID                 0x00000070
#define CKR_MECHANISM_PARAM_INVALID           0x00000071
#ifdef V1COMPLIANT
#define CKR_OBJECT_CLASS_INCONSISTENT         0x00000080
#define CKR_OBJECT_CLASS_INVALID              0x00000081
#endif
#define CKR_OBJECT_HANDLE_INVALID             0x00000082
#define CKR_OPERATION_ACTIVE                  0x00000090
#define CKR_OPERATION_NOT_INITIALIZED         0x00000091
#define CKR_PIN_INCORRECT                     0x000000A0
#define CKR_PIN_INVALID                       0x000000A1
#define CKR_PIN_LEN_RANGE                     0x000000A2
#define CKR_PIN_EXPIRED                       0x000000A3
#define CKR_PIN_LOCKED                        0x000000A4
#define CKR_SESSION_CLOSED                    0x000000B0
#define CKR_SESSION_COUNT                     0x000000B1
/* V1COMPLIANT */
#define CKR_SESSION_EXCLUSIVE_EXISTS          0x000000B2
#define CKR_SESSION_HANDLE_INVALID            0x000000B3
#ifdef NAME32
#define CKR_SESSION_PARALLEL_NOT_SUPPOR       0x000000B4
#else
#define CKR_SESSION_PARALLEL_NOT_SUPPORTED    0x000000B4
#endif
#define CKR_SESSION_READ_ONLY                 0x000000B5
#define CKR_SESSION_EXISTS                    0x000000B6
#define CKR_SESSION_READ_ONLY_EXISTS          0x000000B7
#ifdef NAME32
#define CKR_SESSION_READ_WRITE_SO_EXIST       0x000000B8
#else
#define CKR_SESSION_READ_WRITE_SO_EXISTS      0x000000B8
#endif
#define CKR_SIGNATURE_INVALID                 0x000000C0
#define CKR_SIGNATURE_LEN_RANGE               0x000000C1
#define CKR_TEMPLATE_INCOMPLETE               0x000000D0
#define CKR_TEMPLATE_INCONSISTENT             0x000000D1
#define CKR_TOKEN_NOT_PRESENT                 0x000000E0
#define CKR_TOKEN_NOT_RECOGNIZED              0x000000E1
#define CKR_TOKEN_WRITE_PROTECTED             0x000000E2
#ifdef NAME32
#define CKR_UNWRAPPING_KEY_HANDLE_INVAL       0x000000F0
#define CKR_UNWRAPPING_KEY_TYPE_INCONSI		  0x000000F2
#else
#define CKR_UNWRAPPING_KEY_HANDLE_INVALID     0x000000F0
#define CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT  0x000000F2
#endif
#define CKR_UNWRAPPING_KEY_SIZE_RANGE         0x000000F1
#ifdef NAME32
#else
#endif
#define CKR_USER_ALREADY_LOGGED_IN            0x00000100
#define CKR_USER_NOT_LOGGED_IN                0x00000101
#define CKR_USER_PIN_NOT_INITIALIZED          0x00000102
#define CKR_USER_TYPE_INVALID                 0x00000103
#ifdef NAME32
#define CKR_USER_ANOTHER_ALREADY_LOGGED       0x00000104
#else
#define CKR_USER_ANOTHER_ALREADY_LOGGED_IN    0x00000104
#endif
#define CKR_USER_TOO_MANY_TYPES               0x00000105
#define CKR_WRAPPED_KEY_INVALID               0x00000110
#define CKR_WRAPPED_KEY_LEN_RANGE             0x00000112
#define CKR_WRAPPING_KEY_HANDLE_INVALID       0x00000113
#define CKR_WRAPPING_KEY_SIZE_RANGE           0x00000114
#ifdef NAME32
#define CKR_WRAPPING_KEY_TYPE_INCONSIST       0x00000115
#define CKR_CRYPTOKI_ALREADY_INITIALIZE       0x00000191
#else
#define CKR_WRAPPING_KEY_TYPE_INCONSISTENT    0x00000115
#define CKR_CRYPTOKI_ALREADY_INITIALIZED      0x00000191
#endif
#define CKR_RANDOM_SEED_NOT_SUPPORTED         0x00000120
#define CKR_RANDOM_NO_RNG                     0x00000121
#define CKR_DOMAIN_PARAMS_INVALID             0x00000130
#define CKR_BUFFER_TOO_SMALL                  0x00000150
#define CKR_SAVED_STATE_INVALID               0x00000160
#define CKR_INFORMATION_SENSITIVE             0x00000170
#define CKR_STATE_UNSAVEABLE                  0x00000180
#define CKR_CRYPTOKI_NOT_INITIALIZED          0x00000190
#define CKR_MUTEX_BAD                         0x000001A0
#define CKR_MUTEX_NOT_LOCKED                  0x000001A1

#define CKR_VENDOR_DEFINED                    CK_VENDOR_DEFINED

/* CK_FUNCTION_LIST is a structure holding a Cryptoki spec
 * version and pointers of appropriate types to all the
 * Cryptoki functions */
/* CK_FUNCTION_LIST is new for v2.0 */
typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;

typedef CK_FUNCTION_LIST * CK_FUNCTION_LIST_PTR;

typedef CK_FUNCTION_LIST_PTR * CK_FUNCTION_LIST_PTR_PTR;

#define CK_CALLBACK_FUNCTION(returnType, name) returnType(* name)

/* CK_NOTIFY is an application callback that processes events */
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_NOTIFY)(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_NOTIFICATION   event,
  CK_VOID_PTR       pApplication  /* passed to C_OpenSession */
);

/* CK_CREATEMUTEX is an application callback for creating a
 * mutex object */
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_CREATEMUTEX)(
  CK_VOID_PTR_PTR ppMutex  /* location to receive ptr to mutex */
);

/* CK_DESTROYMUTEX is an application callback for destroying a
 * mutex object */
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_DESTROYMUTEX)(
  CK_VOID_PTR pMutex  /* pointer to mutex */
);

/* CK_LOCKMUTEX is an application callback for locking a mutex */
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_LOCKMUTEX)(
  CK_VOID_PTR pMutex  /* pointer to mutex */
);

/* CK_UNLOCKMUTEX is an application callback for unlocking a
 * mutex */
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_UNLOCKMUTEX)(
  CK_VOID_PTR pMutex  /* pointer to mutex */
);

/* CK_C_INITIALIZE_ARGS provides the optional arguments to
 * C_Initialize */
typedef struct CK_C_INITIALIZE_ARGS {
  CK_CREATEMUTEX CreateMutex;
  CK_DESTROYMUTEX DestroyMutex;
  CK_LOCKMUTEX LockMutex;
  CK_UNLOCKMUTEX UnlockMutex;
  CK_FLAGS flags;
  CK_VOID_PTR pReserved;
} CK_C_INITIALIZE_ARGS;

/* flags: bit flags that provide capabilities of the slot
 *      Bit Flag                           Mask       Meaning
 */
#ifdef NAME32
#define CKF_LIBRARY_CANT_CREATE_OS_THRE    0x00000001
#else
#define CKF_LIBRARY_CANT_CREATE_OS_THREADS 0x00000001
#endif
#define CKF_OS_LOCKING_OK                  0x00000002

typedef CK_C_INITIALIZE_ARGS * CK_C_INITIALIZE_ARGS_PTR;

/* additional flags for parameters to functions */

/* CKF_DONT_BLOCK is for the function C_WaitForSlotEvent */
#define CKF_DONT_BLOCK     1


/* CK_KEA_DERIVE_PARAMS provides the parameters to the
 * CKM_KEA_DERIVE mechanism */
/* CK_KEA_DERIVE_PARAMS is new for v2.0 */
typedef struct CK_KEA_DERIVE_PARAMS {
  CK_BBOOL      isSender;
  CK_ULONG      ulRandomLen;
  CK_BYTE_PTR   pRandomA;
  CK_BYTE_PTR   pRandomB;
  CK_ULONG      ulPublicDataLen;
  CK_BYTE_PTR   pPublicData;
} CK_KEA_DERIVE_PARAMS;

typedef CK_KEA_DERIVE_PARAMS * CK_KEA_DERIVE_PARAMS_PTR;

/* CK_RC2_MAC_GENERAL_PARAMS provides the parameters for the
 * CKM_RC2_MAC_GENERAL mechanism */
/* CK_RC2_MAC_GENERAL_PARAMS is new for v2.0 */
typedef struct CK_RC2_MAC_GENERAL_PARAMS {
  CK_ULONG      effectiveBits;  /* effective bits (1-1024) */
  CK_ULONG      macLength;      /* Length of MAC in bytes */
} CK_RC2_MAC_GENERAL_PARAMS;

typedef CK_RC2_MAC_GENERAL_PARAMS * CK_RC2_MAC_GENERAL_PARAMS_PTR;


/* CK_RC5_PARAMS provides the parameters to the CKM_RC5_ECB and
 * CKM_RC5_MAC mechanisms */
/* CK_RC5_PARAMS is new for v2.0 */
typedef struct CK_RC5_PARAMS {
  CK_ULONG      wordsize;  /* wordsize in bits */
  CK_ULONG      rounds;    /* number of rounds */
} CK_RC5_PARAMS;

typedef CK_RC5_PARAMS * CK_RC5_PARAMS_PTR;


/* CK_RC5_CBC_PARAMS provides the parameters to the CKM_RC5_CBC
 * mechanism */
/* CK_RC5_CBC_PARAMS is new for v2.0 */
typedef struct CK_RC5_CBC_PARAMS {
  CK_ULONG      wordsize;  /* wordsize in bits */
  CK_ULONG      rounds;    /* number of rounds */
  CK_BYTE_PTR   pIv;         /* pointer to IV */
  CK_ULONG      ivLen;     /* length of IV in bytes */
} CK_RC5_CBC_PARAMS;

typedef CK_RC5_CBC_PARAMS * CK_RC5_CBC_PARAMS_PTR;


/* CK_RC5_MAC_GENERAL_PARAMS provides the parameters for the
 * CKM_RC5_MAC_GENERAL mechanism */
/* CK_RC5_MAC_GENERAL_PARAMS is new for v2.0 */
typedef struct CK_RC5_MAC_GENERAL_PARAMS {
  CK_ULONG      wordsize;   /* wordsize in bits */
  CK_ULONG      rounds;     /* number of rounds */
  CK_ULONG      ulMacLength;  /* Length of MAC in bytes */
} CK_RC5_MAC_GENERAL_PARAMS;

typedef CK_RC5_MAC_GENERAL_PARAMS * CK_RC5_MAC_GENERAL_PARAMS_PTR;


/* CK_MAC_GENERAL_PARAMS provides the parameters to most block
 * ciphers' MAC_GENERAL mechanisms.  Its value is the length of
 * the MAC */
/* CK_MAC_GENERAL_PARAMS is new for v2.0 */
typedef CK_ULONG          CK_MAC_GENERAL_PARAMS;

typedef CK_MAC_GENERAL_PARAMS * CK_MAC_GENERAL_PARAMS_PTR;


/* CK_SKIPJACK_PRIVATE_WRAP_PARAMS provides the parameters to the
 * CKM_SKIPJACK_PRIVATE_WRAP mechanism */
/* CK_SKIPJACK_PRIVATE_WRAP_PARAMS is new for v2.0 */
typedef struct CK_SKIPJACK_PRIVATE_WRAP_PARAMS {
  CK_ULONG      ulPasswordLen;
  CK_BYTE_PTR   pPassword;
  CK_ULONG      ulPublicDataLen;
  CK_BYTE_PTR   pPublicData;
  CK_ULONG      ulPAndGLen;
  CK_ULONG      ulQLen;
  CK_ULONG      ulRandomLen;
  CK_BYTE_PTR   pRandomA;
  CK_BYTE_PTR   pPrimeP;
  CK_BYTE_PTR   pBaseG;
  CK_BYTE_PTR   pSubprimeQ;
} CK_SKIPJACK_PRIVATE_WRAP_PARAMS;

typedef CK_SKIPJACK_PRIVATE_WRAP_PARAMS * CK_SKIPJACK_PRIVATE_WRAP_PTR;


/* CK_SKIPJACK_RELAYX_PARAMS provides the parameters to the
 * CKM_SKIPJACK_RELAYX mechanism */
/* CK_SKIPJACK_RELAYX_PARAMS is new for v2.0 */
typedef struct CK_SKIPJACK_RELAYX_PARAMS {
  CK_ULONG      ulOldWrappedXLen;
  CK_BYTE_PTR   pOldWrappedX;
  CK_ULONG      ulOldPasswordLen;
  CK_BYTE_PTR   pOldPassword;
  CK_ULONG      ulOldPublicDataLen;
  CK_BYTE_PTR   pOldPublicData;
  CK_ULONG      ulOldRandomLen;
  CK_BYTE_PTR   pOldRandomA;
  CK_ULONG      ulNewPasswordLen;
  CK_BYTE_PTR   pNewPassword;
  CK_ULONG      ulNewPublicDataLen;
  CK_BYTE_PTR   pNewPublicData;
  CK_ULONG      ulNewRandomLen;
  CK_BYTE_PTR   pNewRandomA;
} CK_SKIPJACK_RELAYX_PARAMS;

typedef CK_SKIPJACK_RELAYX_PARAMS * CK_SKIPJACK_RELAYX_PARAMS_PTR;

#ifdef __cplusplus
extern "C" {                /* define as 'C' functions to prevent mangling */
#endif

#ifdef V1COMPLIANT

/* V1 definitions */
#undef INC_PKCS11F1_H
#include "pkcs11f1.h"

#else
#if defined(_MSC_VER)
#define DLL_EXPORT __declspec( dllexport )
#else
#define DLL_EXPORT __attribute__((visibility("default")))
#endif

/* V2 definitions */

#define CK_DEFINE_FUNCTION(returnType, name) \
   DLL_EXPORT returnType CK_ENTRY name
#define CK_DECLARE_FUNCTION(returnType, name) \
   DLL_EXPORT returnType CK_ENTRY name
#if defined (INSAM) || defined(_WIN32)
/* SAMs, 16 bit OS2, or 32 bit windows */
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
   returnType ( CK_ENTRY * name)
#else
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
   returnType CK_ENTRY (* name)
#endif

#define __PASTE(x,y)      x##y


/* ==============================================================
 * Define the "extern" form of all the entry points.
 * ==============================================================
 */

#define CK_NEED_ARG_LIST  1
#define CK_PKCS11_FUNCTION_INFO(name) \
  extern CK_DECLARE_FUNCTION(CK_RV, name)

/* pkcs11f.h has all the information about the Cryptoki
 * function prototypes. */
#undef INC_PKCS11F_H
#include "pkcs11f.h"

#undef CK_NEED_ARG_LIST
#undef CK_PKCS11_FUNCTION_INFO


/* ==============================================================
 * Define the typedef form of all the entry points.  That is, for
 * each Cryptoki function C_XXX, define a type CK_C_XXX which is
 * a pointer to that kind of function.
 * ==============================================================
 */

#define CK_NEED_ARG_LIST  1
#define CK_PKCS11_FUNCTION_INFO(name) \
  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, __PASTE(CK_,name))

/* pkcs11f.h has all the information about the Cryptoki
 * function prototypes. */
#undef INC_PKCS11F_H
#include "pkcs11f.h"

#undef CK_NEED_ARG_LIST
#undef CK_PKCS11_FUNCTION_INFO


/* ==============================================================
 * Define structed vector of entry points.  A CK_FUNCTION_LIST
 * contains a CK_VERSION indicating a library's Cryptoki version
 * and then a whole slew of function pointers to the routines in
 * the library.  This type was declared, but not defined, in
 * pkcs11t.h.
 * ==============================================================
 */

#define CK_PKCS11_FUNCTION_INFO(name) \
  __PASTE(CK_,name) name;
  
struct CK_FUNCTION_LIST {

  CK_VERSION    version;  /* Cryptoki version */

/* Pile all the function pointers into the CK_FUNCTION_LIST. */
/* pkcs11f.h has all the information about the Cryptoki
 * function prototypes. */
#undef INC_PKCS11F_H
#include "pkcs11f.h"

};

#undef CK_PKCS11_FUNCTION_INFO


#undef __PASTE

#endif

#ifdef __cplusplus
}
#endif

#ifdef _WIN32
# pragma pack(pop,cryptoki)
#else
/* No packing should be used for Unix platforms (as per PKCS#11 standard)
 *
 * Packing causes problems with interoperability with Netscape and 3rd party
 * Java PKCS#11 wrappers.
 */
#endif

#endif /* CRYPTOKI_INCLUDED */

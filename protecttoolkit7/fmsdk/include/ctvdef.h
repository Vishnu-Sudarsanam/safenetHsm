/*
 *  This file is provided as part of the SafeNet Protect Toolkit SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: ctvdef.h
 */

/*
**	Cryptoki vendor defined constants for CRYPTOKI extensions.
**
*/
#include <cryptoki.h>

#ifndef CTVDEF_INCLUDED
#define CTVDEF_INCLUDED

/* vendor defined constants */
#define CK_NO_TRANSPORT_MODE			0x0000
#define CK_SINGLE_TRANSPORT_MODE		0x0001
#define CK_CONTINUOUS_TRANSPORT_MODE	0x0002

#define CK_EVENT_RECORD_LENGTH	48

/* for use with CKH_MONOTONIC_COUNTER */
#define CK_MONOTONIC_COUNTER_SIZE	20

/* vendor defined Flags */

/* slot info flags */
#define CKF_WLD_SLOT				0x10000000

/* token flags */
#define CKF_ADMIN_TOKEN				0x10000000
#define CKF_WLD_TOKEN				0x20000000

/* session info flags */
#define CKF_WLD_SESSION				0x10000000

/* Security Mode flags */
#define CKF_ENTRUST_READY			0x00000001
#define CKF_NO_CLEAR_PINS			0x00000002
#define CKF_AUTH_PROTECTION			0x00000004
#define CKF_NO_PUBLIC_CRYPTO		0x00000008
#define CKF_TAMPER_BEFORE_UPGRADE	0x00000010
#define CKF_INCREASED_SECURITY		0x00000020
#define CKF_FIPS_ALGORITHMS			0x00000040
#define CKF_FULL_SMS_ENC			0x00000080
#define CKF_FULL_SMS_SIGN			0x00000100
#define CKF_PURE_P11                0x00000200
#define CKF_DES_EVEN_PARITY_ALLOWED 0x00000400
#define CKF_USER_ECC_DP_ALLOWED     0x00000800
#define CKF_RESTRICT_KEY_USAGE      0x00001000
#define CKF_WEAK_PKCS11_MECHANISM   0x00010000
#define CKF_PCI_HSM_AUDIT           0x00020000
#define CKF_MODE_LOCKED             0x10000000

/* OTP Feature flag */
#define CKF_USR_OTP_INITIALIZED     0x00002000
#define CKF_SO_OTP_INITIALIZED      0x00004000

/* Mechanism information flags */
#define CKF_TICKET                      (CKF_EXTENSION | 0x40000000)

/* vendor defined Hardware Feature types */

#define CKH_EVENT_LOG                   (CKH_VENDOR_DEFINED + 0x0001)


/* vendor defined object types */

#define CKO_CERTIFICATE_REQUEST         (CKO_VENDOR_DEFINED + 0x0201)
#define CKO_CRL                         (CKO_VENDOR_DEFINED + 0x0202)
#define CKO_ADAPTER                     (CKO_VENDOR_DEFINED + 0x020A)
#define CKO_SLOT                        (CKO_VENDOR_DEFINED + 0x020B)
#define CKO_FM                          (CKO_VENDOR_DEFINED + 0x020C)

/* Entrust translation key type */
#define CKK_RSA_DISCRETE                (CKO_VENDOR_DEFINED + 0x0201)
#define CKK_DSA_DISCRETE                (CKO_VENDOR_DEFINED + 0x0202)

/* Korean SEED algorithm keys */
#define CKK_SEED                        (CKK_VENDOR_DEFINED + 0x0203)
#define CKK_EC_EDWARDS_DEPRECATED       (CKK_VENDOR_DEFINED + 0x0012)

#define CKK_BIP32                       (CKK_VENDOR_DEFINED + 0x0014)

/**
 * Vendor defined CKA_ Attributes.
 */
#define CKA_USAGE_COUNT                 (CKA_VENDOR_DEFINED + 0x0101)
#define CKA_TIME_STAMP                  (CKA_VENDOR_DEFINED + 0x0102)
#define CKA_CHECK_VALUE_DEPRECATED      (CKA_VENDOR_DEFINED + 0x0103)
#define CKA_MECHANISM_LIST              (CKA_VENDOR_DEFINED + 0x0104)

#define CKA_SIGN_LOCAL_CERT             (CKA_VENDOR_DEFINED + 0x0127)
#define CKA_EXPORT                      (CKA_VENDOR_DEFINED + 0x0128)
#define CKA_EXPORTABLE                  (CKA_VENDOR_DEFINED + 0x0129)
#define CKA_DELETABLE                   (CKA_VENDOR_DEFINED + 0x012A)
#define CKA_IMPORT                      (CKA_VENDOR_DEFINED + 0x012B)
#define CKA_KEY_SIZE                    (CKA_VENDOR_DEFINED + 0x012C)

#define CKA_ISSUER_STR                  (CKA_VENDOR_DEFINED + 0x0130)
#define CKA_SUBJECT_STR                 (CKA_VENDOR_DEFINED + 0x0131)
#define CKA_SERIAL_NUMBER_INT           (CKA_VENDOR_DEFINED + 0x0132)

/* CKH_EVENT_LOG attributes */
#define CKA_RECORD_COUNT                (CKA_VENDOR_DEFINED + 0x0136)
#define CKA_RECORD_NUMBER               (CKA_VENDOR_DEFINED + 0x0137)
#define CKA_PURGE                       (CKA_VENDOR_DEFINED + 0x0139)
#define CKA_EVENT_LOG_FULL              (CKA_VENDOR_DEFINED + 0x013A)

/* CKO_ADAPTER attributes */
#define CKA_SECURITY_MODE               (CKA_VENDOR_DEFINED + 0x0140)
#define CKA_TRANSPORT_MODE              (CKA_VENDOR_DEFINED + 0x0141)
#define CKA_BATCH                       (CKA_VENDOR_DEFINED + 0x0142)
#define CKA_HW_STATUS                   (CKA_VENDOR_DEFINED + 0x0143)
#define CKA_FREE_MEM                    (CKA_VENDOR_DEFINED + 0x0144)
#define CKA_TAMPER_CMD                  (CKA_VENDOR_DEFINED + 0x0145)
#define CKA_DATE_OF_MANUFACTURE         (CKA_VENDOR_DEFINED + 0x0146)
#define CKA_HALT_CMD                    (CKA_VENDOR_DEFINED + 0x0147)
#define CKA_APPLICATION_COUNT           (CKA_VENDOR_DEFINED + 0x0148)
#define CKA_FW_VERSION                  (CKA_VENDOR_DEFINED + 0x0149)
#define CKA_RESCAN_PERIPHERALS_CMD      (CKA_VENDOR_DEFINED + 0x014A)
#define CKA_RTC_AAC_ENABLED             (CKA_VENDOR_DEFINED + 0x014B)
#define CKA_RTC_AAC_GUARD_SECONDS       (CKA_VENDOR_DEFINED + 0x014C)
#define CKA_RTC_AAC_GUARD_COUNT         (CKA_VENDOR_DEFINED + 0x014D)
#define CKA_RTC_AAC_GUARD_DURATION      (CKA_VENDOR_DEFINED + 0x014E)
#define CKA_HW_EXT_INFO_STR             (CKA_VENDOR_DEFINED + 0x014F)
#define CKA_PERFORMANCE_LEVEL           (CKA_VENDOR_DEFINED + 0x0150)
#define CKA_SOM_MODE                    (CKA_VENDOR_DEFINED + 0x0160)
#define CKA_SOM_CHALLENGE               (CKA_VENDOR_DEFINED + 0x0161)
#define CKA_SOM_RESPONSE                (CKA_VENDOR_DEFINED + 0x0162)

/* CKO_SLOT attributes */
#define CKA_SLOT_ID                     (CKA_VENDOR_DEFINED + 0x0151)
#define CKA_MAX_SESSIONS                (CKA_VENDOR_DEFINED + 0x0155)
#define CKA_MIN_PIN_LEN                 (CKA_VENDOR_DEFINED + 0x0156)
#define CKA_MAX_PIN_FAIL                (CKA_VENDOR_DEFINED + 0x0158)
#define CKA_FLAGS                       (CKA_VENDOR_DEFINED + 0x0159)
#define CKA_PINPAD_DESC                 (CKA_VENDOR_DEFINED + 0x015A)

/* OS Upgrade key attribute */
#define CKA_VERIFY_OS                   (CKA_VENDOR_DEFINED + 0x0170)

/* FM Upgrade key attribute */
#define CKA_VERSION                     (CKA_VENDOR_DEFINED + 0x0181)
#define CKA_MANUFACTURER                (CKA_VENDOR_DEFINED + 0x0182)
#define CKA_BUILD_DATE                  (CKA_VENDOR_DEFINED + 0x0183)
#define CKA_FINGERPRINT                 (CKA_VENDOR_DEFINED + 0x0184)
#define CKA_ROM_SPACE                   (CKA_VENDOR_DEFINED + 0x0185)
#define CKA_RAM_SPACE                   (CKA_VENDOR_DEFINED + 0x0186)
#define CKA_FM_STATUS                   (CKA_VENDOR_DEFINED + 0x0187)
#define CKA_DELETE_FM                   (CKA_VENDOR_DEFINED + 0x0188)
#define CKA_FM_STARTUP_STATUS           (CKA_VENDOR_DEFINED + 0x0189)
#define CKA_FM_ID                       (CKA_VENDOR_DEFINED + 0x018A)

/* Certificate Start and End time attributes */
#define CKA_CERTIFICATE_START_TIME      (CKA_VENDOR_DEFINED + 0x0190)
#define CKA_CERTIFICATE_END_TIME        (CKA_VENDOR_DEFINED + 0x0191)

/* Key Usage Limiting attributes */
#define CKA_USAGE_LIMIT                 (CKA_VENDOR_DEFINED + 0x0200)
#define CKA_ADMIN_CERT                  (CKA_VENDOR_DEFINED + 0x0201)

#define CKA_PKI_ATTRIBUTE_BER_ENCODED   (CKA_VENDOR_DEFINED + 0x0230)

#define CKA_HIFACE_MASTER               (CKA_VENDOR_DEFINED + 0x0250)

/* Attributes used for DSA Domain Parameter validation */
#define CKA_SEED                        (CKA_VENDOR_DEFINED + 0x0260)
#define CKA_COUNTER                     (CKA_VENDOR_DEFINED + 0x0261)
#define CKA_H_VALUE                     (CKA_VENDOR_DEFINED + 0x0262)

/* Attributes used for internal purposes only */
#define CKA_INTERNAL_1                  (CKA_VENDOR_DEFINED + 0x0270)

/* CKH_VD_USER attributes */
#define CKA_AUTH_CHALLENGE_deprecated   (CKA_VENDOR_DEFINED + 0x0280)
#define CKA_TMP_PIN_deprecated          (CKA_VENDOR_DEFINED + 0x0281)

/* Identity Key support */
#define CKA_LOCAL_IDENTITY_CERT         (CKA_VENDOR_DEFINED + 0x0290)
#define CKA_HSM_OWNER_CERT              (CKA_VENDOR_DEFINED + 0x0291)
#define CKA_HSM_ROOT_CERT               (CKA_VENDOR_DEFINED + 0x0292)

/* TR31 */
#define CKA_TR31_INFO                   (CKA_VENDOR_DEFINED + 0x2A0)

/* BIP32 Additional attributes*/
#define CKA_BIP32_CHAIN_CODE            (CKA_VENDOR_DEFINED + 0x1100)
#define CKA_BIP32_VERSION_BYTES         (CKA_VENDOR_DEFINED + 0x1101)
#define CKA_BIP32_CHILD_INDEX           (CKA_VENDOR_DEFINED + 0x1102)
#define CKA_BIP32_CHILD_DEPTH           (CKA_VENDOR_DEFINED + 0x1103)
#define CKA_BIP32_ID                    (CKA_VENDOR_DEFINED + 0x1104)
#define CKA_BIP32_FINGERPRINT           (CKA_VENDOR_DEFINED + 0x1105)
#define CKA_BIP32_PARENT_FINGERPRINT    (CKA_VENDOR_DEFINED + 0x1106)

#define CKG_BIP32_VERSION_MAINNET_PUB   (0x0488B21E)
#define CKG_BIP32_VERSION_MAINNET_PRIV  (0x0488ADE4)
#define CKG_BIP32_VERSION_TESTNET_PUB   (0x043587CF)
#define CKG_BIP32_VERSION_TESTNET_PRIV  (0x04358394)
#define CKG_BIP44_PURPOSE               (0x0000002C)
#define CKG_BIP44_COIN_TYPE_BTC         (0x00000000)
#define CKG_BIP44_COIN_TYPE_BTC_TESTNET (0x00000001)
#define CKG_BIP32_EXTERNAL_CHAIN        (0x00000000)
#define CKG_BIP32_INTERNAL_CHAIN        (0x00000001)
#define CKG_BIP32_MAX_SERIALIZED_LEN    (113)
#define CKF_BIP32_HARDENED              (0x80000000)

#define CKA_AUDIT_KEY                   (CKA_VENDOR_DEFINED + 0x2000)
/* end of additional attributes */

/* backwards compat with (CK_ATTRIBUTE_TYPE)-1 (V1) */
#define CKA_ENUM_ATTRIBUTE		((CK_ATTRIBUTE_TYPE)0xFFFF)

/* Mask generation function for CKA_HW_STATUS (32 bit int) */
#define CKG_BATTERY_LOW		0x00000001
#define CKG_PCB_VERSION		0x0000000E
#define CKG_EXTERNAL_PINS	0x000000F0
#define CKG_FPGA_VERSION	0x00000F00
#define CKG_TEMP        	0x000FF000

/**
 * Vendor defined CKM_ Mechanisms.
 */
/* additional methods */
#define CKM_DSA_SHA1_PKCS          (CKM_VENDOR_DEFINED + CKM_DSA_SHA1 + 0x1)
#define CKM_DSA_SHA224_DEPRECATED  (CKM_VENDOR_DEFINED + CKM_DSA_SHA1 + 0x20)
#define CKM_DSA_SHA224_PKCS        (CKM_VENDOR_DEFINED + CKM_DSA_SHA1 + 0x21)
#define CKM_DSA_SHA256_DEPRECATED  (CKM_VENDOR_DEFINED + CKM_DSA_SHA1 + 0x22)
#define CKM_DSA_SHA256_PKCS        (CKM_VENDOR_DEFINED + CKM_DSA_SHA1 + 0x23)
#define CKM_DSA_SHA384_PKCS        (CKM_VENDOR_DEFINED + CKM_DSA_SHA1 + 0x24)
#define CKM_DSA_SHA512_PKCS        (CKM_VENDOR_DEFINED + CKM_DSA_SHA1 + 0x25)

#define CKM_RIPEMD256_RSA_PKCS     (CKM_VENDOR_DEFINED + CKM_RIPEMD160_RSA_PKCS + 0x1)
#define CKM_DES_MDC_2_PAD1         (CKM_VENDOR_DEFINED + 0x200 + 0x0)
#define CKM_MD4                    (CKM_VENDOR_DEFINED + 0x200 + 0x1)
#define CKM_SHA                    (CKM_VENDOR_DEFINED + 0x200 + 0x2)
#define CKM_RIPEMD                 (CKM_VENDOR_DEFINED + 0x200 + 0x3)
#define CKM_ARDFP                  (CKM_VENDOR_DEFINED + 0x200 + 0x4)
#define CKM_NVB                    (CKM_VENDOR_DEFINED + 0x200 + 0x5)

/* more additional methods */
#define CKM_DES_ECB_PAD            (CKM_VENDOR_DEFINED + CKM_DES_ECB)
#define CKM_CAST_ECB_PAD           (CKM_VENDOR_DEFINED + CKM_CAST_ECB)
#define CKM_CAST3_ECB_PAD          (CKM_VENDOR_DEFINED + CKM_CAST3_ECB)
#define CKM_CAST5_ECB_PAD          (CKM_VENDOR_DEFINED + CKM_CAST5_ECB)
#define CKM_CAST128_ECB_PAD        CKM_CAST5_ECB_PAD
#define CKM_DES3_ECB_PAD           (CKM_VENDOR_DEFINED + CKM_DES3_ECB)
#define CKM_IDEA_ECB_PAD           (CKM_VENDOR_DEFINED + CKM_IDEA_ECB)
#define CKM_RC2_ECB_PAD            (CKM_VENDOR_DEFINED + CKM_RC2_ECB)
#define CKM_CDMF_ECB_PAD           (CKM_VENDOR_DEFINED + CKM_CDMF_ECB)
#define CKM_RC5_ECB_PAD            (CKM_VENDOR_DEFINED + CKM_RC5_ECB)

#define CKM_XOR_BASE_AND_KEY    (CKM_VENDOR_DEFINED + 0x364)

#define CKM_RSA_FIPS_186_3_PRIME_KEY_PAIR_GEN         (CKM_VENDOR_DEFINED + 0x143)

/* FIPS 186-4 RSA Key gen mechanism and x9.31 Signature generation mechanisms */
#define CKM_RSA_FIPS_186_4_PRIME_KEY_PAIR_GEN  (CKM_VENDOR_DEFINED + 0x400)

/* TR31 */
#define CKM_UNWRAP_TR31_DISCARD    (CKM_VENDOR_DEFINED + 0x410)
#define CKM_UNWRAP_TR31            (CKM_VENDOR_DEFINED + 0x411)
#define CKM_WRAP_TR31_DERIVE       (CKM_VENDOR_DEFINED + 0x412)
#define CKM_WRAP_TR31_VARIANT      (CKM_VENDOR_DEFINED + 0x413)
#define CKM_WRAP_TR31_DERIVE_CTR   (CKM_VENDOR_DEFINED + 0x414)


/* DES and Triple DES key derive mechanisms */
/* These constants are deprecated. New code should use the 
 * new standard CKM_DES[3]_[ECB|CBC]_ENCRYPT_DATA definitions
 */
#define CKM_DES_DERIVE_ECB         (CKM_VENDOR_DEFINED + 0x500)
#define CKM_DES_DERIVE_CBC         (CKM_VENDOR_DEFINED + 0x501)
#define CKM_DES3_DERIVE_ECB        (CKM_VENDOR_DEFINED + 0x502)
#define CKM_DES3_DERIVE_CBC        (CKM_VENDOR_DEFINED + 0x503)
/* end DES and Triple DES key derive mechanisms */

/* Retail CFB MAC specifies left key for main data
 * with triple des on final data block
 */
#define CKM_DES3_RETAIL_CFB_MAC    (CKM_VENDOR_DEFINED + 0x510)

/* 
* Mechanisms impemented for supporting MILENAGE functions as per
* http://www.3gpp.org/specifications/60-confidentiality-algorithms 
*/
#define CKM_MILENAGE_DERIVE		   (CKM_VENDOR_DEFINED + 0x511)
#define CKM_MILENAGE_SIGN		   (CKM_VENDOR_DEFINED + 0x512)

/*
* Mechanisms impemented for supporting TUAK functions as per
* 3GPP spec TS 35.231
*/
#define CKM_TUAK_SIGN		   (CKM_VENDOR_DEFINED + 0x513)
#define CKM_TUAK_DERIVE	           (CKM_VENDOR_DEFINED + 0x514)
#define CKM_KECCAK_1600		   (CKM_VENDOR_DEFINED + 0x515)

/* Timestamp mechanisms */
#define CKM_SHA1_RSA_PKCS_TIMESTAMP (CKM_VENDOR_DEFINED + 0x600)
/* End Timestamp mechanisms */

#define CKM_DES_BCF                (CKM_VENDOR_DEFINED + 0x38e)
#define CKM_DES3_BCF               (CKM_VENDOR_DEFINED + 0x38f)

/* X.9.19 specifies left key for main data with triple des on final IV */
#define CKM_DES3_X919_MAC          (CKM_VENDOR_DEFINED + CKM_DES3_MAC)
#define CKM_DES3_X919_MAC_GENERAL  (CKM_VENDOR_DEFINED + CKM_DES3_MAC_GENERAL)

/* PKCS7 mechanism definitions */
#define CKM_ENCODE_PKCS_7          (CKM_VENDOR_DEFINED + 0x934)
#define CKM_DECODE_PKCS_7          (CKM_VENDOR_DEFINED + 0x935)

#define CKM_RSA_PKCS_7             (CKM_VENDOR_DEFINED + 0x930)
#define CKM_RSA_PKCS_7_ENC         (CKM_VENDOR_DEFINED + 0x931)
#define CKM_RSA_PKCS_7_SIGN        (CKM_VENDOR_DEFINED + 0x932)
#define CKM_RSA_PKCS_7_SIGN_ENC    (CKM_VENDOR_DEFINED + 0x933)
/* end PKCS7 definitions */

#define CKM_DES_OFB64              (CKM_VENDOR_DEFINED + 0x940)
#define CKM_DES3_OFB64             (CKM_VENDOR_DEFINED + 0x941)

#define CKM_ENCODE_ATTRIBUTES   (CKM_VENDOR_DEFINED + 0x950)
#define CKM_ENCODE_X_509        (CKM_VENDOR_DEFINED + 0x951)
#define CKM_ENCODE_PKCS_10      (CKM_VENDOR_DEFINED + 0x952)
#define CKM_DECODE_X_509        (CKM_VENDOR_DEFINED + 0x953)
#define CKM_ENCODE_PUBLIC_KEY   (CKM_VENDOR_DEFINED + 0x954)
#define CKM_ENCODE_X_509_LOCAL_CERT (CKM_VENDOR_DEFINED + 0x955)
#define CKM_WRAPKEY_DES3_ECB    (CKM_VENDOR_DEFINED + 0x961)
#define CKM_WRAPKEY_DES3_CBC    (CKM_VENDOR_DEFINED + 0x962)
#define CKM_WRAPKEY_AES_CBC     (CKM_VENDOR_DEFINED + 0x963)

#define CKM_DES3_DDD_CBC		(CKM_VENDOR_DEFINED + 0x964)

#define CKM_AES_GCM_OLD         (CKM_VENDOR_DEFINED + 0x966)

#define CKM_WRAPKEYBLOB_AES_CBC (CKM_VENDOR_DEFINED + 0x970)
#define CKM_WRAPKEYBLOB_DES3_CBC (CKM_VENDOR_DEFINED + 0x971)
/*
 * NIST 800-38F related:
 */
#define CKM_WRAPKEY_AES_KWP		(CKM_VENDOR_DEFINED + 0x965)/* Used to break unlimited loop in key backup procedure */
#define CKM_AES_KW              (CKM_VENDOR_DEFINED + 0x170)
#define CKM_AES_KWP             (CKM_VENDOR_DEFINED + 0x171)
#define CKM_TDEA_TKW            (CKM_VENDOR_DEFINED + 0x172)

/* */
#define CKM_VERIFY_CERTIFICATE  (CKM_VENDOR_DEFINED + 0x980)

/* entrust */
#define CKM_KEY_TRANSLATION     (CK_VENDOR_DEFINED + 0x1B)

/* FW Upgrading mechanism. Used in C_VerifyInit/C_VerifyUpdate/C_VerifyFinal
   functions. */
#define CKM_OS_UPGRADE			(CKM_VENDOR_DEFINED + 0x990)
#define CKM_FM_DOWNLOAD			(CKM_VENDOR_DEFINED + 0x991)

#define CKM_OS_UPGRADE_2		(CKM_VENDOR_DEFINED + 0x994)
#define CKM_FM_DOWNLOAD_2		(CKM_VENDOR_DEFINED + 0x995)

#define CKM_FW_UPGRADE			(CKM_VENDOR_DEFINED + 0x996)

/*PIK Generation mechanism. Used by C_GenerateKeyPair*/
#define CKM_GEN_PIK_ECC_P521    (CKM_VENDOR_DEFINED + 0x1000)

#define CKM_GEN_KTK_ECC_P521    (CKM_VENDOR_DEFINED + 0x1001)

#define CKM_GEN_KDE_ECC_P521_DERIVE_SEND    (CKM_VENDOR_DEFINED + 0x1002)
#define CKM_GEN_KDE_ECC_P521_DERIVE_RECV    (CKM_VENDOR_DEFINED + 0x1003)

#define CKM_TOKEN_WRAP_KTK_ECC_P521    (CKM_VENDOR_DEFINED + 0x1004)

#define CKM_PP_LOAD_SECRET		(CKM_VENDOR_DEFINED + 0x9a0)
#define CKM_PP_LOAD_SECRET_2	(CKM_VENDOR_DEFINED + 0x9a1)

/** Verified by Visa CVV calculation mechanism. Only valid for C_SignInit() and
 * C_VerifyInit() operations. */
#define CKM_VISA_CVV			(CKM_VENDOR_DEFINED + 0x9b0)

/* ZKA MDC-2 key derive mechanisms */
#define CKM_ZKA_MDC_2_KEY_DERIVATION (CKM_VENDOR_DEFINED + 0x9c0)

/* Korean SEED algorithm. */
#define CKM_SEED_KEY_GEN        (CKM_VENDOR_DEFINED + 0x9d0)
#define CKM_SEED_ECB            (CKM_VENDOR_DEFINED + 0x9d1)
#define CKM_SEED_CBC            (CKM_VENDOR_DEFINED + 0x9d2)
#define CKM_SEED_MAC            (CKM_VENDOR_DEFINED + 0x9d3)
#define CKM_SEED_MAC_GENERAL    (CKM_VENDOR_DEFINED + 0x9d4)
#define CKM_SEED_ECB_PAD        (CKM_VENDOR_DEFINED + 0x9d5)
#define CKM_SEED_CBC_PAD        (CKM_VENDOR_DEFINED + 0x9d6)

/* Token replication mechanisms */
#define CKM_REPLICATE_TOKEN_RSA_AES	(CKM_VENDOR_DEFINED + 0x9e0)

/** N of M secret share mechanism */
#define CKM_SECRET_SHARE_WITH_ATTRIBUTES    (CKM_VENDOR_DEFINED + 0x9f0)

/** N of M secret recovery mechanism */
#define CKM_SECRET_RECOVER_WITH_ATTRIBUTES  (CKM_VENDOR_DEFINED + 0x9f1)

/** PBE based PKCS#12 Export mechanism */
#define CKM_PKCS12_PBE_EXPORT               (CKM_VENDOR_DEFINED + 0x9f2)

/** PBE based PKCS#12 Import mechanism */
#define CKM_PKCS12_PBE_IMPORT               (CKM_VENDOR_DEFINED + 0x9f3)

/** EC IES mechanism (X9.63) */
#define CKM_ECIES               (CKM_VENDOR_DEFINED + 0xA00)
#define CKM_NIST_PRF_KDF        (CKM_VENDOR_DEFINED + 0xA02)
#define CKM_PRF_KDF             (CKM_VENDOR_DEFINED + 0xA03)

/** Ticket Mechanisms */
#define CKM_SET_ATTRIBUTES               (CKM_VENDOR_DEFINED + 0xA10)

/* New mechanisms ( #88843) */
#define CKM_ECDSA_SHA224                       (CKM_VENDOR_DEFINED + 0x122)
#define CKM_ECDSA_SHA256                       (CKM_VENDOR_DEFINED + 0x123)
#define CKM_ECDSA_SHA384                       (CKM_VENDOR_DEFINED + 0x124)
#define CKM_ECDSA_SHA512                       (CKM_VENDOR_DEFINED + 0x125)

#define CKM_BIP32_MASTER_DERIVE                (CKM_VENDOR_DEFINED + 0xE00)
#define CKM_BIP32_CHILD_DERIVE                 (CKM_VENDOR_DEFINED + 0xE01)

#define CKM_ECDSA_GBCS_SHA256                  (CKM_VENDOR_DEFINED + 0x161)

#define CKM_EC_EDWARDS_KEY_PAIR_GEN_DEPRECATED (CKM_VENDOR_DEFINED + 0x0C01)
#define CKM_EDDSA_DEPRECATED                   (CKM_VENDOR_DEFINED + 0x0C03) // ed25519 sign/verify
#define CKM_SHA1_EDDSA                         (CKM_VENDOR_DEFINED + 0x0C09)
#define CKM_SHA224_EDDSA                       (CKM_VENDOR_DEFINED + 0x0C0A)
#define CKM_SHA256_EDDSA                       (CKM_VENDOR_DEFINED + 0x0C0B)
#define CKM_SHA384_EDDSA                       (CKM_VENDOR_DEFINED + 0x0C0C)
#define CKM_SHA512_EDDSA                       (CKM_VENDOR_DEFINED + 0x0C0D)
#define CKM_SHA3_224_EDDSA                     (CKM_VENDOR_DEFINED + 0x1C0A)
#define CKM_SHA3_256_EDDSA                     (CKM_VENDOR_DEFINED + 0x1C0B)
#define CKM_SHA3_384_EDDSA                     (CKM_VENDOR_DEFINED + 0x1C0C)
#define CKM_SHA3_512_EDDSA                     (CKM_VENDOR_DEFINED + 0x1C0D)

#define CKA_DES_USAGE_COUNT                    (CKM_VENDOR_DEFINED + 0x4000)

/* dummy Mechanism */
#define CKM_UNUSED			(-1L)
/**
 * Mechanism used for FIPS evaluation to shortcut direct to key gen and
 * RNG functions with extra parameters. This mechanism MUST NOT be 
 * available in production builds.
 */
#ifdef FIPS_EVALUATION
#	define CKM_FIPS_EVAL_REQUEST   CKR_VENDOR_DEFINED+0x10000+0x00001
#endif

/**
 * Mechanism parameters for CKM_DES_DERIVE_ECB, CKM_DES_DERIVE_CBC,
 * CKM_DES3_DERIVE_ECB, CKM_DES3_DERIVE_CBC
 * CKM_DES_ECB_ENCRYPT_DATA, CKM_DES_CBC_ENCRYPT_DATA
 * CKM_DES3_ECB_ENCRYPT_DATA, CKM_DES3_CBC_ENCRYPT_DATA
 */
typedef struct CK_DES_CBC_PARAMS {
  CK_BYTE		iv[8];		/* CBC IV */
  CK_BYTE		data[8];	/* Data to be encrypted */
} CK_DES_CBC_PARAMS;
typedef CK_DES_CBC_PARAMS * CK_DES_CBC_PARAMS_PTR;

typedef struct CK_DES2_CBC_PARAMS {
  CK_BYTE		iv[8];		/* CBC IV */
  CK_BYTE		data[16];	/* Data to be encrypted */
} CK_DES2_CBC_PARAMS;
typedef CK_DES2_CBC_PARAMS * CK_DES2_CBC_PARAMS_PTR;

typedef struct CK_DES3_CBC_PARAMS {
  CK_BYTE		iv[8];		/* CBC IV */
  CK_BYTE		data[24];	/* Data to be encrypted */
} CK_DES3_CBC_PARAMS;
typedef CK_DES3_CBC_PARAMS * CK_DES3_CBC_PARAMS_PTR;

/**
 * Mechanism parameters for CKM_SHA1_RSA_PKCS_TIMESTAMP.
 */
typedef CK_ULONG CK_TIMESTAMP_FORMAT;

/* CK_TIMESTAMP_FORMAT values */
#define CK_TIMESTAMP_FORMAT_ERACOM 0x00000001
#define CK_TIMESTAMP_FORMAT_PTKC   0x00000001

typedef struct CK_TIMESTAMP_PARAMS {
  /* use millisecond granularity in timestamp */
  CK_BBOOL              useMilliseconds;
  /* output data format */
  CK_TIMESTAMP_FORMAT   timestampFormat;
} CK_TIMESTAMP_PARAMS;
typedef CK_TIMESTAMP_PARAMS * CK_TIMESTAMP_PARAMS_PTR;

/**
 * Mechanism parameters for PKCS7 mechanisms.
 */
#define CKF_PKCS_7_INCLUDE_CERTS_AND_CRLS	0x01

/* object attribute list managed as an array (Note: matches TOK_ATTR_DATA) */
struct CK_ATTRIBUTES {
	CK_ATTRIBUTE * attributes;  /* an array of attribute items */
	CK_COUNT count;				/* number of items in 'attributes' */
};
typedef struct CK_ATTRIBUTES CK_ATTRIBUTES;

struct CK_MECH_AND_OBJECT {
	CK_MECHANISM  mechanism;		/* signature mechanism specification */
	CK_OBJECT_HANDLE obj;
};
typedef struct CK_MECH_AND_OBJECT CK_MECH_AND_OBJECT;

struct CK_MECH_TYPE_AND_OBJECT {
	CK_MECHANISM_TYPE  mechanism;		/* signature mechanism type */
	CK_OBJECT_HANDLE obj;
};
typedef struct CK_MECH_TYPE_AND_OBJECT CK_MECH_TYPE_AND_OBJECT;

struct CK_MECH_AND_OBJECTS {
	CK_MECH_AND_OBJECT * mechanism;
	CK_COUNT count;
};
typedef struct CK_MECH_AND_OBJECTS CK_MECH_AND_OBJECTS;

typedef struct CK_PKCS_7_PARAMS {
  CK_ULONG		flags;		/* mechanism control flags */
  CK_ULONG      length;		/* content length (may be indefinite) */
  CK_MECH_AND_OBJECTS  signature;	/* signature mechanism specification */
  CK_MECH_AND_OBJECTS  encryption;	/* encryption mechanism specification */
  CK_ATTRIBUTES	extensions;
} CK_PKCS_7_PARAMS;

typedef CK_PKCS_7_PARAMS * CK_PKCS_7_PARAMS_PTR;

/**
 * The mechanism parameters for CKM_PP_LOAD_SECRET.
 */
/**
 * Specifies the type of conversion to be applied to the data input from the
 * pinpad.
 */
typedef CK_CHAR CK_PP_CONVERT_TYPE;

/** No conversion in pin pad input. */
#define	CK_PP_CT_NONE (CK_PP_CONVERT_TYPE)0

/** Conversion from octal to binary in pin pad input. */
#define CK_PP_CT_OCTAL (CK_PP_CONVERT_TYPE)8

/** Conversion from decimal to binary in pin pad input. */
#define CK_PP_CT_DECIMAL (CK_PP_CONVERT_TYPE)10

/** Conversion from hexadecimal to binary in pin pad input. */
#define CK_PP_CT_HEX (CK_PP_CONVERT_TYPE)16

typedef struct CK_PP_LOAD_SECRET_PARAMS CK_PP_LOAD_SECRET_PARAMS;
typedef struct CK_PP_LOAD_SECRET_PARAMS_2 CK_PP_LOAD_SECRET_PARAMS_2;

struct CK_PP_LOAD_SECRET_PARAMS
{
	/** Entered characters should be masked with '*' or similar to hide the
	 * value being entered. There will be an error returned if this is TRUE
	 * and the device does not support this feature. */
	CK_BBOOL bMaskInput;

	/** Entered characters should be converted from the ASCII representation
	 * to binary before being stored, according to the conversion type
	 * supplied. If the device does not support the specified type of input
	 * (e.g. hex input on a decimal keyboard), an error will be returned.
	 * The octal and decimal representations will expect 3 digits per byte,
	 * whereas the hexadecimal representations will expect 2 digits per byte.
	 * An error will be returned if the data contains invalid encoding (such
	 * as 351 for decimal conversion).
	 */
	CK_PP_CONVERT_TYPE cConvert;

	/** The time to wait for operator response - in seconds. An error is
	 * returned if the operation does not complete in the specified time.
	 * This field may be ignored if the device does not support a confgiurable
	 * timeout. */
	CK_CHAR cTimeout;

	/** Reserved for future extensions. Must be set to zero. */
	CK_CHAR reserved;

	/** The prompt to be displayed on the device. If the prompt cannot fit on
	 * the device display, the output will be clipped. If the device does not
	 * have any display, the operation will continue without any prompt, or
	 * error.
	 *
	 * The following special characters are recognized on the display:
	 * - Newline (0x0a): Continue the display on the next line.
	 */
	CK_CHAR_PTR prompt;
};

struct CK_PP_LOAD_SECRET_PARAMS_2
{
	/** Entered characters should be masked with '*' or similar to hide the
	 * value being entered. There will be an error returned if this is TRUE
	 * and the device does not support this feature. */
	CK_BBOOL bMaskInput;

	/** Entered characters should be converted from the ASCII representation
	 * to binary before being stored, according to the conversion type
	 * supplied. If the device does not support the specified type of input
	 * (e.g. hex input on a decimal keyboard), an error will be returned.
	 * The octal and decimal representations will expect 3 digits per byte,
	 * whereas the hexadecimal representations will expect 2 digits per byte.
	 * An error will be returned if the data contains invalid encoding (such
	 * as 351 for decimal conversion).
	 */
	CK_PP_CONVERT_TYPE cConvert;

	/** The time to wait for operator response - in seconds. An error is
	 * returned if the operation does not complete in the specified time.
	 * This field may be ignored if the device does not support a confgiurable
	 * timeout. */
	CK_CHAR cTimeout;

	/** Reserved for future extensions. Must be set to zero. */
	CK_CHAR reserved;

	/** The prompt to be displayed on the device. If the prompt cannot fit on
	 * the device display, the output will be clipped. If the device does not
	 * have any display, the operation will continue without any prompt, or
	 * error.
	 *
	 * The following special characters are recognized on the display:
	 * - Newline (0x0a): Continue the display on the next line.
	 */
	CK_CHAR_PTR prompt;

    /** Optional - Object handle to XOR with, the resulting object will inherit of
     * important attributes from this handle
     */
	CK_OBJECT_HANDLE xorWith;
};

/**
 * The mechanism parameters for CKM_REPLICATE_TOKEN_RSA_AES.
 */
typedef struct CK_REPLICATE_TOKEN_PARAMS 
{
    CK_CHAR           peerId[CK_SERIAL_NUMBER_SIZE];	/* the peer id */
} CK_REPLICATE_TOKEN_PARAMS;

typedef CK_REPLICATE_TOKEN_PARAMS * CK_REPLICATE_TOKEN_PARAMS_PTR;

/**
 * Mechanism parameter for the CKM_SECRET_SHARE_WITH_ATTRIBUTES.
 */
typedef struct CK_SECRET_SHARE_PARAMS
{
    /** Number of shares required to recover the secret. Must be at least 2 and
     * and not greater than the number of shares (m). */
    CK_ULONG n;

    /** Total mumber of shares. Must be at least 2 and not greater than 64. */
    CK_ULONG m;

} CK_SECRET_SHARE_PARAMS;

typedef CK_SECRET_SHARE_PARAMS * CK_SECRET_SHARE_PARAMS_PTR;

/**
 * Mechanism parameter for CKM_PKCS12_PBE_EXPORT.
 */
typedef struct CK_PKCS12_PBE_EXPORT_PARAMS
{
    /** Handle to certificate associated to the private key */
    CK_OBJECT_HANDLE     keyCert;
    
    /** AuthenticatedSafe password */
    CK_CHAR_PTR       passwordAuthSafe;
    
    /** Size of AuthenticatedSafe password */
    CK_SIZE           passwordAuthSafeLen;
    
    /** HMAC password */
    CK_CHAR_PTR       passwordHMAC;
    
    /** Size of HMAC password */
    CK_SIZE           passwordHMACLen;
    
    /** Encryption mechanism for SafeBag 
     *  Supported mechanisms:
     *     - CKM_PBE_SHA1_RC4_128       
     *     - CKM_PBE_SHA1_RC4_40        
     *     - CKM_PBE_SHA1_DES3_EDE_CBC  
     *     - CKM_PBE_SHA1_DES2_EDE_CBC  
     *     - CKM_PBE_SHA1_RC2_128_CBC   
     *     - CKM_PBE_SHA1_RC2_40_CBC   
     */
    CK_MECHANISM_TYPE safeBagKgMech;
    
    /** Encryption mechanism for SafeContent
     *  Supported mechanisms:
     *     - CKM_PBE_SHA1_RC4_128       
     *     - CKM_PBE_SHA1_RC4_40        
     *     - CKM_PBE_SHA1_DES3_EDE_CBC  
     *     - CKM_PBE_SHA1_DES2_EDE_CBC  
     *     - CKM_PBE_SHA1_RC2_128_CBC   
     *     - CKM_PBE_SHA1_RC2_40_CBC   
     */
    CK_MECHANISM_TYPE safeContentKgMech;
    
    /** HMAC mechanism for PFX 
     *  Supported mechanism:
     *     - CKM_PBA_SHA1_WITH_SHA1_HMAC        
     */    
    CK_MECHANISM_TYPE hmacKgMech;
    
}CK_PKCS12_PBE_EXPORT_PARAMS;

typedef CK_PKCS12_PBE_EXPORT_PARAMS * CK_PKCS12_PBE_EXPORT_PARAMS_PTR;

/**
 * Mechanism parameter for CKM_PKCS12_PBE_IMPORT.
 */
typedef struct CK_PKCS12_PBE_IMPORT_PARAMS
{
    /** AuthenticatedSafe password */
    CK_CHAR_PTR           passwordAuthSafe;
    
    /** Size of AuthenticatedSafe password */
    CK_SIZE               passwordAuthSafeLen;
    
    /** HMAC password */
    CK_CHAR_PTR           passwordHMAC;
    
    /** Size of HMAC password */
    CK_SIZE               passwordHMACLen;
    
    /** Certificate attributes */
    CK_ATTRIBUTE_PTR      certAttr;
    
    /** Number of certificate attributes */
    CK_COUNT              certAttrCount;
    
    /** Handle to returned certificate(s) */
    CK_OBJECT_HANDLE_PTR  hCert;
    
    /** Number allocated certificate handle(s) */
    CK_COUNT_PTR          hCertCount;
    
}CK_PKCS12_PBE_IMPORT_PARAMS;

typedef CK_PKCS12_PBE_IMPORT_PARAMS * CK_PKCS12_PBE_IMPORT_PARAMS_PTR;

/**
 * Mechanism parameters for CKM_ECIES.
 */
/** EC Diffie-Hellman (DH) primitive to use for shared secret derivation */
typedef CK_ULONG CK_EC_DH_PRIMITIVE;

/** EC DH primitives */
#define CKDHP_STANDARD	0x00000001 	  
#define CKDHP_MODIFIED	0x00000002 /* Not implemented */

/** Inner encryption scheme to use for ECIES */
typedef CK_ULONG CK_EC_ENC_SCHEME;

/** Inner encryption schemes */
#define CKES_XOR			0x00000001 	  
#define CKES_DES3_CBC_PAD	0x00000002 /* Not implemented */

/** Message Authentication Code (MAC) scheme to use for ECIES */
typedef CK_ULONG CK_EC_MAC_SCHEME;

/** MAC schemes */
#define CKMS_HMAC_SHA1	0x00000001
#define CKMS_SHA1		0x00000002

/** Mechanism parameter structure for ECIES */
typedef struct CK_ECIES_PARAMS
{
	/** Diffie-Hellman primitive used to derive the shared secret value */
    CK_EC_DH_PRIMITIVE dhPrimitive;

	/**	key derivation function used on the shared secret value */
    CK_EC_KDF_TYPE kdf;

	/** the length in bytes of the key derivation shared data */
    CK_ULONG ulSharedDataLen1;

	/** the key derivation padding data shared between the two parties */
    CK_BYTE_PTR pSharedData1;

	/** the encryption scheme used to transform the input data */
    CK_EC_ENC_SCHEME encScheme;

	/** the bit length of the key to use for the encryption scheme */
    CK_ULONG ulEncKeyLenInBits;

	/** the MAC scheme used for MAC generation or validation */
    CK_EC_MAC_SCHEME macScheme;

	/** the bit length of the key to use for the MAC scheme */
    CK_ULONG ulMacKeyLenInBits;

	/** the bit length of the MAC scheme output */
    CK_ULONG ulMacLenInBits;

	/** the length in bytes of the MAC shared data */
    CK_ULONG ulSharedDataLen2;

	/** the MAC padding data shared between the two parties */
    CK_BYTE_PTR pSharedData2;
} CK_ECIES_PARAMS;

typedef CK_ECIES_PARAMS * CK_ECIES_PARAMS_PTR;

typedef CK_ULONG CK_KDF_PRF_TYPE;
typedef CK_ULONG CK_KDF_PRF_ENCODING_SCHEME;

/** PRF KDF schemes */
#define CK_NIST_PRF_KDF_DES3_CMAC      0x00000001
#define CK_NIST_PRF_KDF_AES_CMAC       0x00000002
#define CK_PRF_KDF_ARIA_CMAC           0x00000003
#define CK_PRF_KDF_SEED_CMAC           0x00000004

#define LUNA_PRF_KDF_ENCODING_SCHEME_1     0x00000000
#define LUNA_PRF_KDF_ENCODING_SCHEME_2     0x00000001

typedef struct CK_KDF_PRF_PARAMS {
   CK_KDF_PRF_TYPE            prfType;
   CK_BYTE_PTR                pLabel;
   CK_ULONG                   ulLabelLen;
   CK_BYTE_PTR                pContext;
   CK_ULONG                   ulContextLen;
   CK_ULONG                   ulCounter;
   CK_KDF_PRF_ENCODING_SCHEME ulEncodingScheme;
} CK_PRF_KDF_PARAMS;
typedef CK_PRF_KDF_PARAMS * CK_KDF_PRF_PARAMS_PTR;

/* CKM_BIP32_MASTER_DERIVE params
    TODO: Decide on the correct name of the fields*/
typedef struct CK_BIP32_MASTER_DERIVE_PARAMS {
    CK_ATTRIBUTE_PTR pPublicKeyTemplate;
    CK_ULONG ulPublicKeyAttributeCount;
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate;
    CK_ULONG ulPrivateKeyAttributeCount;
    CK_OBJECT_HANDLE hPublicKey; // output parameter
    CK_OBJECT_HANDLE hPrivateKey; // output parameter
} CK_BIP32_MASTER_DERIVE_PARAMS;

typedef struct CK_BIP32_MASTER_DERIVE_PARAMS * CK_BIP32_MASTER_DERIVE_PARAMS_PTR;

/* CKM_BIP32_CHILD_DERIVE params
    TODO: Decide on the correct name of the fields*/
typedef struct CK_BIP32_CHILD_DERIVE_PARAMS {
    CK_ATTRIBUTE_PTR pPublicKeyTemplate;
    CK_ULONG ulPublicKeyAttributeCount;
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate;
    CK_ULONG ulPrivateKeyAttributeCount;
    CK_ULONG_PTR pulPath;
    CK_ULONG ulPathLen;
    CK_OBJECT_HANDLE hPublicKey; // output parameter
    CK_OBJECT_HANDLE hPrivateKey; // output parameter
    CK_ULONG ulPathErrorIndex; // output parameter
} CK_BIP32_CHILD_DERIVE_PARAMS;

typedef struct CK_BIP32_CHILD_DERIVE_PARAMS * CK_BIP32_CHILD_DERIVE_PARAMS_PTR;

/* 
* Mechanisms parameter for supporting MILENAGE functions (CKM_MILENAGE_DERIVE and CKM_MILENAGE_SIGN) as per
* http://www.3gpp.org/specifications/60-confidentiality-algorithms 
*/
typedef struct CK_MILENAGE_DERIVE_PARAMS
{
	CK_ULONG f;					/* Function Code - 30(f3), 40(f4), 50(f5), 51(f5*) */
	CK_OBJECT_HANDLE hObject;	/* Handle to OP stored as Generic Secret Key */
	CK_BYTE random[16];			/* 16-byte of random Number. */
}CK_MILENAGE_DERIVE_PARAMS;
typedef struct CK_MILENAGE_DERIVE_PARAMS * CK_MILENAGE_DERIVE_PARAMS_PTR;

typedef struct CK_MILENAGE_SIGN_PARAMS
{
	CK_ULONG f;					/* Function Code - 10 (f1), 11(f1*), 20(f2) */
	CK_OBJECT_HANDLE hObject;	/* Handle to OP stored as Generic Secret Key */
	CK_BYTE sqn[6];				/* SQN 6-byte of Sequence Number. */
	CK_BYTE amf[2]; 			/* AMF 2-byte of Authentication Management Field. */
}CK_MILENAGE_SIGN_PARAMS;
typedef struct CK_MILENAGE_SIGN_PARAMS * CK_MILENAGE_SIGN_PARAMS_PTR;

typedef struct CK_GEN_PIK_PARAM {
    CK_BBOOL	bSelfSign;
} CK_GEN_PIK_PARAM;

typedef CK_GEN_PIK_PARAM * CK_GEN_PIK_PARAM_PTR;

#define CK_KDE_MACTAG_LEN (512 / 8)

typedef struct CK_KDE_ECCP521_DERIVE_PARAMS {
    CK_BYTE_PTR pPeerKTC;
    CK_SIZE     pPeerKTCLen;
    CK_BYTE     bMacTagOut[CK_KDE_MACTAG_LEN]; /*output parameter*/
} CK_KDE_ECCP521_DERIVE_PARAMS;

typedef CK_KDE_ECCP521_DERIVE_PARAMS * CK_KDE_ECCP521_DERIVE_PARAMS_PTR;

typedef struct CK_KDE_TOKEN_WRAP_PARAMS {
    CK_BYTE bPeerMacTag[CK_KDE_MACTAG_LEN];
} CK_KDE_TOKEN_WRAP_PARAMS;

typedef CK_KDE_TOKEN_WRAP_PARAMS * CK_TOKEN_WRAP_KDE_PARAMS_PTR;

/*
* Mechanisms parameter for supporting TUAK functions (CKM_TUAK1_DERIVE and CKM_TUAK1_SIGN) as per
* TS 35.231
*/
typedef struct CK_TUAK_DERIVE_PARAMS
{
	CK_ULONG f;			/* Function Code - 30(f3), 40(f4), 50(f5), 51(f5*) */
	CK_OBJECT_HANDLE hObject;	/* Handle to TOP stored as Generic Secret Key */
	CK_BYTE random[16];		/* 16-byte of random Number. */
	CK_BYTE ck_size;		/* size of the confidentiality key that will be the ouput of f3 */
	CK_BYTE ik_size;		/* size of the integrity keys that will be the ouput of f4 */
	CK_BYTE res_size;		/* size of the signed response that is the output of f2 */	
	CK_BYTE keccak_it;		/* keccak iterations */
}CK_TUAK_DERIVE_PARAMS;
typedef struct CK_TUAK_DERIVE_PARAMS CK_PTR CK_TUAK_DERIVE_PARAMS_PTR;

typedef struct CK_TUAK_SIGN_PARAMS
{
	CK_ULONG f;			/* Function Code - 10 (f1), 11(f1*), 20(f2) */
	CK_OBJECT_HANDLE hObject;	/* Handle to TOP stored as Generic Secret Key */
	CK_BYTE sqn[6];			/* SQN 6-byte of Sequence Number. */
	CK_BYTE amf[2]; 		/* AMF 2-byte of Authentication Management Field. */
	CK_BYTE mac_res_size;		/* Size of MAC-A (output of f1) or MAC-S (output of f*) or size of RES (output of f2)*/
	CK_BYTE ck_size;		/* Size of Confidentiality key that is the output of the function f3*/
	CK_BYTE ik_size;		/* Size of Integrity key that is the output of the function f4 */
	CK_BYTE keccak_it;		/* Keccak iterations */
}CK_TUAK_SIGN_PARAMS;
typedef struct CK_TUAK_SIGN_PARAMS CK_PTR CK_TUAK_SIGN_PARAMS_PTR;

typedef CK_BYTE CK_SOM_CHALLENGE[20];   // Null terminated 19 characters length string in format XXXX-XXXX-XXXX-XXXX
typedef CK_BYTE CK_SOM_RESPONSE[20];    // Null terminated 19 characters length string in format XXXX-XXXX-XXXX-XXXX

/**
 * Vendor defined CKR_ error codes.
 */
#define CKR_ERACOM_ERROR		(CKR_VENDOR_DEFINED+0x100)
#define CKR_TIME_STAMP          (CKR_ERACOM_ERROR+0x01)
#define CKR_ACCESS_DENIED		(CKR_ERACOM_ERROR+0x02)
#define CKR_CRYPTOKI_UNUSABLE	(CKR_ERACOM_ERROR+0x03)
#define CKR_ENCODE_ERROR		(CKR_ERACOM_ERROR+0x04)
#define CKR_V_CONFIG			(CKR_ERACOM_ERROR+0x05)
#define CKR_SO_NOT_LOGGED_IN	(CKR_ERACOM_ERROR+0x06)
#define CKR_CERT_NOT_VALIDATED	(CKR_ERACOM_ERROR+0x07)
#define CKR_PIN_ALREADY_INITIALIZED (CKR_ERACOM_ERROR+0x08)

#define CKR_REMOTE_SERVER_ERROR	(CKR_ERACOM_ERROR+0x0a)
#define CKR_CSA_HW_ERROR		(CKR_ERACOM_ERROR+0x0b)

#define CKR_NO_CHALLENGE		(CKR_ERACOM_ERROR+0x10)
#define CKR_RESPONSE_INVALID	(CKR_ERACOM_ERROR+0x11)

#define CKR_EVENT_LOG_NOT_FULL	(CKR_ERACOM_ERROR+0x13)
#define CKR_OBJECT_READ_ONLY    (CKR_ERACOM_ERROR+0x14)
#define CKR_TOKEN_READ_ONLY     (CKR_ERACOM_ERROR+0x15)
#define CKR_TOKEN_NOT_INITIALIZED (CKR_ERACOM_ERROR+0x16)
#define CKR_NOT_ADMIN_TOKEN     (CKR_ERACOM_ERROR+0x17)

#if 0 /* Not implementing this functionality as at 06/06/2002 */
#define CKR_CERTIFICATE_NOT_YET_ACTIVE     (CKR_ERACOM_ERROR+0x20)
#define CKR_CERTIFICATE_EXPIRED            (CKR_ERACOM_ERROR+0x21)
#endif

#define CKR_AUTHENTICATION_REQUIRED (CKR_ERACOM_ERROR + 0x30)
#define CKR_OPERATION_NOT_PERMITTED (CKR_ERACOM_ERROR + 0x31)
#define CKR_PKCS12_DECODE           (CKR_ERACOM_ERROR + 0x32)
#define CKR_PKCS12_UNSUPPORTED_SAFEBAG_TYPE   (CKR_ERACOM_ERROR + 0x33)
#define CKR_PKCS12_UNSUPPORTED_PRIVACY_MODE   (CKR_ERACOM_ERROR + 0x34)
#define CKR_PKCS12_UNSUPPORTED_INTEGRITY_MODE (CKR_ERACOM_ERROR + 0x35)
#define CKR_KEY_NOT_ACTIVE      (CKR_ERACOM_ERROR + 0x036)

#define CKR_ET_NOT_ODD_PARITY   (CKR_ERACOM_ERROR + 0x40)


#define CKR_HOST_ERROR			(CKR_VENDOR_DEFINED+0x1000)
#define CKR_BAD_REQUEST			(CKR_HOST_ERROR + 1)
#define CKR_BAD_ATTRIBUTE_PACKING (CKR_HOST_ERROR + 2)
#define CKR_BAD_ATTRIBUTE_COUNT (CKR_HOST_ERROR + 3)
#define CKR_BAD_PARAM_PACKING	(CKR_HOST_ERROR + 4)
#define CKR_EXTERN_DCP_ERROR	(CKR_HOST_ERROR + 0x386)

#define CKR_MSG_ERROR			(CKR_VENDOR_DEFINED+0x300)
#define CKR_CANNOT_DERIVE_KEYS	(CKR_MSG_ERROR + 0x81)
#define CKR_BAD_REQ_SIGNATURE	(CKR_MSG_ERROR + 0x82)
#define CKR_BAD_REPLY_SIGNATURE (CKR_MSG_ERROR + 0x83)
#define CKR_SMS_ERROR			(CKR_MSG_ERROR + 0x84)
#define CKR_BAD_PROTECTION		(CKR_MSG_ERROR + 0x85)
#define CKR_DEVICE_RESET		(CKR_MSG_ERROR + 0x86)
#define CKR_NO_SESSION_KEYS		(CKR_MSG_ERROR + 0x87)
#define CKR_BAD_REPLY			(CKR_MSG_ERROR + 0x88)
#define CKR_KEY_ROLLOVER		(CKR_MSG_ERROR + 0x89)

#define CKR_NEED_IV_UPDATE		(CKR_MSG_ERROR+0x10)
#define CKR_DUPLICATE_IV_FOUND	(CKR_MSG_ERROR+0x11)

#define CKR_WLD_ERROR                        (CKR_VENDOR_DEFINED + 0x2000)
#define CKR_WLD_CONFIG_NOT_FOUND             (CKR_WLD_ERROR) + 0x01
#define CKR_WLD_CONFIG_ITEM_READ_FAILED      (CKR_WLD_ERROR) + 0x02
#define CKR_WLD_CONFIG_NO_TOKEN_LABEL        (CKR_WLD_ERROR) + 0x03
#define CKR_WLD_CONFIG_TOKEN_LABEL_LEN       (CKR_WLD_ERROR) + 0x04
#define CKR_WLD_CONFIG_TOKEN_SERIAL_NUM_LEN  (CKR_WLD_ERROR) + 0x05
#define CKR_WLD_CONFIG_SLOT_DESCRIPTION_LEN  (CKR_WLD_ERROR) + 0x06
#define CKR_WLD_CONFIG_ITEM_FORMAT_INVALID   (CKR_WLD_ERROR) + 0x07
#define CKR_WLD_LOGIN_CACHE_INCONSISTENT     (CKR_WLD_ERROR) + 0x10

#define CKR_HA_ERROR                        (CKR_VENDOR_DEFINED + 0x3000)
#define CKR_HA_MAX_SLOTS_INVALID_LEN        (CKR_HA_ERROR) + 0x01
#define CKR_HA_SESSION_HANDLE_INVALID       (CKR_HA_ERROR) + 0x02
#define	CKR_HA_SESSION_INVALID				(CKR_HA_ERROR) + 0x03
#define CKR_HA_OBJECT_INDEX_INVALID			(CKR_HA_ERROR) + 0x04
#define CKR_HA_CANNOT_RECOVER_KEY			(CKR_HA_ERROR) + 0x05
#define CKR_HA_NO_HSM           			(CKR_HA_ERROR) + 0x06
#define CKR_HA_OUT_OF_OBJS        			(CKR_HA_ERROR) + 0x07

#define CKR_SECURITY_FLAGS_INCOMPATIBLE		(CKR_VENDOR_DEFINED + 0x3500)

#define CKR_FM_ERROR                        (CKR_VENDOR_DEFINED + 0x4000)
#define CKR_FM_NOT_REGISTERED               (CKR_FM_ERROR) + 0x01
#define CKR_FM_DISPATCH_BLOCKED             (CKR_FM_ERROR) + 0x02

#define CKR_BIP32_CHILD_INDEX_INVALID           (CKR_VENDOR_DEFINED + 0x7B)
#define CKR_BIP32_INVALID_HARDENED_DERIVATION   (CKR_VENDOR_DEFINED + 0x7C)
#define CKR_BIP32_MASTER_SEED_LEN_INVALID       (CKR_VENDOR_DEFINED + 0x7D)
#define CKR_BIP32_MASTER_SEED_INVALID           (CKR_VENDOR_DEFINED + 0x7E)
#define CKR_BIP32_INVALID_KEY_PATH_LEN          (CKR_VENDOR_DEFINED + 0x7F)

#define CKR_OTP_PIN_INCORRECT                 (CKR_VENDOR_DEFINED + 0x8B)
#define CKR_OTP_PIN_LEN_RANGE                 (CKR_VENDOR_DEFINED + 0x8C)
#define CKR_OTP_PIN_ALREADY_INITIALIZED       (CKR_VENDOR_DEFINED + 0x8D)
#define CKR_OTP_PIN_NOT_INITIALIZED           (CKR_VENDOR_DEFINED + 0x8E)
#define CKR_OTP_PIN_REUSED                    (CKR_VENDOR_DEFINED + 0x8F)

#define CKR_POINT_INVALID                     (CKR_VENDOR_DEFINED + 0x90)
#define CKR_IN_SOM                            (CKR_VENDOR_DEFINED + 0x91)

#define CKR_TR31_HDR_INCONSISTENT             (CKR_VENDOR_DEFINED + 0x98)

#endif




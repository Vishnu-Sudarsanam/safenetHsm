/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2023 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cryptoki.h>

#include <csa8hiface.h>
#include <ctype.h>
#include <ecc.h>
#include <fm.h>
#include <fmciphobj.h>
#include <fmdebug.h>
#include <fmsw.h>

#include "eccdemo.h"

/**
 * This structure is used to store information about points on elliptic curves
 * in a memory efficient manner.
 */
typedef struct {
    /** x coordinate */
    char *x;

    /** y coordinate */
    char *y;
} AsciiPoint_t;

/**
 * This structure is used to store the curve information in the ascii format.
 * All the fields are hexadecimal representations of the values used in a curve.
 * e.g. "AABA91" is a representation for the buffer {0xAA, 0xBA, 0x91};
 * Curves can be defined in binary but sometimes an ascii representation is easier to obtain.
 */
typedef struct {

    /** The field over which this curve is defined. */
    ECC_FieldType_t fieldType;

    /** The curve modulus. */
    const char *modulus;

    /** The coefficient 'a' in the elliptic curve equation. */
    const char *a;

    /** The coefficient 'b' in the elliptic curve equation. */
    const char *b;

    /** The base point. */
    AsciiPoint_t base;

    /** The base point order. This buffer contains a big endian large number
     * regardless of the field type. */
    const char *bpOrder;

} AsciiCurve_t;

/* SEC-2 2.6.2 (secp224r1) */
AsciiCurve_t curvep224r1 = {
    ECC_FT_GFP,
    /* p = 2^224 - 2^96 + 1 */
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001", /* p */
    /* = -3 mod p */
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE", /* a */
    "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4", /* b */
    {
        "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21", /* Gx */
        "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34"  /* Gy */
    },
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D" /* n */
};

/* Private Key */
uint8_t priv224r1[] = {
    0xEA, 0x65, 0xF6, 0xDD, 0x7A, 0x75, 0xB8, 0xB5,
    0x13, 0x3A, 0xA5, 0xDE, 0xD5, 0xD1, 0x4D, 0xC5,
    0x90, 0xAB, 0x21, 0x91, 0xF6, 0xED, 0xA4, 0x37,
    0xA5, 0x79, 0x1A, 0x85
};

/**Public key
 * 04 || x || y
 */
uint8_t pub224r1[] = {
    0x04,
        0x21, 0x65, 0xC5, 0x7E, 0x42, 0x9E, 0x87, 0xDA,
        0xE4, 0x0D, 0x65, 0x30, 0xCE, 0x74, 0x8C, 0x5D,
        0xD5, 0xAB, 0x71, 0x40, 0x77, 0xD3, 0xE3, 0x2C,
        0x00, 0xAA, 0x75, 0xA9, 0x9C, 0xA7, 0x0C, 0xAF,
        0xA9, 0x9F, 0xC9, 0x65, 0xFD, 0x3E, 0xAF, 0xC7,
        0x25, 0x97, 0xD8, 0x54, 0x47, 0xCA, 0x40, 0xFB,
        0xAA, 0xAA, 0x8C, 0xBF, 0xF8, 0x3F, 0xC4, 0xB8
};

/* SHA1 hash of "abc" */
uint8_t sha1Hash[] = {
    0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
    0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
    0x9c, 0xd0, 0xd8, 0x9d
};

/**  Returns an index to the first non zero byte in a buffer.
 *   Returns len if the buffer was all zeros.
*/
static size_t skipLeadingNull(const uint8_t *str, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++)
        if (*(str++))
            break;
    return i;
}

static void getOrdLenBits(const ECC_Curve_t *curve, uint32_t *pOrdLen)
{
    if (curve == NULL || pOrdLen == NULL)
        return;
    size_t ordLen = sizeof(curve->bpOrder) - skipLeadingNull(curve->bpOrder, sizeof(curve->bpOrder));
    if (ordLen > sizeof(curve->bpOrder))
        *pOrdLen = ECC_MAX_MOD_LEN;
    else {
        size_t  modBits = ordLen * 8;
        uint8_t msb     = curve->bpOrder[sizeof(curve->bpOrder) - ordLen];

        /* reduce modBits for each leading zero bit in MSB of modulus */
        while ((msb & 0x80) == 0) {
            msb <<= 1;
            --modBits;
        }
        *pOrdLen = modBits;
    }
}

#define CHRVAL(c) (uint8_t)((c) - ((c) <= '9' ? '0' : 'A' - 10))

static size_t hex2bin(void *bin, const char *hex, size_t maxLen)
{
    uint8_t *buf = (uint8_t *)bin;
    size_t   i   = 0;

    for (; *hex; hex++) {
        int ch = *hex;

        if (isspace(ch))
            continue; /* ignored */

        ch = toupper(*hex);

        if (!isxdigit(ch))
            break; /* terminate if non hex character is detected */

        if (i & 1) {
            /* second nybble */
            *buf = (uint8_t)((*buf) * 16 + CHRVAL(ch));
            buf++;
        } else {
            /* first nybble */

            if (i / 2 >= maxLen)
                break; /* output buffer overflow */

            *buf = CHRVAL(ch);
        }
        i++;
    }
    /* If i is odd length AND greater than 1, then must shift entire HEX value
     * 1 nibble to the right, and prepend a 0.
     */
    if ((i / 2 < maxLen) && (i & 1) && (i > 1)) {
        size_t j;

        buf = (uint8_t *)bin;
        /* move 2nd nibble of 2nd last byte to first nibble of last byte */
        buf[i / 2] |= buf[i / 2 - 1] << 4;
        /* for all bytes except first byte, first nibble becomes second nibble
         * and previous byte's second nibble becomes this bytes first nibble.
         */
        for (j = i / 2 - 1; j > 0; j--)
            buf[j] = (uint8_t)(((buf[j] >> 4) & 0xf) | buf[j - 1] << 4);
        /* Append leading zero to first byte, by shifting first nibble to
         * second nibble.
         */
        buf[0] = (uint8_t)((buf[0] >> 4) & 0xf);
        i++;
    }
    return i / 2;
}

/**
 * Convert an ASCII hex dump of memory to binary data.
 *
 * This function assumes that the output memory will be right-aligned, and
 * zeroizes the leftmost bytes.
 *
 * @param out
 *    The output buffer, that will contain the binary data when the function
 *    returns.
 * @param len
 *    The number of bytes in @ref buffer
 * @param in
 *    The ASCII hex dump of the bytes to be copied to the buffer.
 */
static void asciiToBin(uint8_t *out, size_t len, const char *in)
{
    size_t offset;
    /*Assume that the input has no spaces and/or non-hex values*/
    size_t ordlen = (strlen(in) + 1) / 2;
    if (ordlen > len) return;

    /* Convert ASCII hex data to binary data */
    offset = len - ordlen;
    hex2bin(out + offset, in, ordlen);
}

/**
 * Convert an Ascii curve definition to a curve definition that can be used by
 * the library.
 *
 * @param out
 *    The ECC library curve structure
 *    fieldtype is set up
 *    modulus, a, b and bpOrder are zero padded right aligned
 *    base has x and y values zero padded and right aligned
 *    pointSize is number ob significant bytes od modulus
 *    ordBitSize is number of significant bits of bpOrder
 *    curveOID is zero
 * @param in
 *    The ASCII curve structure
 */
static void asciiToBinCurve(ECC_Curve_t *out, const AsciiCurve_t *in)
{
    memset(out, 0, sizeof(*out));
    out->fieldType = in->fieldType;

    asciiToBin(out->modulus, sizeof(out->modulus), in->modulus);
    asciiToBin(out->a, sizeof(out->a), in->a);
    asciiToBin(out->b, sizeof(out->b), in->b);
    asciiToBin(out->base.x, sizeof(out->base.x), in->base.x);
    asciiToBin(out->base.y, sizeof(out->base.y), in->base.y);
    asciiToBin(out->bpOrder, sizeof(out->bpOrder), in->bpOrder);

    out->pointSize = sizeof(out->modulus) - skipLeadingNull(out->modulus, sizeof(out->modulus));
    getOrdLenBits(out, &out->ordBitSize);
}

/* Perform Single Part sign/verify with P-224 curve */
static CK_RV SinglePart_EccDemo(void)
{
    CK_RV rv    = CKR_OK;
    int   coerr = CO_OK;

    size_t               modLen, ordLen, offset, hashLen;
    ECC_Curve_t          curve;
    ECC_PrivateKey_t     privKey;
    ECC_PublicKey_t      pubKey;
    ECC_EcdsaSignature_t sign;
    uint8_t              sign_buf[2 * ECC_MAX_BUF_LEN] = {0};
    CipherObj *          pCiphObj                      = NULL;

    unsigned int retSz;

    ECC_SignKey_t   ciphObjPriKeyVal;
    ECC_VerifyKey_t ciphObjPubKeyVal;

    printf("%s: Start", __func__);

    /** Allocate an ECDSA Cipher Object
     * Other objects like FMCO_IDX_ECDSA_SHA224 will compute the hash value
     * but the FMCO_IDX_ECDSA object just takes a raw hash value.
     * Curves, key and signature structures are the same.
     */
    pCiphObj = FmCreateCipherObject(FMCO_IDX_ECDSA);
    if (pCiphObj == NULL) {
        rv = CKR_FUNCTION_FAILED;
        goto exit;
    }

    /** Build the Curve structure.
     * Alternatively you could use a statically defined structure
     */
    asciiToBinCurve(&curve, &curvep224r1);

    /* pick up a couple of useful values */
    modLen = curve.pointSize;
    /* order length in bytes */
    ordLen = (curve.ordBitSize + 7) / 8;

    sign.sign        = sign_buf;
    sign.sign_length = 2 * ordLen;

    /* input data hash - truncate hash if necessary */
    hashLen = MIN(sizeof(sha1Hash), ordLen);

    /** copy private key into input structure
     * - right aligned and zero padded */
    offset = ECC_MAX_BUF_LEN - ordLen;
    memset(privKey.d, 0, offset);
    memcpy(privKey.d + offset, priv224r1, ordLen);

    /* init sign operation */
    ciphObjPriKeyVal.curve  = curve;
    ciphObjPriKeyVal.priKey = privKey;

    coerr = pCiphObj->SignInit(pCiphObj,
                               0,
                               &ciphObjPriKeyVal,
                               sizeof(ciphObjPriKeyVal),
                               NULL,
                               0);
    if (coerr != CO_OK) {
        printf("%s: Error calling SignInit = %d", __func__, coerr);
        rv = CKR_FUNCTION_FAILED;
        goto exit;
    }

    /* perform sign operation */
    retSz = sign.sign_length;
    coerr = pCiphObj->SignRecover(pCiphObj,
                                  sign.sign, retSz, &retSz,
                                  sha1Hash, hashLen);
    if (coerr != CO_OK) {
        printf("%s: Error calling SignRecover = %d", __func__, coerr);
        rv = CKR_FUNCTION_FAILED;
        goto exit;
    }
    sign.sign_length = retSz;

    /** store public key point into struct
     *  - right aligned and zero padded */
    offset = ECC_MAX_BUF_LEN - modLen;
    memset(pubKey.p.x, 0, offset);
    memset(pubKey.p.y, 0, offset);
    /*do not copy in the leading 04h byte*/
    memcpy(pubKey.p.x + offset, pub224r1 + 1, modLen);
    memcpy(pubKey.p.y + offset, pub224r1 + 1 + modLen, modLen);

    ciphObjPubKeyVal.curve  = curve;
    ciphObjPubKeyVal.pubKey = pubKey;

    /* init verify operation */
    coerr = pCiphObj->VerifyInit(pCiphObj,
                                 0,
                                 &ciphObjPubKeyVal,
                                 sizeof(ciphObjPubKeyVal),
                                 NULL,
                                 0);

    if (coerr != CO_OK) {
        printf("%s: Error calling VerifyInit = %d", __func__, coerr);
        rv = CKR_FUNCTION_FAILED;
        goto exit;
    }

    /* perform verify operation */
    coerr = pCiphObj->Verify(pCiphObj,
                             sign.sign, retSz,
                             sha1Hash, hashLen);

    if (coerr != CO_OK) {
        printf("%s: Error calling Verify = %d", __func__, coerr);
        rv = CKR_FUNCTION_FAILED;
        goto exit;
    }

exit:
    if (pCiphObj)
        pCiphObj->Free(pCiphObj);

    printf("%s: Finish: ret code = %#08lx", __func__, rv);

    return rv;
}

/* Curve structure in full binary for G2M 191V1E */
ECC_Curve_t Curve191v1e = {

    ECC_FT_G2M, /*type*/
    /* p = 2^191 + 2^9 + 1 */
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01 /*modulus*/
    },
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 /*a*/
    },
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x30, 0xe5, 0xd4, 0xce, 0x34, 0x54, 0xed, 0x2e, 0xc0, 0x66, 0x1d, 0x08, 0xbf, 0x17, 0xc6, 0xed,
        0xc6, 0xd6, 0xf9, 0xb1, 0xa4, 0xf9, 0xd1, 0x6c /*b*/
    },
    {/* Base Point */
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x63, 0xE1, 0x31, 0xE2, 0x3E, 0xB3, 0xE4, 0x5B, 0xDC, 0x0B, 0xED, 0xB9, 0x1E, 0x69, 0x7B, 0xC2,
            0xAE, 0x5B, 0xD3, 0xFF, 0x29, 0xA3, 0xCC, 0x6D /*Gx*/
        },
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x52, 0x1F, 0x0A, 0xCF, 0x1F, 0xF6, 0x1C, 0x51, 0x5F, 0xB9, 0x88, 0x55, 0x8B, 0x74, 0xEF, 0x90,
            0x34, 0xB8, 0xB7, 0xE1, 0xF7, 0xE9, 0xBB, 0xD8 /*Gy*/
        }
    },
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x98, 0x78, 0xAF, 0x7F,
        0x62, 0x12, 0x18, 0x47, 0x8E, 0x6E, 0x69, 0x9D /*order*/
    },

    0, /* Set to OID_UNKNOWN (0) */

    24, /** The modulus size in bytes.*/

    191 /** The order size in bits. */
};

/* Private Key - significant bytes only */
uint8_t priv191v1e[] = {
    0x0A, 0xD4, 0x79, 0x17, 0x9C, 0xE4, 0x7E, 0xB7,
    0xF7, 0x45, 0xF6, 0x63, 0xB8, 0x17, 0x80, 0xD1,
    0xF4, 0x0F, 0x13, 0x24, 0xF5, 0x30, 0x85, 0x37
};

/** Public key - significant bytes only
 * Format 04 || x || y
 */
uint8_t pub191v1e[] = {
    0x04,
        0x46, 0x82, 0x2A, 0xF5, 0xD7, 0x1F, 0x47, 0x24,
        0x9A, 0x3E, 0x7D, 0x79, 0x37, 0x27, 0x76, 0x28,
        0xA5, 0xE7, 0x29, 0x3E, 0x18, 0xEC, 0xCF, 0xB9,
        0x09, 0x3C, 0x96, 0xDB, 0x24, 0xD2, 0x19, 0x3E,
        0xD0, 0x2D, 0x95, 0x37, 0x5D, 0x54, 0x39, 0x1C,
        0xEE, 0xC2, 0xAB, 0x84, 0xEB, 0xE3, 0xAD, 0xD9
};

const char message[] = "Now is the time for all good men.";

/* Perform Multi Part sign/verify with P191V1E curve using SHA256 Digest */

static CK_RV MultiPart_EccDemo(void)
{
    CK_RV rv    = CKR_OK;
    int   coerr = CO_OK;

    size_t               modLen, ordLen, offset, msgLen;
    ECC_Curve_t          curve;
    ECC_PrivateKey_t     privKey;
    ECC_PublicKey_t      pubKey;
    ECC_EcdsaSignature_t sign;
    uint8_t              sign_buf[2 * ECC_MAX_BUF_LEN] = {0};
    CipherObj *          pCiphObj                      = NULL;

    unsigned int retSz;

    ECC_SignKey_t   ciphObjPriKeyVal;
    ECC_VerifyKey_t ciphObjPubKeyVal;

    printf("%s: Start", __func__);

    curve = Curve191v1e; /*take a local copy of the curve structure*/

    /* Allocate an ECDSA SHA256 Cipher Object*/
    pCiphObj = FmCreateCipherObject(FMCO_IDX_ECDSA_SHA256);
    if (pCiphObj == NULL) {
        rv = CKR_FUNCTION_FAILED;
        goto exit;
    }

    /*pick up a couple of useful values*/
    modLen = curve.pointSize;
    /* order length in bytes */
    ordLen = (curve.ordBitSize + 7) / 8;
    msgLen = strlen(message);

    sign.sign        = sign_buf;
    sign.sign_length = 2 * ordLen;

    /** copy private key into input structure
     *  - right aligned and zero padded */
    offset = ECC_MAX_BUF_LEN - ordLen;

    memset(privKey.d, 0, offset);
    memcpy(privKey.d + offset, priv191v1e, ordLen);

    /* init sign operation */
    ciphObjPriKeyVal.curve  = curve;
    ciphObjPriKeyVal.priKey = privKey;

    coerr = pCiphObj->SignInit(pCiphObj,
                               0,
                               &ciphObjPriKeyVal,
                               sizeof(ciphObjPriKeyVal),
                               NULL,
                               0);
    if (coerr != CO_OK) {
        printf("%s: Error calling SignInit = %d", __func__, coerr);
        rv = CKR_FUNCTION_FAILED;
        goto exit;
    }

    /* perform sign update in two separate operations */
    offset = msgLen / 2;
    coerr  = pCiphObj->SignUpdate(pCiphObj, message, offset);
    if (coerr != CO_OK) {
        printf("%s: Error calling SignUpdate = %d", __func__, coerr);
        rv = CKR_FUNCTION_FAILED;
        goto exit;
    }

    coerr = pCiphObj->SignUpdate(pCiphObj, message + offset, msgLen - offset);
    if (coerr != CO_OK) {
        printf("%s: Error calling SignUpdate = %d", __func__, coerr);
        rv = CKR_FUNCTION_FAILED;
        goto exit;
    }

    /* Perform sign final */
    retSz = sign.sign_length;
    coerr = pCiphObj->SignFinal(pCiphObj, sign.sign, retSz, &retSz);

    sign.sign_length = retSz;

    if (coerr != CO_OK) {
        printf("%s: Error calling SignFinal = %d", __func__, coerr);
        rv = CKR_FUNCTION_FAILED;
        goto exit;
    }

    /** store public key point into struct
     *  - right aligned and zero padded */
    offset = ECC_MAX_BUF_LEN - modLen;
    memset(pubKey.p.x, 0, offset);
    memset(pubKey.p.y, 0, offset);
    /* do not copy in the leading 04h byte */
    memcpy(pubKey.p.x + offset, pub191v1e + 1, modLen);
    memcpy(pubKey.p.y + offset, pub191v1e + 1 + modLen, modLen);

    ciphObjPubKeyVal.curve  = curve;
    ciphObjPubKeyVal.pubKey = pubKey;

    /* perform verify init */
    coerr = pCiphObj->VerifyInit(pCiphObj,
                                 0,
                                 &ciphObjPubKeyVal,
                                 sizeof(ciphObjPubKeyVal),
                                 NULL,
                                 0);

    if (coerr != CO_OK) {
        printf("%s: Error calling VerifyInit = %d", __func__, coerr);
        rv = CKR_FUNCTION_FAILED;
        goto exit;
    }

    /* Perform verify update in two steps */
    offset = msgLen / 2;
    coerr  = pCiphObj->VerifyUpdate(pCiphObj, message, offset);
    if (coerr != CO_OK) {
        printf("%s: Error calling VerifyUpdate = %d", __func__, coerr);
        rv = CKR_FUNCTION_FAILED;
        goto exit;
    }

    coerr = pCiphObj->VerifyUpdate(pCiphObj, message + offset, msgLen - offset);
    if (coerr != CO_OK) {
        printf("%s: Error calling VerifyUpdate = %d", __func__, coerr);
        rv = CKR_FUNCTION_FAILED;
        goto exit;
    }

    /* Perform verify final */
    coerr = pCiphObj->VerifyFinal(pCiphObj,
                                  sign.sign, sign.sign_length, NULL, 0, NULL);

    if (coerr != CO_OK) {
        printf("%s: Error calling VerifyFinal = %d", __func__, coerr);
        rv = CKR_FUNCTION_FAILED;
        goto exit;
    }

exit:
    if (pCiphObj)
        pCiphObj->Free(pCiphObj);

    printf("%s: Finish: ret code = %08lx", __func__, rv);

    return rv;
}

/* command handler entry point */
static void EccDemoFM_HandleMessage(
    HI_MsgHandle token,
    void *       reqBuffer,
    uint32_t     reqLength)
{
    uint16_t cmd = 0;
    CK_RV    rv  = CKR_OK;

    /* Argument sanity check */
    if (reqLength < sizeof(cmd)) {
        /* Ensure the request is long enough to contain at least the cmd  */
        rv = CKR_FUNCTION_NOT_SUPPORTED;
    } else {
        /* parse command */
        cmd = *(uint16_t *)reqBuffer;
        cmd = ntoh_short(cmd);

        /* command switch, only one command */
        switch (cmd) {
            case ECC_DEMO_CMD:
                /* call API fuction */
                rv = SinglePart_EccDemo();
                if (rv == CKR_OK)
                    rv = MultiPart_EccDemo();
                break;
            default:
                rv = CKR_FUNCTION_NOT_SUPPORTED;
                break;
        }
    }
    /* send reply back */
    SVC_SendReply(token, (uint32_t)rv);
}

/* FM Startup function */
FM_RV Startup(void)
{
    FM_RV rv = FM_OK;
    /* register handler for our new API */
    debug(printf("Registering dispatch function ... "););
    rv = (FM_RV)FMSW_RegisterDispatch(ECCDEMO_FM_NUMBER, EccDemoFM_HandleMessage);
    debug(printf("registered. Return Code = %08x", rv););
    return rv;
}

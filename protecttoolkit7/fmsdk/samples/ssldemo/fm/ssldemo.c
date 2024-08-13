/**
 * @file
 * ECDSA program: Demonstrates the creation of a custom API using
 * the FM SDK.
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include <cryptoki.h>
#include <cprovtbl.h>
#include <cprovpch.h>
#include <csa8hiface.h>
#include <fmciphobj.h>
#include <ctutil.h>
#include <string.h>
#include <time.h>
#include <fmsw.h>
#include <fm.h>
#include <fmdebug.h>
#include <genmacro.h>

#include <openssl/ec/ec.h>

#define ECC_MAX_LEN_BITS 571

#define XPRV_KEY_LEN                    64
#define XPUB_KEY_LEN                    65

#define PRV_KEY_LEN                     32
#define PUB_FULL_KEY_LEN                65
#define PUB_COMP_KEY_LEN                33
#define CHAIN_CODE_LEN                  32
#define COORD_LEN                       32
#define IDX_LEN                         4
#define MY_FM_NUMBER                    0x600

// convert HashObj error code to CK_RV type
CK_RV ConvHOToRV(int err)
{
    switch( err )
    {

	case CO_OK:
        return CKR_OK;

	case CO_PARAM_INVALID:
        return CKR_ARGUMENTS_BAD;

	case CO_SIG_INVALID:
        return CKR_SIGNATURE_INVALID;

	case CO_LENGTH_INVALID:
        return CKR_DATA_LEN_RANGE;

	case CO_DEVICE_ERROR:
        return CKR_DEVICE_ERROR;

	case CO_GENERAL_ERROR:
        return CKR_GENERAL_ERROR;

	case CO_MEMORY_ERROR:
        return CKR_DEVICE_MEMORY;

	case CO_BUFFER_TOO_SMALL:
        return CKR_BUFFER_TOO_SMALL;

	case CO_DATA_INVALID:
        return CKR_DATA_INVALID;

	case CO_NEED_IV_UPDATE:
	case CO_NOT_SUPPORTED:
	case CO_DUPLICATE_IV_FOUND:
    case CO_FIPSG_ERROR:
    case CO_FUNCTION_NOT_IMPLEMENTED:
    default:
        break;
    }
    return CKR_FUNCTION_FAILED; 
}

CK_RV DoHMAC(int klength, char *key, 
             int dataLen, char *data, 
             HashObj * hashObj, 
             unsigned char * out, int outBufLen )
{
    int err = 0;
    unsigned char keyBuf[1024/8] = {0};   // handle block for SHA512
    unsigned char hashBuf[512/8] = {0};   // handle up to 512 bit hash lengths
    unsigned int hlen;
	HashInfo hinfo;

	hashObj->GetInfo(hashObj, &hinfo);

    if(hinfo.blockLength > sizeof(keyBuf))
	{
		err = CO_LENGTH_INVALID;
		goto error;
	}
	if ( outBufLen > hinfo.hashLength )
	{
		err = CO_LENGTH_INVALID;
		goto error;
	}

    /* truncate key if it is too long */
    if ( klength > hinfo.blockLength ) 
    {
        // key buf is H(key) || zero padding
        /* replace key with h(key) */
        unsigned int hlen = sizeof(keyBuf);

        /* rehash for HMAC */
        if ((err = hashObj->Init(hashObj)) != 0 ||
           (err = hashObj->Update(hashObj, (void*)key, klength)) != 0 ||
           (err = hashObj->Final(hashObj, keyBuf, sizeof(keyBuf), &hlen)) != 0)
               goto error;
    } else {
        // key buf is key || zero padding
        memcpy(keyBuf, key, klength);
    }
    
    klength = hinfo.blockLength;


    // klength is now the length of the keyBuf and
    // key points to padded B length key value

	{
		/* perform the inner digest */
		unsigned int i;
        char ipad[1024/8];   // handle up to SHA512 

		memcpy(ipad, keyBuf, klength);
		for (i = 0; i < klength; i++)
			ipad[i] ^= 0x36;

		if ( (err = hashObj->Init(hashObj)) != 0 ||
		     (err = hashObj->Update(hashObj, ipad, klength)) != 0 ||
	         (err = hashObj->Update(hashObj, data, dataLen)) != 0 ||
	         (err = hashObj->Final(hashObj, hashBuf, sizeof(hashBuf), &hlen)) != 0 )
			goto error;
	}

	if ( err ) goto error;

    {
	    /* outer padding */
        char opad[1024/8];   // handle up to SHA512
        int i;

	    memcpy( opad, keyBuf, klength );
	    for (i = 0; i < klength; i++) {
		    opad[i] ^= 0x5c;
	    }

	        /* 2nd pass */
	    if ( (err = hashObj->Init(hashObj)) != 0 ||
	         (err = hashObj->Update(hashObj, opad, klength)) != 0 ||
             (err = hashObj->Update(hashObj, hashBuf, hlen)) != 0 ||
             (err = hashObj->Final(hashObj, hashBuf, sizeof(hashBuf), &hlen)) != 0 )
		    goto error;
    }

	memcpy(out, hashBuf, outBufLen);

error:

	return ConvHOToRV(err);
}

CK_RV DoHMAC512(int klength, char *key, 
             int dataLen, char *data, 
             unsigned char * out, int outBufLen )
{
    static HashObj * hashObj = NULL; 

    if ( hashObj == NULL )
        hashObj = FmCreateHashObject(FMCO_IDX_SHA512);

    return DoHMAC(klength, key, 
             dataLen, data, 
             hashObj, 
             out, outBufLen );
}

// set up an ec_curve structure for secp256k1 curve parameters
CK_RV EC_GROUP_new_secp256k1( EC_GROUP * ec_group )
{
    char *methodName = "EC_GROUP_new_secp256k1()";

    // look up a curve by OID (name lookup not supported)
    unsigned char secp256k1OID[] = { 0x06,0x05,0x2B,0x81,0x04,0x00,0x0A };
    int nid_secp256k1;  // index value of secp256k1 curve params 

    nid_secp256k1 = EC_oid2nid(secp256k1OID, sizeof(secp256k1OID));

    if (EC_GROUP_new_by_nid(ec_group, nid_secp256k1) == 0)
    {
        printf("-- %s: EC group not found for: [%d]\n", methodName, nid_secp256k1);
        return CKR_ARGUMENTS_BAD;
    }

    return CKR_OK;
}

// convert a char array into a hex string.
// max output is 256 bytes
// Return:
//    pointer to static buffer with string in it or  NULL is i/p too big
//
char *bytes2hex(unsigned char buf[], size_t buf_len) 
{
    static char str[256];
    size_t str_len = 2 * buf_len + 1, i;
    char *ptr = str;

    if ( str_len > sizeof(str) )
        return NULL;

    for (i = 0; i < buf_len; i++) {
        ptr += sprintf(ptr, "%02X", buf[i]);
    }

    return str;
}

// convert private key to public point
// ec_group:  curve
// prv:       serialized private key - len = PRV_KEY_LEN
// out:       where to store output in EC_POINT format
//
CK_RV GenPointBn( EC_GROUP * ec_group, BIGNUM * bnPrv, EC_POINT * out )
{
    // perform point multiplication gen*pGenX -> point
    CK_RV ret = EC_POINT_mul(ec_group, out, bnPrv, NULL, 0, NULL, 0);
    return ret ? CKR_OK : CKR_FUNCTION_FAILED;
}

// convert private key to public point
// ec_group:  curve
// prv:       serialized private key - len = PRV_KEY_LEN
// out:       where to store output in EC_POINT format
//
CK_RV GenPointBin( EC_GROUP * ec_group, CK_BYTE_PTR prv, EC_POINT * out )
{
    CK_RV ret;
    BN_Declare (bnPrv, ECC_MAX_LEN_BITS);

    BN_Constructor(bnPrv, BN_GetWordSize(bnPrv));
    BN_bin2bn(prv, PRV_KEY_LEN, bnPrv);

    ret = GenPointBn( ec_group, bnPrv, out );

    BN_Destructor(bnPrv);

    return ret;
} 

int DoKeyDeriveNormal(int idx, 
                      CK_BYTE prvPar[PRV_KEY_LEN], CK_BYTE chainPar[CHAIN_CODE_LEN],
                      CK_BYTE prvChild[PRV_KEY_LEN], CK_BYTE chainChild[CHAIN_CODE_LEN] )
{
    CK_RV rv;
    char *methodName = "DoKeyDerive()";

    uint32_t idx32;
    int len;
    EC_GROUP ec_group;
    EC_POINT point; 
    size_t point_len;
    CK_BYTE dgst[PRV_KEY_LEN + CHAIN_CODE_LEN];
    CK_BYTE data[PUB_COMP_KEY_LEN + IDX_LEN];
    BN_Declare (bnPrv, ECC_MAX_LEN_BITS);
    BN_Declare (bnIl, ECC_MAX_LEN_BITS);
    BN_Declare (bnChildPrv, ECC_MAX_LEN_BITS);
    BN_Declare (bnOrder, ECC_MAX_LEN_BITS);

    // fetch curve for secp256k1 - this could be cached for efficiency
    if ( (rv = EC_GROUP_new_secp256k1( &ec_group )) != CKR_OK )
        return rv;

    // initialize EC_POINT struct
    if ( EC_POINT_new(&point, &ec_group) == NULL )
    {
        printf("-- %s: EC cannot init point\n", methodName);
        return CKR_ARGUMENTS_BAD;
    }

    BN_Constructor(bnPrv, BN_GetWordSize(bnPrv));
    BN_bin2bn(prvPar, PRV_KEY_LEN, bnPrv);

    // convert private key of parent into the corresponding pub point
    if ( (rv = GenPointBn( &ec_group, bnPrv, &point )) != CKR_OK )
        return rv;

    // convert point to char array in start of data buffer
    point_len = EC_POINT_point2oct(&ec_group, &point, 
                                   POINT_CONVERSION_COMPRESSED, 
                                   data, XPUB_KEY_LEN, NULL);
    if( point_len != PUB_COMP_KEY_LEN ) 
		return CKR_GENERAL_ERROR;
    EC_POINT_free(&point);


#ifdef IS_LITTLE_ENDIAN
    idx32 = hton_long(idx);
#else
    idx32 = (uint32_t)idx;
#endif

    // append the big endian index value to end of data
    memcpy(data + PUB_COMP_KEY_LEN, &idx32, IDX_LEN);

    printf("-- %s: buf: [%s]\n", methodName, bytes2hex(data, sizeof(data)));

    rv = DoHMAC512(CHAIN_CODE_LEN, (char*)chainPar,   // key
             point_len + IDX_LEN, (char*)data,         // data to sign
             dgst, sizeof(dgst));

    if (rv) {
        printf("-- %s: DoHMAC512: rv = %#08x\n", methodName, (uint32_t)rv);
        return rv;
    }
    else {
        printf("-- %s: dgst: [%s]\n", methodName, bytes2hex(dgst, sizeof(dgst)));
    }

    // the returned chain code is Ir
    memcpy(chainChild, dgst + PRV_KEY_LEN, CHAIN_CODE_LEN);

    // parse256(Il)
    BN_Constructor(bnIl, BN_GetWordSize(bnIl));
    BN_bin2bn(dgst, PRV_KEY_LEN, bnIl);

    // take a copy of the Group order value
    BN_Constructor(bnOrder, BN_GetWordSize(bnOrder));
    EC_GROUP_get_order(&ec_group, bnOrder, NULL);

    // bnChildPrv = bnPrv + bnIl
    BN_Constructor(bnChildPrv, BN_GetWordSize(bnChildPrv));
    BN_mod_add(bnChildPrv, bnPrv, bnIl, bnOrder, NULL);

    { char buf[ECC_MAX_LEN_BITS*2];
        printf("-- %s: bnChildPrv: [%s]\n", methodName, BN_bn2hex(bnChildPrv, buf));
    }

    // output the child private key
    len = BN_bn2bin(bnChildPrv, prvChild);
    if(len != PRV_KEY_LEN)
		return CKR_GENERAL_ERROR;

    BN_Destructor(bnChildPrv);
    BN_Destructor(bnIl);
    BN_Destructor(bnPrv);
    BN_Destructor(bnOrder);

    // cleanup EC_GROUP structure
    EC_GROUP_free(&ec_group);

    return rv;
}

CK_RV testOpenSSLBigNum(char *out, uint32_t *outLen) 
{
    char *methodName = "testOpenSSLBigNum()";
    int len;
    int rv;

    CK_CHAR  buf[CHAIN_CODE_LEN];

    // Test Vector 2 - ext prv m
    // xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U

    char *mChain = "60499F801B896D83179A4374AEB7822AAEACEAA0DB1F85EE3E904C4DEFBD9689";
    CK_CHAR  mChainBin[CHAIN_CODE_LEN];
    char *mPriv  = "4B03D6FC340455B363F51020AD3ECCA4F0850280CF436C70C727923F6DB46C3E";
    CK_CHAR  mPrivBin[PRV_KEY_LEN];

    // Test Vector 2 - ext prvf m/0
    char *m0Chain = "F0909AFFAA7EE7ABE5DD4E100598D4DC53CD709D5A5C2CAC40E7412F232F7C9C";
    CK_CHAR  m0ChainBin[CHAIN_CODE_LEN];
    char *m0Priv  = "ABE74A98F6C7EABEE0428F53798F0AB8AA1BD37873999041703C742F15AC7E1E";
    CK_CHAR  m0PrivBin[PRV_KEY_LEN];

    BN_Declare (bn, ECC_MAX_LEN_BITS);

    printf("-- %s: entered.\n", methodName);

    // alternative methed for hex to bin - to show functions
    BN_Constructor(bn, BN_GetWordSize(bn));
    BN_hex2bn(&bn, (char*)mPriv);        
    len = BN_bn2bin(bn, mPrivBin);
    if(len != PRV_KEY_LEN) return CKR_GENERAL_ERROR;
    BN_hex2bn(&bn, mChain);        
    len = BN_bn2bin(bn, mChainBin);
    if(len != CHAIN_CODE_LEN) return CKR_GENERAL_ERROR;

    rv = DoKeyDeriveNormal(0, 
                      mPrivBin, mChainBin,
                      m0PrivBin, m0ChainBin);

    BN_hex2bn(&bn, (char*)m0Priv);        
    len = BN_bn2bin(bn, buf);
    if(len != PRV_KEY_LEN) return CKR_GENERAL_ERROR;

    // compare result to expected priv key
    if (memcmp(m0PrivBin, buf, sizeof(m0PrivBin)) != 0)
        return CKR_FUNCTION_FAILED;

    BN_hex2bn(&bn, (char*)m0Chain);        
    len = BN_bn2bin(bn, buf);
    if(len != CHAIN_CODE_LEN) return CKR_GENERAL_ERROR;

    // compare result to expected chain 
    if (memcmp(m0ChainBin, buf, sizeof(m0ChainBin)) != 0)
        return CKR_FUNCTION_FAILED;
	
	memcpy(out, m0ChainBin, sizeof(m0ChainBin));
	*outLen = sizeof(m0ChainBin);

    BN_Destructor(bn);

    return rv;
}

static void FM_HandleMessage(
    HI_MsgHandle token,            
    void *reqBuffer,            
    uint32_t reqLength) 
{
	CK_RV rv;
	char *out;
	uint32_t outLen, outLen_user;
	
	outLen_user = SVC_GetUserReplyBufLen(token);
	out = SVC_GetReplyBuffer(token, outLen_user);
	outLen = outLen_user;
	
	rv = testOpenSSLBigNum(out, &outLen);
	
	if(rv == CKR_OK && outLen < outLen_user) { 
        if(SVC_ResizeReplyBuffer(token, outLen) == NULL) rv = CKR_DEVICE_MEMORY;
    }
	
	SVC_SendReply(token, (uint32_t) rv);
}


/* FM Startup function */
FM_RV Startup(void) {
    char *methodName = "Startup()";

    FM_RV rv = 0;

    printf("-- %s: starting...\n", methodName);

	OS_GetCprovFuncTable();  // required to make EMUL link properly

    /* register handler for our new API */
     printf("-- %s: Registering dispatch function ... \n", methodName);
     rv = FMSW_RegisterDispatch(MY_FM_NUMBER, FM_HandleMessage);
     printf("-- %s: registered. Return Code = 0x%x\n", methodName, rv);

    return rv;
}

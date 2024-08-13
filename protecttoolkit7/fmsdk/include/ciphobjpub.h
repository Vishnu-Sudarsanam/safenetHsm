/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 1997-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: ciphobjpub.h
 */
/**
 * @file
 * This header describes the CipherObj C structure that is often referred
 * to as a "Cipher Object".
 *
 * There are also other types and values that are associated with Cipher
 * Objects.
 */

#ifndef CIPHOBJPUB_INCLUDED
#define CIPHOBJPUB_INCLUDED

#include "cipherr.h"

#ifdef __cplusplus
extern "C" {                /* define as 'C' functions to prevent mangling */
#endif

/** minimum MAC length for symmetric ciphers */
#define MIN_MAC 4

/** Common symmetric cipher encrypt/decrypt modes 
 *  Choose from 0 to 5 and optionally 'or in' a padding specifier.
 *
 *  Padding is the method used to extend the last bit of data up to a block 
 *  boundary so the block cipher can be applied.
 *
 *  PKCS#1 padding applies from 1 to 8 bytes where the value of each byte
 *  is the number of bytes added.
 *  NULL padding adds from 0 to 7 bytes of zero.
 *  An error is returned from Final calls if no padding is selected and there
 *  are bytes left over.
 *
 *  Algorithm block lengths are published with the GetInfo function (see
 *  CipherObjGetInfo and CipherInfo).
 */
enum _CipherEncMode {
    SYM_MODE_ECB = 0,   /* Electronic Code Book */
    SYM_MODE_CBC = 1,   /* Cipher Block Chaining */
    SYM_MODE_CFB = 2,   /* Cipher Feed Back (64 bit) */
    SYM_MODE_BCF = 3,   /* Byte Cipher Feedback (8 bit CFB) */
    SYM_MODE_OFB = 4,   /* Output feed back (64 bit) */
    SYM_MODE_BOF = 5,   /* Byte - 8 bit - Output feed back */
    SYM_MODE_WRAP = 6,  /* AES key wrap */
	SYM_MODE_WRAP_KWP = 7,   /* AES-KWP. NIST 800-38F. */
	SYM_MODE_WRAP_TKW = 8,   /* TDEA-TKW. NIST 800-38F. */
	SYM_MODE_GCM = 9,        /* AES-GCM. NIST 800-38D. */
	SYM_MODE_CCM = 0x0A,     /* AES-GCM. NIST 800-38C. */
	SYM_MODE_CTR = 0x0B,    /* Counter mode */
	SYM_MODE_GCM_OLD = 0x0C, /* AES-GCM. Legacy Version. */
    SYM_MODE_MASK= 0x0F,     /* Mask to select Mode */

    SYM_MODE_PADPKCS1 = 0x80,   /* PKCS#1 padding to be applied */
    SYM_MODE_PADCMAC  = 0x40,   /* CMAC padding to be applied */
    SYM_MODE_PADMASK  = 0xF0    /* Mask to select PAdding */
};
typedef enum _CipherEncMode CipherEncMode; 

/** temporary value for backwards compatability */
#define SYM_MODE_PAD SYM_MODE_PADPKCS1

/** Common symmetric cipher MAC (signature) modes 

    Padding is the method used to extend the last bit of data up to a block 
    boundary so the block cipher can be applied.
    NULL padding adds from 0 to 7 bytes of zero.

    The message is always padded.

    Standard CBC mode uses DES-CBC or DES3-CBC encryption.

    ANSI DES3 applies when there are double or triple length keys.
    The message is signed in Standard CBC mode with the LEFT key and the result
    is then ECB-decrypted with the MIDDLE key and finally ECB-encrypted with
    the RIGHT key.
*/
enum _CipherSignMode {
    SYM_MODE_MAC_3         = 0,  /* standard CBC with NULL or CMAC padding */
    SYM_MODE_MAC_GEN       = 1,  /* standard CBC with NULL or CMAC padding - Generic o/p length */
    SYM_MODE_MAC_X9_19     = 2,  /* X9_19 with NULL padding */
    SYM_MODE_MAC_X9_19_GEN = 3,  /* X9_19 with NULL padding - Generic o/p length */
    SYM_MODE_MAC_RETAIL    = 4,  /* RETAIL MAC with NULL padding */
    SYM_MODE_GMAC          = 5   /* GMAC */
};
typedef enum _CipherSignMode CipherSignMode ;

/** temporary value for backwards compatability */
#define SYM_MODE_MAC_X919 SYM_MODE_MAC_GEN

/* Modes used by the TR31Cipher object */
enum _TR31DeriveMode {
    TR31_MODE_DERIVE = 0,  /* Key Derive method */
    TR31_MODE_VARIANT = 1  /* Key Variant method */
};
typedef enum _TR31DeriveMode TR31DeriveMode;


/**
 *  Cipher information.
 *
 *  Allows application to determine characteristics of the cipher.
 */
struct CipherInfo {
    char name[32];              /**< null terminated ascii string e.g. "DES" */
    unsigned int minKeyLength;  /**< minimum key length (bytes) */
    unsigned int maxKeyLength;  /**< maximum key length (bytes) */
    unsigned int blockSize;     /**< cipher block size in bytes (may depend on
                                  mode) */
    unsigned int defSignatureSize;  /**< default signature size (bytes) */
    struct CipherObj * ciph;    /**< parent cipher object */
};
typedef struct CipherInfo CipherInfo;


/******************************************************************************
*
*       THE CIPHER OBJECT STRUCTURE 
*
*
    Generic Cipher object.
    Wraps cipher algorithms into a common interface.

    The object is implemented by a structure and function pointers within that
    structure. 

    There will be various implementations of these structures for both - 
        1) different cipher algorithms and 
        2) different implementations of the same cipher algorithms.

    For example there is a DES cipher object using software algorithms and a
    DES cipher object using SuperCrypt chip services (on the CSA7000).

    All cipher object implementations and algorithm versions can be managed in
    a similar way.
    This allows code to be written that requires, say, DES cipher operations
    whereby the code can be used in different architectures (where DES is done
    differently) by selecting to link against the appropriate implementation of
    the DES cipher object.

    Each algorithm version is represented by a static global cipher object
    structure (referred to here as the Cipher Class Object) which is named such
    as to represent the cipher algorithm (not the implementation).

    e.g.
        DesCipher
        TripleDesCipher
        IdeaCipher
        CastCipher
        Rc2Cipher
        Rc4Cipher

    Generally all ciphers can be managed in the same way however there is, in
    some cases, some cipher specific details. In particular the encryption and
    signature mode parameters may have a different meaning depending on the
    Cipher algorithm and different levels of support between different Class
    Object implementations of the same algorithm.  (e.g. mode parameter for RSA
    objects has a different meaning for DES objects. More mode parameter values
    are supported by the SW DES object than the CSA8000 DES object)
    
    To use cipher objects the caller -
    - Creates a new object by calling through the 'New' function ptr found in
        the appropriate Cipher Class Object.
    - The caller then invokes functions in the new structure (passing the ptr
        to the new object as the first argument).
    - When finished the caller Destroys the object by calling the 'Free'
        function in the new object.

    Each object may support the following cipher mechanisms -
        Encryption
        Decryption
        Signature Generation (e.g. MACing)
        Signature Verification (e.g. MAC Verifying)
        Signature Generation with data recovery (e.g. RSA ISO 9796)
        Signature Verification with data recovery

    Signature Generation and Verification with data recovery are mechanisms
    that include the message into the signature (so that it can be recovered
    when the signature is verified). These mechanisms are therefore single part
    operations. i.e. no update operations are allowed following the SignInit or
    VerifyInit. (Signatures with mesage recovery are only supported on RSA
    based Cipher Objects).
    
    Not all functions are supported by all object implementations - unsupported
    functions may simply return an error or may have a NULL pointer in the
    object where the function pointer should be.  Callers need to check for
    NULL pointers or ensure the object supports the function by some other
    means before calling the function entries in any object.

    The object can be in different states depending on the previous operations
    executed on it.  In particular if the object has been moded up for
    encryption (with the EncInit function) then the object may only be used for
    encryption until another Init operation is called. Therefore if you want to
    encrypt and decrypt with the same key you should either Init the same
    object twice or init two different objects. The choice depends on whether
    the operations need to be performed in parrallel or serially.

    REENTRANCY - Cipher object contexts are NOT re-entrant. Threads should
    keep objects they create private or arrange other means to protect shared
    objects.

  Example Usage
    CipherObj * p = DesCipher.new(NULL);
    p->EncInit( p, .....);
    p->EncUpdate( p, ....);
    p->EncFinal(p, ....);
    p->Free(p);
*/

/**
 * CipherObj structure
 *  Holds functions performed by cipher objects.
 */
struct CipherObj {
    /** private context data for member functions */
    void * data;

    
    /** constructor (see CipherObjNew) */
    struct CipherObj * (*New)(struct CipherObj * ctx);
    
    /** destructor (see CipherObjFree) */
    int (*Free)(struct CipherObj * ctx);

    
    /** return cipher details (see CipherObjGetInfo) */
    int (*GetInfo)(struct CipherObj * ctx, struct CipherInfo * info);

    
    /** algorithm specific function (see CipherObjConfig) */
    int (*Config)(struct CipherObj * ctx, const void * parameters,
            unsigned int length);

    /** returns some status information (see CipherObjStatus) */
    int (*Status)(struct CipherObj * ctx, void * parameters,
            unsigned int length);

    /** prepare to encrypt (see CipherObjEncInit) */
    int (*EncInit)(struct CipherObj * ctx,
        int mode,
        const void * key, unsigned int klength,
        const void * param, unsigned int plength);

    /** prepare to decrypt (see CipherObjDecInit) */
    int (*DecInit)(struct CipherObj * ctx,
        int mode,
        const void * key, unsigned int klength,
        const void * param, unsigned int plength);

    /** prepare to sign (see CipherObjSignInit) */
    int (*SignInit)(struct CipherObj * ctx,
        int mode,
        const void * key, unsigned int klength,
        const void * param, unsigned int plength);

    /** prepare to verify (see CipherObjVerifyInit) */
    int (*VerifyInit)(struct CipherObj * ctx,
        int mode,
        const void * key, unsigned int klength,
        const void * param, unsigned int plength);

    /** encrypt some more (see CipherObjEncryptUpdate) */
    int (*EncryptUpdate)(struct CipherObj * ctx,
        void * tgt, unsigned int tlength, unsigned int * plen,
        const void * src, unsigned int length);

    /** finish encrypting (see CipherObjEncryptFinal) */
    int (*EncryptFinal)(struct CipherObj * ctx,
        void * tgt, unsigned int tlength, unsigned int * plen);

    /** decrypt some more (see CipherObjDecryptUpdate) */
    int (*DecryptUpdate)(struct CipherObj * ctx,
        void * tgt, unsigned int tlength, unsigned int * plen,
        const void * src, unsigned int length);

    /** finish decrypting (see CipherObjDecryptFinal) */
    int (*DecryptFinal)(struct CipherObj * ctx,
        void * tgt, unsigned int tlength, unsigned int * plen);

    /** sign some more (see CipherObjSignUpdate) */
    int (*SignUpdate)(struct CipherObj * ctx,
        const void * src, unsigned int length);

    /** generate signature (see CipherObjSignFinal) */
    int (*SignFinal)(struct CipherObj * ctx,
        void * tgt, unsigned int tlength, unsigned int * plen);

    /** generate signature (see CipherObjSignRecover) */
    int (*SignRecover)(struct CipherObj * ctx,
        void * tgt, unsigned int tlength, unsigned int * plen,
        const void * src, unsigned int length);

    /** verify some more (see CipherObjVerifyUpdate) */
    int (*VerifyUpdate)(struct CipherObj * ctx,
        const void * src, unsigned int length);

    /** verify signature (see CipherObjVerifyFinal) */
    int (*VerifyFinal)(struct CipherObj * ctx,
        const void * sig, unsigned int slength,
        void * tgt, unsigned int tlength, unsigned int * plen);

    /** verify signature and return message (see CipherObjVerifyRecover) */
    int (*VerifyRecover)(struct CipherObj * ctx,
        const void * sig, unsigned int slength,
        void * tgt, unsigned int tlength, unsigned int * plen,
        const void * src, unsigned int length);

    /** verify signature (see CipherObjVerify) */
    int (*Verify)(struct CipherObj * ctx,
        const void * sig, unsigned int slength,
        const void * src, unsigned int length);

    
    /** parameter modifier (see CipherObjLoadParam) */
    int (*LoadParam)(struct CipherObj * ctx,
                    const void * param, 
                    unsigned int length);

    /** get parameter modifier (see CipherObjUnloadParam) */
    int (*UnloadParam)( struct CipherObj * ctx,
                        void * param, 
                        unsigned int length, 
                        unsigned int * plen);

    /** serialize internal context (see CipherObjEncodeState) */
    int (*EncodeState)(struct CipherObj * ctx, 
                        unsigned char * buf, 
                        unsigned int len, 
                        unsigned int * plen);

    /** restore internal context (see CipherObjDecodeState) */
    int (*DecodeState)(struct CipherObj * ctx, 
                        unsigned char * buf, 
                        unsigned int len);
};
typedef struct CipherObj CipherObj;


/***************************************************************
*
* Cipher Object Member Function Documentation
*
* (These functions do not actually exist - they are defined here just for the 
* sake of documentation)
*
****************************************************************/

/**
    CipherObj constructor.

    The cipher object new function initializes a CipherObj structure by
    attaching a malloced() context and loading up all the function pointers.

    The context is an opaque (to the user) block of memory used to hold the
    state of the object.

    The function pointers provide the user the ability to modify the object
    state and/or obtain cryptographic services. 

    The single parameter to this function may be a pointer to either an
    unitialized structure or NULL.  If the ptr is NULL the new structure is
    malloced() and initialized otherwise the structure pointed at by 'ctx' is
    initialized.
            
    In either case Free() must be called when the object is no longer required
    or goes out of scope (because the context will need to be freed - see
    CipherObjFree).

    For backwards compatability ctx will be treated as NULL if it points to the
    Cipher Class Object the New function is stored in. (see CipherObj for more
    details).

    @return
        pointer to newly initialized object or NULL if there is a (memory) error

    EXAMPLES
    <pre>
    {
        CipherObj o;
        DesCipher.new(&o);
        o.Free(&o);
    }
    </pre>
    or
    <pre>
    {
        CipherObj * p;
        p = DesCipher.new(NULL);
        return p;
    }
    </pre>
*/
struct CipherObj * CipherObjNew
(
        /** NULL or uninitialized structure */
        struct CipherObj * ctx
); 

/**
    CipherObj destructor

    The cipher object Free function releases resources used by the object.
    The context structure attached to the object will be freed. The object
    itself will be freed if it was malloced (see CipherObjNew for more details).

    This function erases, by overwriting with zeros, any key material in the
    context structure. 
    
    @return
        see CiphObjStat     
*/
int CipherObjFree
(
        /** pointer to object to destroy */
        struct CipherObj * ctx
); 

/**
    CipherObjGetInfo will return information about an initialized CipherObj.
    No sensitive information is returned by this function.

    (see CipherInfo for more details).

    @return
        see CiphObjStat     
*/
int CipherObjGetInfo
(
        /** IN object to query */
        struct CipherObj * ctx,
        /** OUT pointer to where to store the result (see CipherInfo) */
        struct CipherInfo * info
);

/**
    CipherObjConfig allows algorithm specific operations to be performed.
    See the specific Cipher Class implementation description for details.

    @return
        see CiphObjStat     
*/
int CipherObjConfig
(
        /** IN/OUT object to modify */
        struct CipherObj * ctx,
        /** IN object class specific data */
        const void * parameters,
        /** IN length in bytes of 'parameters' */
        unsigned int length
);

/**
    CipherObjStatus allows algorithm specific information to be returned.
    See the specific Cipher Class implementation description for details.
    (Currently no algorithm exists that uses this function and this ptr is
    NULL).

    @return
        see CiphObjStat     
*/
int CipherObjStatus
(
        /** IN object to query */
        struct CipherObj * ctx,
        /** OUT algorithm specific information */
        void * parameters,
        /** IN length of parameters buffer */
        unsigned int length
);

/**
    CipherObjEncInit configures the object to perform encryption.

    The algorithm will always verify that the mode, key length and parameter
    length is valid.
    See the particular Cipher Class implementation description for details on
    valid modes and parameters.
    Valid Key lengths are published with the GetInfo function (see
    CipherObjGetInfo and CipherInfo).

    @return
        see CiphObjStat     
*/
int CipherObjEncInit
(
        /** IN/OUT object to modify */
        struct CipherObj * ctx,
        /** algorithm specific encryption mode parameter */
        CipherEncMode mode,
        /** key value */
        const void * key,
        /** length of key value */
        unsigned int klength,
        /** algorithm parameter value */
        const void * param,
        /** length of algorithm parameter value */
        unsigned int plength
);

/**
    CipherObjDecInit configures the object to perform decryption.

    The algorithm will always verify that the mode, key length and parameter
    length is valid.
    See the particular Cipher Class implementation description for details on
    valid modes and parameters.
    Valid Key lengths are published with the GetInfo function (see
    CipherObjGetInfo and CipherInfo).

    @return
        see CiphObjStat     
*/
int CipherObjDecInit
(
        /** IN/OUT object to modify */
        struct CipherObj * ctx,
        /** algorithm specific encryption mode parameter */
        CipherEncMode mode,
        /** key value */
        const void * key,
        /** length of key value */
        unsigned int klength,
        /** algorithm parameter value */
        const void * param,
        /** length of algorithm parameter value */
        unsigned int plength
);

/**
    CipherObjSignInit configures the object to perform signature generation.

    The algorithm will always verify that the mode, key length and parameter
    length is valid.
    See the particular Cipher Class implementation description for details on
    valid modes and parameters.
    Valid Key lengths are published with the GetInfo function (see
    CipherObjGetInfo and CipherInfo).

    @return
        see CiphObjStat     
*/
int CipherObjSignInit
(
        /** IN/OUT object to modify */
        struct CipherObj * ctx,
        /** algorithm specific signature mode parameter */
        CipherSignMode mode,
        /** key value */
        const void * key,
        /** length of key value */
        unsigned int klength,
        /** algorithm parameter value */
        const void * param,
        /** length of algorithm parameter value */
        unsigned int plength
);

/**
    CipherObjVerifyInit configures the object to perform signature verifications

    The algorithm will always verify that the mode, key length and parameter
    length is valid.
    See the particular Cipher Class implementation description for details on
    valid modes and parameters.
    Valid Key lengths are published with the GetInfo function (see
    CipherObjGetInfo and CipherInfo).

    @return
        see CiphObjStat     
*/
int CipherObjVerifyInit
(
        /** IN/OUT object to modify */
        struct CipherObj * ctx,
        /** algorithm specific signature mode parameter */
        CipherSignMode mode,
        /** key value */
        const void * key,
        /** length of key value */
        unsigned int klength,
        /** algorithm parameter value */
        const void * param,
        /** length of algorithm parameter value */
        unsigned int plength
);

/**
    CipherObjEncryptUpdate uses the object to perform encryptions

    Because of buffering the output length may not equal the input length.
    If 'tgt' is NULL no operation is performed but the length that would be
    output is returned in '*plen'.

    @return
        see CiphObjStat     
*/
int CipherObjEncryptUpdate
(
        /** IN/OUT object to modify */
        struct CipherObj * ctx,
        /** OUT where to place cipher text or NULL for length prediction */
        void * tgt,
        /** IN length of tgt (only used if tgt not NULL) */
        unsigned int tlength,
        /** OUT number of bytes (actually or potentially) returned in tgt */
        unsigned int * plen,
        /** IN clear text */
        const void * src,
        /** IN length of src */
        unsigned int length
);

/**
    CipherObjEncryptFinal uses the object to finish an encryption

    Because of various buffering algorithms the output length may equal none or
    one blocks.
    If 'tgt' is NULL no operation is performed but the length that would be
    output is returned in '*plen'.

    @return
        see CiphObjStat     
*/
int CipherObjEncryptFinal
(
        /** IN/OUT object to modify */
        struct CipherObj * ctx,
        /** OUT where to place cipher text or NULL for length prediction */
        void * tgt,
        /** IN length of tgt (only used if tgt not NULL) */
        unsigned int tlength,
        /** OUT number of bytes (actually or potentially) returned in tgt */
        unsigned int * plen
);

/**
    CipherObjDecryptUpdate uses the object to perform decryptions

    Because of buffering the output length may not equal the input length.
    If 'tgt' is NULL no operation is performed but the length that would be
    output is returned in '*plen'.

    @return
        see CiphObjStat     
*/
int CipherObjDecryptUpdate
(
        /** IN/OUT object to modify */
        struct CipherObj * ctx,
        /** OUT where to place clear text or NULL for length prediction */
        void * tgt,
        /** IN length of tgt (only used if tgt not NULL) */
        unsigned int tlength,
        /** OUT number of bytes (actually or potentially) returned in tgt */
        unsigned int * plen,
        /** IN cipher text */
        const void * src,
        /** IN length of src */
        unsigned int length 
);

/**
    CipherObjDecryptFinal uses the object to finish a decryption

    Because of various buffering algorithms the output length may from zero to
    the length of one block.
    If 'tgt' is NULL no operation is performed but the length that would be
    output is returned in '*plen'.

    @return
        see CiphObjStat     
*/
int CipherObjDecryptFinal
(
        /** IN/OUT object to modify */
        struct CipherObj * ctx,       /* IN/OUT object to modify */
        /** OUT where to place clear text or NULL for length prediction */
        void * tgt,
        /** IN length of tgt (only used if tgt not NULL) */
        unsigned int tlength,
        /** OUT number of bytes (actually or potentially) returned in tgt */
        unsigned int * plen
);

/**
    CipherObjSignUpdate specifies more data for signature generation.
    Generally the data is absorbed by this function and no data is returned.
    However the internal object context state will be modified to reflect the
    new data.

    Some CipherObj implementations may be only able to accept a limited amount
    of data.

    @return
        see CiphObjStat     
*/
int CipherObjSignUpdate
(
        /** IN/OUT object to modify */
        struct CipherObj * ctx,
        /** IN data to sign */
        const void * src,
        /** IN length of src */
        unsigned int length
);

/**
    CipherObjSignFinal indicates signature generation message has finished and
    the sig should be returned.

    @return
        see CiphObjStat     
*/
int CipherObjSignFinal
(
        /** IN/OUT object to modify */
        struct CipherObj * ctx,
        /** OUT where to place signature or NULL for length prediction */ 
        void * tgt,
        /** IN length of tgt buffer (only used if tgt not NULL) */
        unsigned int tlength,
        /** OUT number of bytes (actually or potentially) returned in tgt */
        unsigned int * plen
);

/**
    CipherObjSignRecover performs a signature generation (with message
    recovery) operation.
    The message to be signed is passed in and the signature is generated and
    returned.

    @return
        see CiphObjStat     
*/
int CipherObjSignRecover
(
        /** IN/OUT object to modify */
        struct CipherObj * ctx,
        /** OUT where to place signature or NULL for length prediction */ 
        void * sig,
        /** IN length of sig buffer (only used if sig not NULL) */
        unsigned int slength,
        /** OUT number of bytes (actually or potentially) returned in tgt */
        unsigned int * plen,
        /** IN message to sign */
        const void * src,
        /** IN length of src (in bytes) */
        unsigned int length
);

/**
    CipherObjVerifyUpdate specifies more data for signature verification.
    Generally the data is absorbed by this function and no data is returned.
    However the internal object context state will be modified to reflect the
    new data.

    Some CipherObj implementations may be only able to accept a limited amount
    of data.

    @return
        see CiphObjStat     
*/
int CipherObjVerifyUpdate
(
        /** IN/OUT object to modify */
        struct CipherObj * ctx,
        /** IN message part */
        const void * src,
        /** IN length (in bytes) of src */
        unsigned int length
);

/**
    CipherObjVerifyFinal performs signature verification operation.
    The message to be signed must have been passed in in previous
    CipherObjVerifyUpdate calls.
    The signature is generated and returned in 'tgt'.
    The signature to compare against is passed in in 'sig'. Compare errors are
    returned as a return error code.

    @return
        see CiphObjStat     
*/
int CipherObjVerifyFinal
(
        /** IN/OUT object to modify */
        struct CipherObj * ctx,
        /** IN signature to verify against */
        const void * sig,
        /** IN length of sig (bytes) */
        unsigned int slength,
        /** OUT correct signature as calculated by verify operation!! */
        void * tgt,
        /** IN length (in bytes) of tgt */
        unsigned int tlength,
        /** OUT number of bytes (actually or potentially) returned in tgt */
        unsigned int * plen
);

/**
    CipherObjVerifyRecover performs signature verification operations with
    message recovery.
    This is a single part operation - no sign updates should have been used.
    This mechanism only supported by RSA ciphers.
    
    The message is recovered from the signature and returned in 'tgt'.
    Compare errors are returned as a return error code.

    @return
        see CiphObjStat     
*/
int CipherObjVerifyRecover
(
        /** IN/OUT object to modify */
        struct CipherObj * ctx,
        /** IN signature cryptogram (message comes from here) */
        const void * sig,
        /** IN length of sig (bytes) */
        unsigned int slength,
        /** OUT recovered message (or NULL for length prediction) */
        void * tgt,
        /** IN length (in bytes) of tgt */ 
        unsigned int tlength,
        /** OUT number of bytes (actually or potentially) returned in tgt */
        unsigned int * plen,
        /** IN should be NULL */
        const void * src,
        /** IN unused */
        unsigned int length
);

/**
    CipherObjVerify performs a single part signature verification operation.
    This function not supported on Symmetrical Cipher objects.
    A message (probably a hash value) is compared to the message recovered from
    the sig cryptogram.
        
    Compare errors are returned as a return error code.

    @return
        see CiphObjStat     
*/

int CipherObjVerify
(
        /** IN/OUT object to modify */
        struct CipherObj * ctx,
        /** IN signature cryptogram */
        const void * sig,
        /** IN length of sig */
        unsigned int slength,
        /** IN signature value to compare to value recovered from cryptogram */
        const void * src,
        /** IN length of src */
        unsigned int length
);

/**
    CipherObjLoadParam directly modifies a Cipher Object state.
    This function is mainly used by Symmetrical Cipher objects to define the
    IVR.
    See the particular Cipher Class implementation description for details on
    valid parameter types and their values.   
    
    see CipherObjUnloadParam

    @return
        see CiphObjStat
*/    
int CipherObjLoadParam
(
        /** IN/OUT object to modify */
        struct CipherObj * ctx,
        /** IN cipher class specific information */
        const void * param,
        /** IN length (in bytes) of param */
        unsigned int length
);

/**
    CipherObjUnloadParam queries a Cipher Object state and return certain
    information.
    This function is mainly used by Symmetrical Cipher objects to return the
    current IVR.
    See the particular Cipher Class implementation description for details on
    valid parameter types and their values.   

    see CipherObjLoadParam

    @return
        see CiphObjStat
*/
int CipherObjUnloadParam
(
        /** IN object to query */
        struct CipherObj * ctx,
        /** OUT cipher class specific information (depends on pType) */
        void * param,
        /** IN length of param (in bytes) */
        unsigned int length,
        /** OUT where to store the number of bytes returned in param (may be
         * NULL)
         */
        unsigned int * plen
);

/**
    CipherObjEncodeState serializes a Cipher Object state.
    i.e. information about the current state of the object sufficient to
    restore its state is returned in the callers buffer.

    See CipherObjDecodeState

    @return
        see CiphObjStat
*/
int CipherObjEncodeState
(
        /** IN object to encode */
        struct CipherObj * ctx,
        /** OUT where to place the result (may be NULL for length prediction) */
        unsigned char * buf,
        /** IN length (in bytes) of buf */
        unsigned int len,
        /** OUT number of bytes (actually or potentially) returned in buf */
        unsigned int * plen
);

/**
    CipherObjDecodeState de-serializes a Cipher Object state.
    i.e. the state of the object is restored to the state it was when the
    object was serialized.

    See CipherObjEncodeState
    
    @return
        see CiphObjStat
*/
int CipherObjDecodeState
(
        /** IN/OUT object to restore */
        struct CipherObj * ctx,
        /** IN buffer containing state to restore */
        unsigned char * buf, 
        /** IN number of bytes in buf */
        unsigned int len
);


#ifdef __cplusplus
}
#endif

#endif /* CIPHOBJPUB_INCLUDED */

/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 1997-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: hashobjpub.h
 */

/**
 *	@file
 *	Generic Hash object.
 *	Wraps hashing algorithms into a common interface.
 */

#ifndef HASHOBJPUB_INCLUDED
#define HASHOBJPUB_INCLUDED

#include "cipherr.h"

#ifdef __cplusplus
    extern "C" {            /* define as 'C' functions to prevent mangling */
#endif

/**
**	Hash information.
**
**	Allows application to determine characteristics of the digest algorithm.
*/
struct HashInfo {
	char name[32];	/**< null terminated ascii string e.g. "SHA-1" */
	unsigned int blockLength;	/**< optimal hash block size */
	unsigned int hashLength;	/**< size of hash value */
	struct HashObj * hobj; /**< version 1 */
};
typedef struct HashInfo HashInfo;

/**
**	The hash object includes a context pointer and member functions.
*/
struct HashObj {
	void * data;	/**< private data for Hash algorithm */

	/** constructor */ 
	struct HashObj * (*New)(struct HashObj * ctx);
    /** destructor */
	int (*Free)(struct HashObj * ctx);

	/** prepare to hash  */
	int (*Init)(struct HashObj * ctx);
    /** hash some more data */
	int (*Update)(struct HashObj * ctx, const void * buf, unsigned int length);
    /** finish hashing */
	int (*Final)(struct HashObj * ctx,
		unsigned char * hashVal, unsigned int length, unsigned int * plength);
    /** return hash details */
	int (*GetInfo)(struct HashObj * ctx, struct HashInfo * hinfo);

	/* Hash specific functions */
	/** Loads the internal parameters of the hash object from a byte array. If
	   the internal data contains integers, the input byte array should contain
	   big endian values for these integers. */
	int (*LoadParam)(struct HashObj * ctx, const unsigned char * parameters,
            unsigned int paramlen);

	/** Writes the internal parameters of the hash object to a byte array. If
	   the internal data contains integers, the output byte array will contain
	   big endian values for these integers. */
	int (*UnloadParam)(struct HashObj * ctx, unsigned char * parameters,
            unsigned int paramlen, unsigned int * plen);

	/** encoder to save hash state */
	int (*EncodeState)(struct HashObj * ctx, unsigned char * buf,
            unsigned int len, unsigned int * plen);
    /** decoder to restore hash state */
	int (*DecodeState)(struct HashObj * ctx, unsigned char * buf,
            unsigned int len);
};
typedef struct HashObj HashObj;


/***************************************************************
*
* Hash Object Member Function Documentation
*
* (These functions do not actually exist - they are defined here just for the 
* sake of documentation)
*
****************************************************************/

/** 
    HashObj constructor.

    The hash object new function initializes a HashObj structure by
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
    HashObjFree).

    For backwards compatability ctx will be treated as NULL if it points to the
    Hash Class Object the New function is stored in. (see CipherObj for more
    details).

    RETURN -
        pointer to newly initialized object or NULL if there is a (memory) error

    EXAMPLES
    <pre>
    {
        HashObj o;
        Sha1.new(&o);
        o.Free(&o);
    }
    </pre>
    or
    <pre>
    {
        HashObj * p;
        p = Sha1.new(NULL);
        return p;
    }
    </pre>

    @return
        Pointer to initialised structure
*/
struct HashObj * HashObjNew
(
    /** NULL or uninitialised structure */
    struct HashObj * ctx
);

/** 
    HashObj destructor

    The hash object Free function releases resources used by the object.
    The context structure attached to the object will be freed. The object
    itself will be freed if it was malloced (see HashObjNew for more details).

    This function erases, by overwriting with zeros, any key material in the
    context structure. 
    
    @return 
        see CiphObjStat
*/
int HashObjFree
(
        /** pointer to object to destroy */
        struct HashObj * ctx
); 

/** 

    HashObj copy constructor 

    The hash object copy function creates or initializes a HashObj
    structure using an existing structure as a template.

    @return
        pointer to new or newly initialized object or NULL if there is a
        (memory) error

    EXAMPLES
    <pre>
        extern HashObj *p;

        HashObj o;
        Sha1.copy(p, &o);
        o.Update(&o, ....);
        o.Free(&o);
    </pre>
*/
struct HashObj * HashObjCopy
(
        /** original HashObj structure */
        struct HashObj * src,

        /** pointer to a HashObj structure to initialize (follows same
         * convention as HashObjNew)
         */
        struct HashObj * tgt
);

/** 
    HashObjInit configures the object to perform a hash operation.

    @return
        see CiphObjStat     
*/
int HashObjInit
(
        /** IN/OUT object to modify */
        struct HashObj * ctx
);

/** 
    HashObjUpdate uses the object to perform a hash operation

    The data passed in src is passed throught the hash algorithm

    @return
        see CiphObjStat     
*/
int HashObjUpdate
(
        /** IN/OUT object to modify */
        struct HashObj * ctx,
        
        /** IN message to hash */
        const void * src,

        /** IN length of message */
        unsigned int length
);

/** 
    HashObjFinal uses the object to finish a hash operation

    If 'tgt' is NULL no operation is performed but the length that would be
    output is returned in '*plen'.

    @return
        see CiphObjStat
*/
int HashObjFinal
(
        /** IN/OUT object to modify */
        struct HashObj * ctx,
        /** OUT where to place hash or NULL for length prediction */
        void * tgt,
        /** IN length of tgt (only used if tgt not NULL) */
        unsigned int tlength,
        /** OUT number of bytes (actually or potentially) returned in tgt */
        unsigned int * plen
);

/** 
    HashObjGetInfo will return information about an initialized HashObj.
    No sensitive information is returned by this function.

    (see HashInfo for more details).

    @return
        see CiphObjStat     
*/
int HashObjGetInfo
(
        /** IN object to query */
        struct HashObj * ctx,
        /** OUT pointer to where to store the result (see HashInfo) */
        struct HashInfo * info
);

/** 
    HashObjLoadParam directly modifies a Hash Object state.

    See the particular Hash Class implementation description for details on
    valid parameter types and their values.   
    
    see HashObjUnloadParam

    @return
        see CiphObjStat
*/
int HashObjLoadParam
(
        /** IN/OUT object to modify */
        struct HashObj * ctx,
        /** IN hash class specific information */
        const void * param,
        /** IN length (in bytes) of param */
        unsigned int length
);

/** 
    HashObjUnloadParam queries a Hash Object state and return certain
    information.

    See the particular Hash Class implementation description for details on
    valid parameter types and their values.   
    
    see HashObjLoadParam

    @return
        see CiphObjStat
  */
int HashObjUnloadParam
(
        /** IN object to query */
        struct HashObj * ctx,
        /** OUT hash class specific information (depends on pType) */
        void * param,
        /** IN length of param (in bytes) */
        unsigned int length,
        /** OUT where to store the number of bytes returned in param (may be
         * NULL)
         */
        unsigned int * plen
);

/**
    HashObjEncodeState serializes a Hash Object state.
    i.e. information about the current state of the object sufficient to
    restore its state is returned in the callers buffer.

    See HashObjDecodeState
    
    @return
        see CiphObjStat     
*/
int HashObjEncodeState
(
        /** IN object to encode */
        struct HashObj * ctx,
        /** OUT where to place the result (may be NULL for length prediction) */
        unsigned char * buf,
        /** IN length (in bytes) of buf */
        unsigned int len,
        /** OUT number of bytes (actually or potentially) returned in buf */
        unsigned int * plen
);

/** 
    HashObjDecodeState de-serializes a Hash Object state.
    i.e. the state of the object is restored to the state it was when the
    object was serialized.

    See HashObjEncodeState

    @return  
        see CiphObjStat     
*/
int HashObjDecodeState
(
        /** IN/OUT object to restore */
        struct HashObj * ctx,
        /** IN buffer containing state to restore */
        unsigned char * buf, 
        /** IN number of bytes in buf */
        unsigned int len
);

#ifdef __cplusplus
}
#endif

#endif /* HASHOBJPUB_INCLUDED */

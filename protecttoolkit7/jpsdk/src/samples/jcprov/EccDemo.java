import java.util.Arrays;
import safenet.jcprov.*;
import safenet.jcprov.constants.*;
import safenet.jcprov.params.*;
import java.nio.charset.*;

/**
 * The class demonstrates the use of generatation and sign/verify mechanisms
 * for eliptic curve key pairs.
 */
public class EccDemo
{
    /** easy access to System.out.println */
    static public void println(String s)
    {
        System.out.println(s);
    }

    /** display runtime usage of the class */
    public static void usage()
    {
        println("java ...EccDemo <-g> <-k> -n<keyname>");
        println("");
        println("-g            Generate key pair only.");
        println("-k            Perform ECDH Key Derive Known Answer Test only.");
        println("-n<keyname>   Name of key pair to create or sign/verify with");
        println("");

        System.exit(1);
    }

	private static CK_MECHANISM_TYPE shaMech = CKM.SHA512;//SHA1, sha244, SHA256, SHA384, SHA512
	private static CK_MECHANISM_TYPE ecdsaShaMech = CKM.ECDSA_SHA512;//ECDSA_SHA1, ECDSA_SHA224, ECDSA_SHA256, ECDSA_SHA384, ECDSA_SHA512

    public static void main(String args[])
    {
        CK_SESSION_HANDLE hSession = new CK_SESSION_HANDLE();
        long slotId = 0;

        CK_OBJECT_HANDLE hPublicKey = new CK_OBJECT_HANDLE();
        CK_OBJECT_HANDLE hPrivateKey = new CK_OBJECT_HANDLE();

        boolean bKeyDer = false;
        boolean bKeyGen = false;
        String keyName = "";

        String data = new String("This sentence is 36 characters long.");

        /*
         * Process cmd line.
         */
        for (int i = 0; i < args.length; ++i)
        {
            if (args[i].equalsIgnoreCase("-k"))
            {
				println("Performing Key Derive Test");
                bKeyDer = true;
            } else if (args[i].equalsIgnoreCase("-g"))
            {
				println("Generating Key Pair");
                bKeyGen = true;
            }
            else if (args[i].equalsIgnoreCase("-n"))
            {
                if (++i >= args.length) usage();

                keyName = args[i];
            }
            else
            {
				println("Unknown parameter");
                usage();
            }
        }

        if (!(bKeyDer || bKeyGen) && keyName.equalsIgnoreCase("")) usage();

        try
        {
            /*
             * Initialize cryptoki.
             */
            CryptokiEx.C_Initialize(null);

            /*
             * Open a session
             */
            CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION, null, null,
                                     hSession);

            /*
             * Determine what the user wants to do.
             */
            if (bKeyDer)
            {
                /* User wants to perform Derive KAT */
                EccKeyDeriveTest(hSession);
				println("Derive Test passed");

                System.exit(0);
            }

            if (bKeyGen)
            {
                /* User just wants to generate keys */
                generateEccKeyPair(hSession, keyName, hPublicKey, hPrivateKey);
                println("Key Derive generated successfully");

                System.exit(0);
            }

            /*
             * User wants to perform sign/verify operations
             */
            String shaMechStr = shaMech.toString();
            int shaMechInd = shaMechStr.indexOf("@") + 1;
            String ecdsaShaMechStr = ecdsaShaMech.toString();
            int ecdsaShaMechInd = ecdsaShaMechStr.indexOf("@") + 1;
            //Tested Mechnisms:
            println("Tested Mechanisms: " + shaMechStr.substring(shaMechInd)  + ", " + ecdsaShaMechStr.substring(ecdsaShaMechInd));
            /* find the public and private keys to use */
            hPublicKey = findKey(hSession, CKO.PUBLIC_KEY, CKK.EC, keyName);
            hPrivateKey = findKey(hSession, CKO.PRIVATE_KEY, CKK.EC, keyName);

            /* hash the data */
            System.out.print("Generating hash of data                 : ");
            byte[] hash = shaHashData(hSession, data.getBytes(StandardCharsets.US_ASCII), data.length());
            println("Done");

            /* generate two signatures */
            System.out.print("Generating signature of hash            : ");
            byte[] sign1 = eccSign(hSession, hPrivateKey, hash, hash.length);
            println("Done");

            System.out.print("Generating hashed signature of data     : ");
            byte[] sign2 = eccHashSign(hSession, hPrivateKey, data.getBytes(StandardCharsets.US_ASCII), data.length());
            println("Done");
            println("");

            /* verify the signatures */
            System.out.print("Verifying signature of hash             : ");
            eccVerify(hSession, hPublicKey, hash, hash.length, sign1, sign1.length);
            System.out.println("Valid");

            System.out.print("Verifying hashed signature of data      : ");
            eccHashVerify(hSession, hPublicKey, data.getBytes(StandardCharsets.US_ASCII), data.length(), sign2, sign2.length);
            System.out.println("Valid");

            /* cross-check signatures */
            System.out.print("Cross-checking signature of hash        : ");
            eccHashVerify(hSession, hPublicKey, data.getBytes(StandardCharsets.US_ASCII), data.length(), sign1, sign1.length);
            System.out.println("Valid");

            System.out.print("Cross-checking hashed signature of data : ");
            eccVerify(hSession, hPublicKey, hash, hash.length, sign2, sign2.length);
            System.out.println("Valid");
        }
        catch (CKR_Exception ex)
        {
            /*
             * A Cryptoki related exception was thrown
             */
            ex.printStackTrace();
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
        finally
        {
            /*
             * Close the session.
             *
             * Note that we are not using CryptokiEx and we are not checking the
             * return value. This is because if we did not log in then an error
             * will be reported - and we don't really care because we are shutting down.
             */
            Cryptoki.C_CloseSession(hSession);

            /*
             * All done with Cryptoki
             *
             * Note that we are not using CryptokiEx.
             */
             Cryptoki.C_Finalize(null);
        }


    }

    /**
     * Perform ECDH Key Derive Test.
     *
     * @param hSession
     *  handle to an open session
     */
    public static void EccKeyDeriveTest(CK_SESSION_HANDLE hSession)
    {

        byte[] curve = getDerEncodedNamedCurve("prime192v1");

        byte[] priKey = {
			(byte)0x0A, (byte)0xD4, (byte)0x79, (byte)0x17, (byte)0x9C, (byte)0xE4, (byte)0x7E, (byte)0xB7, 
			(byte)0xF7, (byte)0x45, (byte)0xF6, (byte)0x63, (byte)0xB8, (byte)0x17, (byte)0x80, (byte)0xD1, 
			(byte)0xF4, (byte)0x0F, (byte)0x13, (byte)0x24, (byte)0xF5, (byte)0x30, (byte)0x85, (byte)0x37
		};

        byte[] pubKey = {
			(byte)0x04, (byte)0x31, (byte)0x04, (byte)0xDE, (byte)0x3E, (byte)0xE1, (byte)0x44, (byte)0x14, 
			(byte)0xB6, (byte)0xB5, (byte)0x59, (byte)0x84, (byte)0xD3, (byte)0x06, (byte)0xC5, (byte)0x30, 
			(byte)0xCA, (byte)0xC6, (byte)0x08, (byte)0x97, (byte)0x05, (byte)0x13, (byte)0xBB, (byte)0x83, 
			(byte)0x4E, (byte)0x48, (byte)0x09, (byte)0xC8, (byte)0x70, (byte)0xC7, (byte)0xFA, (byte)0xBD,
			(byte)0x6B, (byte)0x94, (byte)0xB8, (byte)0x8D, (byte)0x65, (byte)0xC5, (byte)0x1E, (byte)0x11, 
			(byte)0x80, (byte)0xA5, (byte)0xF9, (byte)0xF6, (byte)0xE0, (byte)0xD8, (byte)0xAE, (byte)0x5B, 
			(byte)0x04, (byte)0x26, (byte)0x8B
		};

		byte[] SharedData    = "Our shared data".getBytes(StandardCharsets.US_ASCII);

		byte[] expectedResult = { 
			(byte)0x14, (byte)0x44, (byte)0xD1, (byte)0x46, (byte)0x5F, (byte)0x74,
			(byte)0xFA, (byte)0x03, (byte)0xB9, (byte)0x57, (byte)0x98, (byte)0x60,
			(byte)0x30, (byte)0xEB, (byte)0x20, (byte)0x89, (byte)0x4F, (byte)0xA5,
			(byte)0x62, (byte)0xA0,
		};

        /*
         * Setup the template for the private key.
         */
        CK_ATTRIBUTE[] baseKeyTpl =
        {
            new CK_ATTRIBUTE(CKA.CLASS,     CKO.PRIVATE_KEY),
            new CK_ATTRIBUTE(CKA.TOKEN,     CK_BBOOL.FALSE),
            new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.KEY_TYPE,  CKK.EC),
            new CK_ATTRIBUTE(CKA.DERIVE,    CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.EC_PARAMS, curve),
            new CK_ATTRIBUTE(CKA.VALUE,     priKey),
        };

		CK_OBJECT_HANDLE hBaseKey = new CK_OBJECT_HANDLE();
		CK_OBJECT_HANDLE hNewKey  = new CK_OBJECT_HANDLE();

		CK_ECDH1_DERIVE_PARAMS params = 
				new CK_ECDH1_DERIVE_PARAMS(KDF.CKD_SHA1_KDF, 
											SharedData.length,
											SharedData,
											pubKey.length,
											pubKey
										);

        CK_MECHANISM mech = new CK_MECHANISM(CKM.ECDH1_DERIVE, params);

		/* create the base key */
		CryptokiEx.C_CreateObject(hSession, baseKeyTpl, baseKeyTpl.length, hBaseKey);

		/* Template of the derived object */
        CK_ATTRIBUTE[] newObjTpl =
        {
            new CK_ATTRIBUTE(CKA.CLASS,     CKO.SECRET_KEY),
            new CK_ATTRIBUTE(CKA.TOKEN,     CK_BBOOL.FALSE),
            new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.FALSE),
            new CK_ATTRIBUTE(CKA.KEY_TYPE,  CKK.GENERIC_SECRET),
            new CK_ATTRIBUTE(CKA.VALUE_LEN, expectedResult.length),
        };

		/* perform the derive */
		CryptokiEx.C_DeriveKey(hSession, mech, hBaseKey, newObjTpl, newObjTpl.length, hNewKey);

		/* because we made the new key non sensitive we will read the value directly */
		CK_ATTRIBUTE[] valAttr = { 
			new CK_ATTRIBUTE(CKA.VALUE, new byte[expectedResult.length]) 
		};

		CryptokiEx.C_GetAttributeValue(hSession, hNewKey, valAttr, valAttr.length);

        /* clean up */
        CryptokiEx.C_DestroyObject(hSession, hBaseKey);
        CryptokiEx.C_DestroyObject(hSession, hNewKey);

		/* Verify result */
		if ( !Arrays.equals((byte[])valAttr[0].pValue, expectedResult) )
			throw new CKR_Exception("ECDH1 DERIVE Result Error", CKR.FUNCTION_FAILED);
    }

    /**
     * Generate an asymetric key pair.
     *
     * @param hSession
     *  handle to an open session
     *
     * @param keyName
     *  name (label) to give the generated keys
     *
     * @param hPublicKey
     *  upon completion, the handle of the generated public key
     *
     * @param hPrivateKey
     *  upon completion, the handle of the generated private key
     */
    public static void generateEccKeyPair(CK_SESSION_HANDLE hSession,
                                          String keyName,
                                          CK_OBJECT_HANDLE hPublicKey,
                                          CK_OBJECT_HANDLE hPrivateKey)
    {
        CK_MECHANISM keyGenMech = new CK_MECHANISM(CKM.EC_KEY_PAIR_GEN);

        /*
         * Setup the curve that we are going to generate the key pair on.
         * Possible values are:
         *     c2tnb191v1
		 *     c2tnb191v1e	
         *     prime192v1
         */
        byte[] curve = getDerEncodedNamedCurve("prime192v1");

        /*
         * Setup the template for the public key.
         */
        CK_ATTRIBUTE[] publicTemplate =
        {
            new CK_ATTRIBUTE(CKA.CLASS,     CKO.PUBLIC_KEY),
            new CK_ATTRIBUTE(CKA.TOKEN,     CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.FALSE),
            new CK_ATTRIBUTE(CKA.KEY_TYPE,  CKK.EC),
            new CK_ATTRIBUTE(CKA.LABEL,     keyName.getBytes(StandardCharsets.US_ASCII)),
            new CK_ATTRIBUTE(CKA.VERIFY,    CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.EC_PARAMS, curve),
        };

        /*
         * Setup the template for the private key.
         */
        CK_ATTRIBUTE[] privateTemplate =
        {
            new CK_ATTRIBUTE(CKA.CLASS,     CKO.PRIVATE_KEY),
            new CK_ATTRIBUTE(CKA.TOKEN,     CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.FALSE),
            new CK_ATTRIBUTE(CKA.KEY_TYPE,  CKK.EC),
            new CK_ATTRIBUTE(CKA.LABEL,     keyName.getBytes(StandardCharsets.US_ASCII)),
            new CK_ATTRIBUTE(CKA.SIGN,      CK_BBOOL.TRUE)
        };

        CryptokiEx.C_GenerateKeyPair(hSession, keyGenMech,
                                     publicTemplate, publicTemplate.length,
                                     privateTemplate, privateTemplate.length,
                                     hPublicKey, hPrivateKey);
    }

    /**
     * Locate the specified key.
     *
     * @param session
     *  handle to an open session
     *
     * @param keyClass
     *  {@link safenet.jcprov.constants.CKO} class of the key to locate
     *
     * @param keyName
     *  name (label) of the key to locate
     *
     */
    static CK_OBJECT_HANDLE findKey(CK_SESSION_HANDLE session,
                                    CK_OBJECT_CLASS keyClass,
                                    CK_KEY_TYPE keyType,
                                    String keyName)
    {
        /* array of one object handles */
        CK_OBJECT_HANDLE[] hObjects = {new CK_OBJECT_HANDLE()};

        /* to receive the number of objects located */
        LongRef objectCount = new LongRef();

        /* setup the template of the object to search for */
        CK_ATTRIBUTE[] template =
        {
            new CK_ATTRIBUTE(CKA.CLASS,     keyClass),
            new CK_ATTRIBUTE(CKA.KEY_TYPE,  keyType),
            new CK_ATTRIBUTE(CKA.TOKEN,     CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.LABEL,     keyName.getBytes(StandardCharsets.US_ASCII))
        };

        CryptokiEx.C_FindObjectsInit(session, template, template.length);

        CryptokiEx.C_FindObjects(session, hObjects, hObjects.length, objectCount);

        CryptokiEx.C_FindObjectsFinal(session);

        if (objectCount.value == 1)
        {
            /* return the handle of the located object */
            return hObjects[0];
        }
        else
        {
            /* return an object handle which is invalid */
            return new CK_OBJECT_HANDLE();
        }
    }

    /**
     * Generate a hash on some data.
     *
     * @param hSession
     *     handle of an open session.
     *
     * @param data
     *     data to hash from
     *
     * @param dataLen
     *     length of the data to hash
     */
    static byte[] shaHashData(CK_SESSION_HANDLE hSession,
                               byte[] data,
                               long dataLen)
    {
        CK_MECHANISM hashMech = new CK_MECHANISM(shaMech);

        byte[] hash = null;
        LongRef hashLen = new LongRef();

        /* start the digest operation */
        CryptokiEx.C_DigestInit(hSession, hashMech);

        /* determine how long the hash will be */
        CryptokiEx.C_Digest(hSession, data, dataLen, null, hashLen);

        /* allocate space for the hash */
        hash = new byte[(int)hashLen.value];

        /* generate the hash */
        CryptokiEx.C_Digest(hSession, data, dataLen, hash, hashLen);

        return hash;
    }

    /**
     * Sign a hash using the ECDSA mechanism.
     *
     * @param hSession
     *     handle to an open session
     *
     * @param hPrivateKey
     *     handle of the private key to sign with
     *
     * @param hash
     *     the hash value to generate the signature from
     *
     * @param hashLen
     *     the length of the hash
     */
    static byte[] eccSign(CK_SESSION_HANDLE hSession,
                          CK_OBJECT_HANDLE hPrivateKey,
                          byte[] hash,
                          long hashLen)
    {
        CK_MECHANISM signMech = new CK_MECHANISM(CKM.ECDSA);

        byte[] signature = null;
        LongRef signLen = new LongRef();

        /* start the sign operation */
        CryptokiEx.C_SignInit(hSession, signMech, hPrivateKey);

        /* determine the length of the signature */
        CryptokiEx.C_Sign(hSession, hash, hashLen, null, signLen);

        /* allocate space for the signature */
        signature = new byte[(int)signLen.value];

        /* do the sign */
        CryptokiEx.C_Sign(hSession, hash, hashLen, signature, signLen);

        return signature;
    }

    /**
     * Hash and sign some raw data using a hashing mechanism.
     *
     * @param hSession
     *     handle to an open session
     *
     * @param hPrivateKey
     *     handle to the private key to sign with
     *
     * @param data
     *     the data to hash and sign
     *
     * @param dataLen
     *     the length of the data
     */
    static byte[] eccHashSign(CK_SESSION_HANDLE hSession,
                              CK_OBJECT_HANDLE hPrivateKey,
                              byte[] data,
                              long dataLen)
    {
        CK_MECHANISM signMech = new CK_MECHANISM(ecdsaShaMech);

        byte[] signature = null;
        LongRef signLen = new LongRef();

        /* start the sign operation */
        CryptokiEx.C_SignInit(hSession, signMech, hPrivateKey);

        /* determine the length of the signature */
        CryptokiEx.C_Sign(hSession, data, dataLen, null, signLen);

        /* allocate space for the signature */
        signature = new byte[(int)signLen.value];

        /* do the sign */
        CryptokiEx.C_Sign(hSession, data, dataLen, signature, signLen);

        return signature;
    }

    /**
     * Verify a signature of a hash using the ECDSA mechanism.
     *
     * @param hSession
     *     handle to an open session
     *
     * @param hPublicKey
     *     public key to verify with
     *
     * @param hash
     *     hash to verify against
     *
     * @param hashLen
     *     length of the hash to verify against
     *
     * @param signature
     *     signature of the hash to verify against
     *
     * @param signatureLen
     *     length of the signature
     */
    static void eccVerify(CK_SESSION_HANDLE hSession,
                          CK_OBJECT_HANDLE hPublicKey,
                          byte[] hash,
                          long hashLen,
                          byte[] signature,
                          long signatureLen)
    {
        CK_MECHANISM verifyMech = new CK_MECHANISM(CKM.ECDSA);

        /* start the verify operation */
        CryptokiEx.C_VerifyInit(hSession, verifyMech, hPublicKey);

        /* verify the signature against the hash */
        CryptokiEx.C_Verify(hSession, hash, hashLen, signature, signatureLen);
    }

    /**
     * Verify a hased signature of some raw data using the ECDSA_SHA1 mechanism.
     *
     * @param hSession
     *     handle to an open session
     *
     * @param hPublicKey
     *     public key to verify with
     *
     * @param data
     *     data to verify against
     *
     * @param dataLen
     *     length of the data to verify against
     *
     * @param signature
     *     hashed signature of the data to verify against
     *
     * @param signatureLen
     *     length of the signature
     */
    static void eccHashVerify(CK_SESSION_HANDLE hSession,
                              CK_OBJECT_HANDLE hPublicKey,
                              byte[] data,
                              long dataLen,
                              byte[] signature,
                              long signatureLen)
    {
        CK_MECHANISM verifyMech = new CK_MECHANISM(ecdsaShaMech);

        /* start the verify operation */
        CryptokiEx.C_VerifyInit(hSession, verifyMech, hPublicKey);

        /* verify the signature against the hash */
        CryptokiEx.C_Verify(hSession, data, dataLen, signature, signatureLen);
    }


    /**
     * Get a specified named curve.
     *
     * @param pszCurveName
     *     Name of the curve to get.
     */
    private static byte[] getDerEncodedNamedCurve(String pszCurveName)
    {
        if (pszCurveName.equalsIgnoreCase("c2tnb191v1"))
        {
            return s_c2tnb191v1;
        }
//
		else if (pszCurveName.equalsIgnoreCase("c2tnb191v1e"))
        {
            return s_c2tnb191v1e;
        }
//
        else if (pszCurveName.equalsIgnoreCase("prime192v1"))
        {
            return s_prime192v1;
        }
        else
        {
            return null;
        }
    }

    private static final byte s_c2tnb191v1[] =
    {
        (byte)0x06, (byte)0x08, (byte)0x2A, (byte)0x86,
        (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x03,
        (byte)0x00, (byte)0x05
    };
//js
    private static final byte s_c2tnb191v1e[] =
    {
        (byte)0x06, (byte)0x08, (byte)0x2A, (byte)0x86,
        (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x03,
        (byte)0x00, (byte)0x15
    };
//sj
    private static final byte s_prime192v1[] =
    {
        (byte)0x06, (byte)0x08, (byte)0x2A, (byte)0x86,
        (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x03,
        (byte)0x01, (byte)0x01
    };
}

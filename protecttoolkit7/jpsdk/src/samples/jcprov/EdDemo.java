import java.util.Arrays;
import safenet.jcprov.*;
import safenet.jcprov.constants.*;
import safenet.jcprov.params.*;
import java.nio.charset.*;

/**
 * The class demonstrates the use of generatation and sign/verify mechanisms
 * for Edward and Montgomery curves.
 */
public class EdDemo {
    /** easy access to System.out.println */
    static public void println(String s) {
        System.out.println(s);
    }

    //Used for EdDSA
    private static String[] edCurves = {
        "ed25519",
        "ed448",
    };

    //Used for ECDH
    private static String[] montCurves = {
        "curve25519",
        "curve448",
    };

    /** display runtime usage of the class */
    public static void usage() {
        println("java ... EdDemo [<-g>  [-C <curve>]] [<-k>] [-p] -n <keyname>");
        println("");
        println("-p            Perform EdDSAph instead of EdDSA (Edward curves)");
        println("-k            Perform ECDH Key Derive Test instead. (Montgomery curves)");
        println("-n <keyname>  Name of key pair to create or sign/verify with");
        println("-g            Generate key pair.");
        println("-C <curve>    Name of curve");
        println("Available curves are:");
        println("Edwards (EdDSA):");
        for(String l:edCurves) println("    "+l);
        println("Montgomery (ECDH):");
        for(String l:montCurves) println("    "+l);
        println("");

        System.exit(1);
    }

    public static void main(String args[]) {
        CK_SESSION_HANDLE hSession = new CK_SESSION_HANDLE();
        long slotId = 0;
        CK_KEY_TYPE keyType;

        CK_OBJECT_HANDLE hPublicKey = new CK_OBJECT_HANDLE();
        CK_OBJECT_HANDLE hPrivateKey = new CK_OBJECT_HANDLE();

        boolean bKeyDer = false;
        boolean bKeyGen = false;
        boolean bPreHash = false;
        String keyName = "";
        String CurveString = "ed25519";

        /*
         * Process cmd line.
         */
        for (int i = 0; i < args.length; ++i) {
            if (args[i].equalsIgnoreCase("-h")) {
                usage();
            } else if (args[i].equalsIgnoreCase("-p")) {
                bPreHash = true;
            } else if (args[i].equalsIgnoreCase("-k")) {
                println("Performing Key Derive Test");
                bKeyDer = true;
            } else if (args[i].equalsIgnoreCase("-g")) {
                println("Generating Key Pair");
                bKeyGen = true;
            } else if (args[i].equalsIgnoreCase("-n")) {
                if (++i >= args.length)
                    usage();
                keyName = args[i];
            } else if (args[i].equalsIgnoreCase("-C")) {
                if (++i >= args.length)
                    usage();
                CurveString = args[i].toLowerCase();
            } else {
                println("Unknown parameter: " + args[i]);
                usage();
            }
        }

        if (!(bKeyDer || bKeyGen) && keyName.equalsIgnoreCase(""))
            usage();

        keyType = bKeyDer ? CKK.EC_MONTGOMERY : CKK.EC_EDWARDS;
        boolean validCurveName = false;
        if (bKeyDer) {
            for (String c : montCurves) {
                if (c.equals(CurveString)) {
                    validCurveName = true;
                    break;
                }
            }
        } else {
            for (String c : edCurves) {
                if (c.equals(CurveString)) {
                    validCurveName = true;
                    break;
                }
            }
        }
        if (!validCurveName) {
            println("Incorrect curve name or invalid curve used");
            usage();
        }

        /*
         * Setup the curve that we are going to generate the key pair on.
         * Possible values are:
         * ed25519
         * ed448
         * curve25519
         * curve448
         */
        byte[] CurveName = CurveString.getBytes(StandardCharsets.US_ASCII);
        byte[] curve;
        LongRef derlen = new LongRef();
        CTUtilEx.CTU_DerEncodeNamedCurve(CurveName, null, derlen);
        curve = new byte[(int) derlen.value];
        CTUtilEx.CTU_DerEncodeNamedCurve(CurveName, curve, derlen);

        try {
            CryptokiEx.C_Initialize(null);
            CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION, null, null, hSession);

            /* Get the public and private keys to use */
            if (bKeyGen) {
                /* Generate keys */
                generateEccKeyPair(hSession, curve, keyName, keyType, CK_BBOOL.TRUE, hPublicKey, hPrivateKey);
                println("Key Generated successfully");
            } else {
                /* Load keys */
                hPublicKey = findKey(hSession, CKO.PUBLIC_KEY, keyType, keyName);
                hPrivateKey = findKey(hSession, CKO.PRIVATE_KEY, keyType, keyName);
            }

            if (bKeyDer) {
                /* User wants to perform Derive KAT */
                KeyDeriveTest(hSession, curve, hPublicKey, hPrivateKey);
                println("Derive Test passed");
            } else {
                /* User wants to perform sign/verify operations */
                EdDSASignatureTest(hSession, curve, bPreHash, hPublicKey, hPrivateKey);
            }

        } catch (CKR_Exception ex) {
            /*
             * A Cryptoki related exception was thrown
             */
            ex.printStackTrace();
        } catch (Exception ex) {
            ex.printStackTrace();
        } finally {
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

    public static String toHex(byte[] data) {
        StringBuilder strBuilder = new StringBuilder();
        for (byte val : data) {
            strBuilder.append(String.format("%02X", val & 0xff));
        }
        return strBuilder.toString();
    }

    public static void KeyDeriveTest(
            CK_SESSION_HANDLE hSession,
            byte[] curve,
            CK_OBJECT_HANDLE hPublicKey,
            CK_OBJECT_HANDLE hPrivateKey) {

        CK_OBJECT_HANDLE hDerived1 = new CK_OBJECT_HANDLE();
        CK_OBJECT_HANDLE hDerived2 = new CK_OBJECT_HANDLE();
        CK_OBJECT_HANDLE hOtherPublic = new CK_OBJECT_HANDLE();
        CK_OBJECT_HANDLE hOtherPrivate = new CK_OBJECT_HANDLE();
        int derivedLen = 16;
        // Create temp Montgomery keys to do ECDH
        generateEccKeyPair(hSession, curve, "tmpOther", CKK.EC_MONTGOMERY, CK_BBOOL.FALSE, hOtherPublic, hOtherPrivate);

        // Get public key values, needed for the key derivation
        CK_ATTRIBUTE[] getPubKey = { new CK_ATTRIBUTE(CKA.EC_POINT, null) };
        // Get pubkey size
        CryptokiEx.C_GetAttributeValue(hSession, hPublicKey, getPubKey, getPubKey.length);
        // It's a decent assumption that both public keys are the same size.
        int pubkeylen = (int) getPubKey[0].valueLen;
        byte[] pubKeyA = new byte[pubkeylen];
        byte[] pubKeyB = new byte[pubkeylen];

        getPubKey[0].pValue = pubKeyA;
        CryptokiEx.C_GetAttributeValue(hSession, hPublicKey, getPubKey, getPubKey.length);
        getPubKey[0].pValue = pubKeyB;
        CryptokiEx.C_GetAttributeValue(hSession, hOtherPublic, getPubKey, getPubKey.length);

        // Create template for derived key
        {
            CK_ATTRIBUTE[] derivedtemplate = {
                    new CK_ATTRIBUTE(CKA.CLASS, CKO.SECRET_KEY),
                    new CK_ATTRIBUTE(CKA.TOKEN, CK_BBOOL.FALSE),
                    new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.FALSE),
                    new CK_ATTRIBUTE(CKA.KEY_TYPE, CKK.GENERIC_SECRET),
                    new CK_ATTRIBUTE(CKA.VALUE_LEN, derivedLen),
            };

            CK_ECDH1_DERIVE_PARAMS param1 = new CK_ECDH1_DERIVE_PARAMS(KDF.CKD_NULL,
                    pubKeyA.length, pubKeyA);
            CK_ECDH1_DERIVE_PARAMS param2 = new CK_ECDH1_DERIVE_PARAMS(KDF.CKD_NULL,
                    pubKeyB.length, pubKeyB);
            CK_MECHANISM mech1 = new CK_MECHANISM(CKM.ECDH1_DERIVE, param1);
            CK_MECHANISM mech2 = new CK_MECHANISM(CKM.ECDH1_DERIVE, param2);

            println("Derive key1 with Ab");
            CryptokiEx.C_DeriveKey(hSession, mech1, hOtherPrivate, derivedtemplate, derivedtemplate.length, hDerived1);
            println("Derive key2 with aB");
            CryptokiEx.C_DeriveKey(hSession, mech2, hPrivateKey, derivedtemplate, derivedtemplate.length, hDerived2);
        }
        // Since the keys are not sensitive, we can simply print out their values
        byte[] secret1 = new byte[derivedLen];
        byte[] secret2 = new byte[derivedLen];
        CK_ATTRIBUTE[] getSecret1 = { new CK_ATTRIBUTE(CKA.VALUE, secret1) };
        CK_ATTRIBUTE[] getSecret2 = { new CK_ATTRIBUTE(CKA.VALUE, secret2) };
        CryptokiEx.C_GetAttributeValue(hSession, hDerived1, getSecret1, getSecret1.length);
        CryptokiEx.C_GetAttributeValue(hSession, hDerived2, getSecret2, getSecret2.length);

        println(toHex(secret1));
        println(toHex(secret2));
        if (!Arrays.equals(secret1, secret2))
            throw new CKR_Exception("ECDH1 DERIVE Result Error", CKR.FUNCTION_FAILED);

    }

    static void EdDSASignatureTest(
            CK_SESSION_HANDLE hSession,
            byte[] curve,
            boolean prehash,
            CK_OBJECT_HANDLE hPublicKey,
            CK_OBJECT_HANDLE hPrivateKey) {

        byte[] data = "This sentence is 36 characters long.".getBytes(StandardCharsets.US_ASCII);

        CK_EDDSA_PARAMS params = new CK_EDDSA_PARAMS(prehash, null);
        CK_MECHANISM signMech;

        if (prehash) {
            println("Using prehash mode");
            signMech = new CK_MECHANISM(CKM.EDDSA, params);
        } else {
            println("Using normal mode");
            signMech = new CK_MECHANISM(CKM.EDDSA);
        }

        System.out.print("Generating signature     : ");
        /* generate signature */
        CryptokiEx.C_SignInit(hSession, signMech, hPrivateKey);

        LongRef signLen = new LongRef();
        /* determine the length of the signature */
        CryptokiEx.C_Sign(hSession, data, data.length, null, signLen);
        /* allocate space for the signature */
        byte[] signature = new byte[(int) signLen.value];
        /* do the sign */
        CryptokiEx.C_Sign(hSession, data, data.length, signature, signLen);
        println("Done");
        println("Signature: " + toHex(signature));

        /* verify signature */
        System.out.print("Verifying signature      : ");
        /* start the verify operation */
        CryptokiEx.C_VerifyInit(hSession, signMech, hPublicKey);
        /* verify the signature against the hash */
        CryptokiEx.C_Verify(hSession, data, data.length, signature, signature.length);
        println("Valid");

        println("Signing Test passed");
    }

    /**
     * Generate an asymetric key pair.
     *
     * @param hSession
     *                    handle to an open session
     *
     * @param keyName
     *                    name (label) to give the generated keys
     *
     * @param hPublicKey
     *                    upon completion, the handle of the generated public key
     *
     * @param hPrivateKey
     *                    upon completion, the handle of the generated private key
     */
    public static void generateEccKeyPair(CK_SESSION_HANDLE hSession,
            byte[] curve,
            String keyName,
            CK_KEY_TYPE keyType,
            CK_BBOOL token,
            CK_OBJECT_HANDLE hPublicKey,
            CK_OBJECT_HANDLE hPrivateKey) {
        byte[] label = keyName.getBytes(StandardCharsets.US_ASCII);
        CK_MECHANISM keyGenMech;
        if (keyType == CKK.EC_EDWARDS)
            keyGenMech = new CK_MECHANISM(CKM.EC_EDWARDS_KEY_PAIR_GEN);
        else
            keyGenMech = new CK_MECHANISM(CKM.EC_MONTGOMERY_KEY_PAIR_GEN);
        /*
         * Setup the template for the public key.
         */
        CK_ATTRIBUTE[] publicTemplate = {
                new CK_ATTRIBUTE(CKA.CLASS, CKO.PUBLIC_KEY),
                new CK_ATTRIBUTE(CKA.TOKEN, token),
                new CK_ATTRIBUTE(CKA.KEY_TYPE, keyType),
                new CK_ATTRIBUTE(CKA.LABEL, label),
                new CK_ATTRIBUTE(CKA.VERIFY, CK_BBOOL.TRUE),
                new CK_ATTRIBUTE(CKA.DERIVE, CK_BBOOL.TRUE),
                new CK_ATTRIBUTE(CKA.EC_PARAMS, curve),
        };

        /*
         * Setup the template for the private key.
         */
        CK_ATTRIBUTE[] privateTemplate = {
                new CK_ATTRIBUTE(CKA.CLASS, CKO.PRIVATE_KEY),
                new CK_ATTRIBUTE(CKA.TOKEN, token),
                new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.FALSE),
                new CK_ATTRIBUTE(CKA.KEY_TYPE, keyType),
                new CK_ATTRIBUTE(CKA.LABEL, label),
                new CK_ATTRIBUTE(CKA.SIGN, CK_BBOOL.TRUE),
                new CK_ATTRIBUTE(CKA.DERIVE, CK_BBOOL.TRUE),
        };
        println("Generating key " + keyName);
        CryptokiEx.C_GenerateKeyPair(hSession, keyGenMech,
                publicTemplate, publicTemplate.length,
                privateTemplate, privateTemplate.length,
                hPublicKey, hPrivateKey);
        println("Done");
    }

    /**
     * Locate the specified key.
     *
     * @param session
     *                 handle to an open session
     *
     * @param keyClass
     *                 {@link safenet.jcprov.constants.CKO} class of the key to
     *                 locate
     *
     * @param keyName
     *                 name (label) of the key to locate
     *
     */
    static CK_OBJECT_HANDLE findKey(CK_SESSION_HANDLE session,
            CK_OBJECT_CLASS keyClass,
            CK_KEY_TYPE keyType,
            String keyName) {
        /* array of one object handles */
        CK_OBJECT_HANDLE[] hObjects = { new CK_OBJECT_HANDLE() };

        /* to receive the number of objects located */
        LongRef objectCount = new LongRef();

        /* setup the template of the object to search for */
        CK_ATTRIBUTE[] template = {
                new CK_ATTRIBUTE(CKA.CLASS, keyClass),
                new CK_ATTRIBUTE(CKA.KEY_TYPE, keyType),
                new CK_ATTRIBUTE(CKA.TOKEN, CK_BBOOL.TRUE),
                new CK_ATTRIBUTE(CKA.LABEL, keyName.getBytes(StandardCharsets.US_ASCII))
        };

        CryptokiEx.C_FindObjectsInit(session, template, template.length);
        CryptokiEx.C_FindObjects(session, hObjects, hObjects.length, objectCount);
        CryptokiEx.C_FindObjectsFinal(session);

        if (objectCount.value == 1) {
            /* return the handle of the located object */
            return hObjects[0];
        } else {
            /* return an object handle which is invalid */
            return new CK_OBJECT_HANDLE();
        }
    }

}

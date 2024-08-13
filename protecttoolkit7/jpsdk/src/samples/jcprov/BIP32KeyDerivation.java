import safenet.jcprov.*;
import safenet.jcprov.constants.*;
import safenet.jcprov.params.CK_BIP32_MASTER_DERIVE_PARAMS;
import safenet.jcprov.params.CK_BIP32_CHILD_DERIVE_PARAMS;
import java.nio.charset.*;


/**
 * This class demonstrates how to use BIP32
 * Usage : java ...BIP32KeyDerivation -keyName &lt;keyname&gt; -create
 * <li><i>keyname</i>  name (label) of the key to delete
 */
public class BIP32KeyDerivation
{
    /** easy access to System.out.println */
    static public void println(String s)
    {
        System.out.println(s);
    }

    /** display runtime usage of the class */
    public static void usage()
    {
        println("java ...BIP32KeyDerivation -keyName <keyname> -create");
        println("");
        println("-keyName <keyname> \tname (label) of the generated key");
        println("-create \t\tcreate a new key");
        println("");
        System.exit(1);
    }

    /** main execution method */
    public static void main(String[] args)
    {
        CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
        long slotId = 0;
        boolean create = false;
        String keyName = "";

        /*
         * process command line arguments
         */
        if(args.length == 0)
            usage();

        for (int i = 0; i < args.length; ++i)
        {
            if (args[i].equalsIgnoreCase("-keyName"))
            {
                if (++i >= args.length)
                    usage();

                keyName = args[i];
            }
            else if (args[i].equalsIgnoreCase("-create"))
                create = true;
            else
                usage();
        }

        try
        {
            /*
             * Initialize Cprov so that the library takes care
             * of multithread locking
             */
            CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));

            /*
             * Open a session
             */
            CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION, null, null, session);


            CK_OBJECT_HANDLE pKey;
            if (create)
            {
                /* Generate key pair and exit. */
                println("Generating Keys \""+keyName+"\" in slot 0 and 2\n");
                pKey = generateSecretKey(session, keyName);
                println("Done\n");
            }
            else
            {
                pKey = findSecretKey(session, keyName);
            }

            //Now do ECDH Key derive
            println("Generating derived key : ");
            byte[] array = runDerivationTests(session, pKey);
            println(bytesToHex(array));
            println("\n");
            
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
             * Note that we are not using CryptokiEx.
             */
            Cryptoki.C_CloseSession(session);

            /*
             * All done with Cryptoki
             *
             * Note that we are not using CryptokiEx.
             */
             Cryptoki.C_Finalize(null);
        }
    }

    /**
     * Generate a symetric key.
     *
     * @param session
     *  handle to an open session
     *
     * @param label
     *  name (label) to give the generated key
     *
     */

    public static CK_OBJECT_HANDLE generateSecretKey(   CK_SESSION_HANDLE session,
                                                        String label)
    {
        byte[] testvector = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
        CK_OBJECT_HANDLE pKey  = new CK_OBJECT_HANDLE();
        CK_ATTRIBUTE[] attr =
        {
            new CK_ATTRIBUTE(CKA.LABEL,     label.getBytes(StandardCharsets.US_ASCII)),
            new CK_ATTRIBUTE(CKA.VALUE,     testvector),
            new CK_ATTRIBUTE(CKA.CLASS,     CKO.SECRET_KEY),
            new CK_ATTRIBUTE(CKA.KEY_TYPE,  CKK.GENERIC_SECRET),
            new CK_ATTRIBUTE(CKA.TOKEN,     CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.FALSE),
            new CK_ATTRIBUTE(CKA.DERIVE,    CK_BBOOL.TRUE)
        };

        CryptokiEx.C_CreateObject(session, attr, attr.length, pKey);
        return pKey;
    }


    /**
     * Generate a BIP32 master key pair
     *
     * @param hPrivateSession
     *  handle to an open session
     *
     * @param hSeed
     *  OBJECT_HANDLE linked to a symetric key
     *
     */
    public static CK_BIP32_MASTER_DERIVE_PARAMS  generateMasterKeyPair(  CK_SESSION_HANDLE hPrivateSession,
                                                CK_OBJECT_HANDLE hSeed)
    {
        String pubLabel = "Master BIP32 Key(Public)";
        String priLabel = "Master BIP32 Key(Private)";

        CK_ATTRIBUTE[] pubKeyAttr =
        {
            new CK_ATTRIBUTE(CKA.LABEL,     pubLabel.getBytes(StandardCharsets.US_ASCII)),
            new CK_ATTRIBUTE(CKA.TOKEN,     CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.FALSE),
            new CK_ATTRIBUTE(CKA.DERIVE,    CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.KEY_TYPE,  CKK.BIP32)
        };

        CK_ATTRIBUTE[] priKeyAttr =
        {
            new CK_ATTRIBUTE(CKA.LABEL,     priLabel.getBytes(StandardCharsets.US_ASCII)),
            new CK_ATTRIBUTE(CKA.TOKEN,     CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.FALSE),
            new CK_ATTRIBUTE(CKA.DERIVE,    CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.KEY_TYPE,  CKK.BIP32)
        };

        CK_BIP32_MASTER_DERIVE_PARAMS mechParams = 
				new CK_BIP32_MASTER_DERIVE_PARAMS(pubKeyAttr, priKeyAttr);

        CK_MECHANISM mech = new CK_MECHANISM(CKM.BIP32_MASTER_DERIVE, mechParams);

        CK_OBJECT_HANDLE tmpHandle = new CK_OBJECT_HANDLE();

        CryptokiEx.C_DeriveKey(hPrivateSession, mech, hSeed, priKeyAttr, 
            priKeyAttr.length, tmpHandle);
        
        return mechParams;
    }


    /**
     * Generate a BIP32 child key pair
     *
     * @param hPrivateSession
     *  handle to an open session
     *
     * @param hParent
     *  OBJECT_HANDLE linked to the master private key
     *
     */
    public static CK_BIP32_CHILD_DERIVE_PARAMS  generateChildKeyPair(  CK_SESSION_HANDLE hPrivateSession,
                                                CK_OBJECT_HANDLE hParent)
    {
        String pubLabel = "Child BIP32 Key(Public)";
        String priLabel = "Child BIP32 Key(Private)";

        CK_ATTRIBUTE[] pubKeyAttr =
        {
            new CK_ATTRIBUTE(CKA.LABEL,     pubLabel.getBytes(StandardCharsets.US_ASCII)),
            new CK_ATTRIBUTE(CKA.TOKEN,     CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.FALSE),
            new CK_ATTRIBUTE(CKA.DERIVE,    CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.KEY_TYPE,  CKK.BIP32)
        };

        CK_ATTRIBUTE[] priKeyAttr =
        {
            new CK_ATTRIBUTE(CKA.LABEL,     priLabel.getBytes(StandardCharsets.US_ASCII)),
            new CK_ATTRIBUTE(CKA.TOKEN,     CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.FALSE),
            new CK_ATTRIBUTE(CKA.DERIVE,    CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.KEY_TYPE,  CKK.BIP32)
        };

        long[] path = { 0L, 1L, 4L };

        CK_BIP32_CHILD_DERIVE_PARAMS mechParams = 
				new CK_BIP32_CHILD_DERIVE_PARAMS(pubKeyAttr, priKeyAttr, path);

        CK_MECHANISM mech = new CK_MECHANISM(CKM.BIP32_CHILD_DERIVE, mechParams);

        CK_OBJECT_HANDLE tmpHandle = new CK_OBJECT_HANDLE();

        CryptokiEx.C_DeriveKey(hPrivateSession, mech, hParent, priKeyAttr, 
            priKeyAttr.length, tmpHandle);

        return mechParams;

    }

    public static CK_OBJECT_HANDLE findSecretKey(  CK_SESSION_HANDLE hSession,
                                String label)
    {
        /* array of one object handles */
        CK_OBJECT_HANDLE[] hObjects = {new CK_OBJECT_HANDLE()};

        /* to receive the number of objects located */
        LongRef objectCount = new LongRef();

        CK_ATTRIBUTE[] findAttr =
        {
            new CK_ATTRIBUTE(CKA.LABEL,     label.getBytes(StandardCharsets.US_ASCII)),
            new CK_ATTRIBUTE(CKA.CLASS,     CKO.SECRET_KEY),
            new CK_ATTRIBUTE(CKA.KEY_TYPE,  CKK.GENERIC_SECRET)
        };

        CryptokiEx.C_FindObjectsInit(hSession, findAttr, findAttr.length);

        CryptokiEx.C_FindObjects(hSession, hObjects, hObjects.length,
                objectCount);

        CryptokiEx.C_FindObjectsFinal(hSession);

        if (objectCount.value == 1)
        {
            /* return the handle of the located object */
            return hObjects[0];
        }
        else
        {
            /* return an object handle which is invalid */
            println("Key not found");
            return new CK_OBJECT_HANDLE();
        }
    }


    public static byte[] runDerivationTests(CK_SESSION_HANDLE hPrivateSession,
                                        CK_OBJECT_HANDLE hPrivate)
    {

        CK_BIP32_MASTER_DERIVE_PARAMS master = generateMasterKeyPair(hPrivateSession,hPrivate);
        CK_OBJECT_HANDLE masterPri = master.hPrivateKey;

        CK_BIP32_CHILD_DERIVE_PARAMS bip32Childparams = generateChildKeyPair(hPrivateSession,masterPri);
        CK_OBJECT_HANDLE childPub = bip32Childparams.hPublicKey;

        byte[] derivedKey = new byte[33];

        CK_ATTRIBUTE[] getDerivedValue = { 
			new CK_ATTRIBUTE(CKA.VALUE, derivedKey) 
        };
        CryptokiEx.C_GetAttributeValue( hPrivateSession, childPub, 
            getDerivedValue, getDerivedValue.length );
        
        return derivedKey;
    }

    public static String bytesToHex(byte[] bytes) {
        final char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

}

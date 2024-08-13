import safenet.jcprov.*;
import safenet.jcprov.constants.*;
import java.nio.charset.*;

/**
 * Class is used for PSR-2024 issue testing.
 * How to run:
 * CLASSPATH should contain path to jcprov.jar library,
 * PATH environment variable should contain the paths to jcprov.dll, cryptoki.dll and ethsm.dll libraries.
 * <p>
 * The types of keys supported are :-
 * <li>des          single DES key
 * <li>des2         double length Triple DES key
 * <li>des3         triple length Triple DES key
 * <li>rsa          RSA Key Pair
 * <p>
 * Usage : java ...GenerateKey -keyType &lt;keytype&gt; -keyName &lt;keyname&gt; [-slot &lt;slotId&gt;] [-password &lt;password&gt;][-modlen <modLenInBits>]")
 * <li><i>keytype</i>  one of (des, des2, des3, rsa)
 * <li><i>keyname</i>  name (label) of the key to delete
 * <li><i>slotId</i>   slot containing the token to delete the key from - default (0)
 * <li><i>password</i> user password of the slot. If specified, a private key is created
 */
public class KeyGen
{
    static long modLenInBits = 1024;
    /** easy access to System.out.println */
    static public void println(String s)
    {
        System.out.println(s);
    }

    /** display runtime usage of the class */
    public static void usage()
    {
        println("java ...KeyGen -keyType <keytype> -keyName <keyname> [-slot <slotId>] [-password <password>] [-modlen <modLenInBits>]");
        println("");
        println("<keytype>  one of (des, des2, des3, rsa)");
        println("<keyname>  name (label) of the generated key");
        println("<slotId>   slot containing the token to create the key on - default (0)");
        println("<password> user password of the slot. If specified, a private key is created.");
        println("");

        System.exit(1);
    }

    /** main execution method */
    public static void main(String[] args)
    {
        CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
        long slotId = 0;
        String keyType = "";
        String keyName = "";
        String password = "";
        boolean bPrivate = false;

        /*
         * process command line arguments
         */

        for (int i = 0; i < args.length; ++i)
        {
            if (args[i].equalsIgnoreCase("-keyType"))
            {
                if (++i >= args.length)
                    usage();

                keyType = args[i];
            }
            else if (args[i].equalsIgnoreCase("-keyName"))
            {
                if (++i >= args.length)
                    usage();

                keyName = args[i];
            }
            else if(args[i].equalsIgnoreCase("-slot"))
            {
                if (++i >= args.length)
                    usage();

                slotId = Integer.parseInt(args[i]);
            }
            else if (args[i].equalsIgnoreCase("-password"))
            {
                if (++i >= args.length)
                    usage();

                password = args[i];
            }
            else if(args[i].equalsIgnoreCase("-modlen"))
            {
                if (++i >= args.length)
                    usage();

                modLenInBits = Integer.parseInt(args[i]);
            }
            else
            {
                usage();
            }
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

            /*
             * Login - if we have a password
             */
            if (password.length() > 0)
            {
                CryptokiEx.C_Login(session, CKU.USER, password.getBytes(StandardCharsets.US_ASCII), password.length());

                bPrivate = true;
            }

            /*
             * determine the key type to generate, and generate the key
             */

            if (keyType.equalsIgnoreCase("des"))
            {
                CK_OBJECT_HANDLE hKey = new CK_OBJECT_HANDLE();

                generateKey(session, CKM.DES_KEY_GEN, keyName, bPrivate, hKey);
                println("des key (" + keyName + ") generated");
                println("handle (" + hKey.longValue() + ")");
            }
            else if (keyType.equalsIgnoreCase("des2"))
            {
                CK_OBJECT_HANDLE hKey = new CK_OBJECT_HANDLE();

                generateKey(session, CKM.DES2_KEY_GEN, keyName, bPrivate, hKey);
                println("des2 key (" + keyName + ") generated");
                println("handle (" + hKey.longValue() + ")");
            }
            else if (keyType.equalsIgnoreCase("des3"))
            {
                CK_OBJECT_HANDLE hKey = new CK_OBJECT_HANDLE();

                generateKey(session, CKM.DES3_KEY_GEN, keyName, bPrivate, hKey);
                println("des3 key (" + keyName + ") generated");
                println("handle (" + hKey.longValue() + ")");
            }
            else if (keyType.equalsIgnoreCase("rsa"))
            {
                CK_OBJECT_HANDLE hPublicKey = new CK_OBJECT_HANDLE();
                CK_OBJECT_HANDLE hPrivateKey = new CK_OBJECT_HANDLE();

                generateKeyPair(session,
                                CKM.RSA_PKCS_KEY_PAIR_GEN,
                                keyName,
                                bPrivate,
                                hPublicKey,
                                hPrivateKey);

                println("rsa key pair (" + keyName + ") generated");
                println("handles public(" + hPublicKey.longValue() +
                        ") private(" + hPrivateKey.longValue() + ")");
            }
            else
            {
                usage();
            }
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
             * Logout in case we logged in.
             *
             * Note that we are not using CryptokiEx and we are not checking the
             * return value. This is because if we did not log in then an error
             * will be reported - and we don't really care because we are shutting down.
             */
            Cryptoki.C_Logout(session);

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
     * @param mechanismType
     *  mechanism to use to generate the key. One of :- <br>
     *  CKM.DES_KEY_GEN                                 <br>
     *  CKM.DES2_KEY_GEN                                <br>
     *  CKM.DES3_KEY_GEN                                <br>
     *
     * @param keyName
     *  name (label) to give the generated key
     *
     * @param bPrivate
     *  true if the key is to be a private object
     *
     * @param hKey
     *  upon completion, handle of the generated key
     */
    public static void generateKey(CK_SESSION_HANDLE session,
                                   CK_MECHANISM_TYPE mechanismType,
                                   String keyName,
                                   boolean bPrivate,
                                   CK_OBJECT_HANDLE hKey)
    {
        CK_MECHANISM keyGenMech = new CK_MECHANISM(mechanismType);

        CK_ATTRIBUTE[] template =
        {
            new CK_ATTRIBUTE(CKA.CLASS,     CKO.SECRET_KEY),
            new CK_ATTRIBUTE(CKA.TOKEN,     CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.LABEL,     keyName.getBytes(StandardCharsets.US_ASCII)),
            new CK_ATTRIBUTE(CKA.PRIVATE,   new CK_BBOOL(bPrivate))
        };

        CryptokiEx.C_GenerateKey(session, keyGenMech, template, template.length, hKey);
    }

    /**
     * Generate an asymetric key pair.
     *
     * @param session
     *  handle to an open session
     *
     * @param mechanismType
     *  mechanism to use to generate the key. One of :- <br>
     *  CKM.RSA_PKCS_KEY_PAIR_GEN                       <br>
     *
     * @param keyName
     *  name (label) to give the generated keys
     *
     * @param bPrivate
     *  true if the Private key of the key pair is to be a private object
     *
     * @param hPublicKey
     *  upon completion, the handle of the generated public key
     *
     * @param hPrivateKey
     *  upon completion, the handle of the generated private key
     */
    public static void generateKeyPair(CK_SESSION_HANDLE session,
                                       CK_MECHANISM_TYPE mechanismType,
                                       String keyName,
                                       boolean bPrivate,
                                       CK_OBJECT_HANDLE hPublicKey,
                                       CK_OBJECT_HANDLE hPrivateKey)
    {
        CK_MECHANISM keyGenMech = new CK_MECHANISM(mechanismType);
		/*
         * Setup the template for the public key.
         *
         * Note that the key is NOT sensitive - public keys can be read in the clear.
         */
        CK_ATTRIBUTE[] publicTemplate =
        {
            new CK_ATTRIBUTE(CKA.CLASS,     CKO.PUBLIC_KEY),
            new CK_ATTRIBUTE(CKA.TOKEN,     CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.FALSE),
            new CK_ATTRIBUTE(CKA.LABEL,     keyName.getBytes(StandardCharsets.US_ASCII)),
            new CK_ATTRIBUTE(CKA.PRIVATE,   CK_BBOOL.FALSE),
            new CK_ATTRIBUTE(CKA.MODULUS_BITS, modLenInBits, 4)
        };

        /*
         * Setup the template for the private key.
         *
         * Note that the key IS sensitive - private keys can NOT be read in the clear.
         */
        CK_ATTRIBUTE[] privateTemplate =
        {
            new CK_ATTRIBUTE(CKA.CLASS,     CKO.PRIVATE_KEY),
            new CK_ATTRIBUTE(CKA.TOKEN,     CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.FALSE),
            new CK_ATTRIBUTE(CKA.LABEL,     keyName.getBytes(StandardCharsets.US_ASCII)),
            new CK_ATTRIBUTE(CKA.PRIVATE,   new CK_BBOOL(bPrivate))
        };

        CryptokiEx.C_GenerateKeyPair(session, keyGenMech,
                                     publicTemplate, publicTemplate.length,
                                     privateTemplate, privateTemplate.length,
                                     hPublicKey, hPrivateKey);
    }
}

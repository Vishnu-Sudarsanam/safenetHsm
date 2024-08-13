/*
 * This code sample relates to NistSp800_38F publication,
 * which describes AES_KW, AES_KWP, TDEA_TKW wrapping/unwrapping mechanisms.
 * Environment variables:
 * 1/ SW Emulator:
 * Path=<pat_to_jcprov.dll>;<path_to_cryptoki.dll>;%PATH%
 * 2/ HSM:
 * set ET_HSM_NETCLIENT_SERVERLIST=<server_IP_address>
 * Add <path_to_ethsm.dll> to PATH environment variable.
 **********
 * Compile:
 * javac.exe -cp .\;<path_to_jcprov.jar> SignGMAC.java
 * Run:
 * java.exe -cp .\;<path_to_jcprov.jar> SignGMAC
 */

import safenet.jcprov.*;
import safenet.jcprov.constants.*;
import safenet.jcprov.params.*;
import java.nio.charset.*;
import java.io.IOException;

public class SignGMAC
{
    static byte[] signingKeyBytes = null;
    static String line = null;
    static String errStr = null; 
    
    /** easy access to System.out.println */
    static public void println(String s)
    {
        System.out.println(s);
    }

    public static void cleanVariables (int number) {
        signingKeyBytes = null;
        line = null;
    }
    
    /**
     * Convert a byte array to a hex string.
     *
     * Each byte of the input is convert into two hex characters. There is no
     * space added between the character pairs.
     *
     * @param data
     *  hex data to convert
     */
    static String bytesToHex(byte[] data)
    {
        final String hexCodes = "0123456789ABCDEF";
        int len = data.length;
        char[] ret = new char[len * 2];
        byte digit;
        int j = 0;

        for (int i = 0; i < len; ++i)
        {
            // mask & get the first 4 bits of the byte
            digit = (byte) ((data[i] & 0xF0l) >>> 4);
            // convert to hex
            ret[j++] = hexCodes.charAt(digit);
            // mask & get the last 4 bits of the byte
            digit = (byte) (data[i] & 0x0Fl);
            // convert to hex
            ret[j++] = hexCodes.charAt(digit);
        }

        return (new String(ret));
    }
    
    public static byte[] hexToBin(String str)
    {
        int len = str.length();
        byte[] out = new byte[len / 2];
        int endIndx;

        for (int i = 0; i < len; i = i + 2)
        {
            endIndx = i + 2;
            if (endIndx > len)
                endIndx = len - 1;
            out[i / 2] = (byte) Integer.parseInt(str.substring(i, endIndx), 16);
        }
        return out;
    }
    public static int strstr(String haystack, String needle){
        if (needle.length() == 0) {
            return 0;
        }
        for(int i = 0; i < haystack.length(); i++ ) {
            for(int j = 0; j < needle.length() && 
                            i+j < haystack.length(); j++ ) {
                if(needle.charAt(j) != haystack.charAt(i+j)) {
                    break;
                } else if (j == needle.length()-1) {
                    return i;
                }
            }
        }
        return -1;
    }

    /** display runtime usage of the class */
    public static void usage()
    {
        println("java ...SignGMAC [-slot <slotId>] [-password <password>]");
        println("");
        println("<slotId>   slot containing the token with the key to use - " +
                "default (0)");
        println("<password> user password of the slot. If specified, a " +
                "private key is used.");
        println("");

        System.exit(1);
    }

    /** main execution method 
     * @throws IOException */
    @SuppressWarnings("unused")
    public static void main(String[] args) throws IOException
    {
        CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
        long slotId = 0;
        CK_MECHANISM mech = null;
        CK_GCM_PARAMS params = null;
        String password = "";
        boolean bPrivate = false;
        String signingKeyName = null;
        byte[] gmacIV_96_bit = new byte[] { 
                 (byte)0x7b, (byte)0xe4, (byte)0xb3, (byte)0x35, (byte)0x62, (byte)0x4e, (byte)0x20, (byte)0x46,
                 (byte)0xf5, (byte)0xf4, (byte)0xe8, (byte)0xf4 };

        byte[] gmacKey128 = new byte[] {
                 (byte)0x81, (byte)0x24, (byte)0x5f, (byte)0x7d, (byte)0x31, (byte)0x1e, (byte)0xcd, (byte)0x89,
                 (byte)0x02, (byte)0x26, (byte)0x58, (byte)0x7e, (byte)0x97, (byte)0x0c, (byte)0x32, (byte)0x81 };

        byte[] gmacPlainText128 = new byte[] { 
                 (byte)0xa0, (byte)0x32, (byte)0x84, (byte)0xcd, (byte)0x92, (byte)0xf3, (byte)0x10, (byte)0xfc,
                 (byte)0xc2, (byte)0x7d, (byte)0x65, (byte)0x50, (byte)0x94, (byte)0x2f, (byte)0x6f, (byte)0x1f };

        byte[] gmacTag128 = new byte[] { 
                 (byte)0x36, (byte)0xc6, (byte)0x93, (byte)0x1c, (byte)0x42, (byte)0x1f, (byte)0xda, (byte)0x62,
                 (byte)0x35, (byte)0x73, (byte)0x9c, (byte)0xa8, (byte)0x2d, (byte)0x17, (byte)0x7d, (byte)0xbf };

        /*
         * process command line arguments
         */

        for (int i = 0; i < args.length; ++i)
        {
            if(args[i].equalsIgnoreCase("-slot"))
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
            else
            {
                usage();
            }
        }

        try
        {
            /*
             * Initialize Cprov 
             */
            CK_C_INITIALIZE_ARGS initArgs = new CK_C_INITIALIZE_ARGS(0);
            CryptokiEx.C_Initialize(initArgs);

            /*
             * Open a session
             */
            CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION, null, null,
                    session);

            /*
             * Login - if we have a password
             */
            if (password.length() > 0)
            {
                CryptokiEx.C_Login(session, CKU.USER, password.getBytes(StandardCharsets.US_ASCII),
                        password.length());

                bPrivate = true;
            }

            //Create signing key:
            signingKeyName = "SigningKey";
            CK_OBJECT_HANDLE hSigningKey = new CK_OBJECT_HANDLE();
            createKey(session, CKK.AES, gmacKey128, signingKeyName, hSigningKey, bPrivate);

            println("sign...AAD only");

            params = new CK_GCM_PARAMS(gmacIV_96_bit, gmacPlainText128, 128);
            mech = new CK_MECHANISM(CKM.AES_GMAC, params);

            // Sign:
            byte[] tag = symetricSign(session, mech, hSigningKey, new byte[0] );

            // Print tag:

            // Compare:
            if (strstr(bytesToHex(gmacTag128), bytesToHex(tag)) != -1) {
               println("Test PASSED!");
            } else {
               println("Test FAILED!" + "\n");
               println("Expected Tag : " + bytesToHex(gmacTag128));
               println("Generated Tag: " + bytesToHex(tag));
            }

            //Verify:
            println("verify...AAD only");

            if ( symetricVerify(session, mech, hSigningKey, new byte[0], tag) ) {
               println("Test PASSED!");
            } else {
               println("Test FAILED!" + "\n");
            }

            // sign data without AAD param
            println("sign...no AAD");

            params = new CK_GCM_PARAMS(gmacIV_96_bit, new byte[0], 64);
            mech = new CK_MECHANISM(CKM.AES_GMAC, params);

            // Sign:
            tag = symetricSign(session, mech, hSigningKey, gmacPlainText128 );

            if (strstr(bytesToHex(gmacTag128), bytesToHex(tag)) != -1) {
               println("Test PASSED!");
            } else {
               println("Test FAILED!" + "\n");
               println("Expected Tag : " + bytesToHex(gmacTag128));
               println("Generated Tag: " + bytesToHex(tag));
            }

            println("verify...no AAD");
            if ( symetricVerify(session, mech, hSigningKey, gmacPlainText128, tag) ) {
               println("Test PASSED!");
            } else {
               println("Test FAILED!" + "\n");
            }

            // sign data without AAD param and raw IV
            println("sign...raw IV");
            mech = new CK_MECHANISM(CKM.AES_GMAC, gmacIV_96_bit);

            // Sign:
            tag = symetricSign(session, mech, hSigningKey, gmacPlainText128 );

            if (strstr(bytesToHex(gmacTag128), bytesToHex(tag)) != -1) {
               println("Test PASSED!");
            } else {
               println("Test FAILED!" + "\n");
               println("Expected Tag : " + bytesToHex(gmacTag128));
               println("Generated Tag: " + bytesToHex(tag));
            }

            println("verify...raw IV");
            if ( symetricVerify(session, mech, hSigningKey, gmacPlainText128, tag) ) {
               println("Test PASSED!");
            } else {
               println("Test FAILED!" + "\n");
            }

            CryptokiEx.C_DestroyObject(session, hSigningKey);
            cleanVariables(0);
        }
        catch (CKR_Exception ex)
        {
            /*
             * A Cryptoki related exception was thrown
             */
            println(errStr + " Operation FAILED " + ex.errorString(ex.ckrv));
            cleanVariables(0);
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
             * will be reported - and we don't really care because we are
             * shutting down.
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
    public static void createKey(CK_SESSION_HANDLE session,
            CK_KEY_TYPE keyType,
            byte[] keyBytes,
            String keyName,
            CK_OBJECT_HANDLE hKey,
            boolean bPrivate )
    {
        CK_ATTRIBUTE[] template =
        {
            new CK_ATTRIBUTE(CKA.CLASS,         CKO.SECRET_KEY),
            new CK_ATTRIBUTE(CKA.TOKEN,         CK_BBOOL.FALSE),
            new CK_ATTRIBUTE(CKA.SENSITIVE,     CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.PRIVATE,       bPrivate),
            new CK_ATTRIBUTE(CKA.LABEL,         keyName.getBytes(StandardCharsets.US_ASCII)),
            new CK_ATTRIBUTE(CKA.VALUE_LEN,     keyBytes.length),
            new CK_ATTRIBUTE(CKA.VALUE,         keyBytes, keyBytes.length),
            new CK_ATTRIBUTE(CKA.SIGN,       CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.VERIFY,       CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.WRAP,          CK_BBOOL.FALSE),
            new CK_ATTRIBUTE(CKA.UNWRAP,       CK_BBOOL.FALSE),
            new CK_ATTRIBUTE(CKA.EXTRACTABLE,   CK_BBOOL.FALSE),
            new CK_ATTRIBUTE(CKA.EXPORTABLE,   CK_BBOOL.FALSE),
            new CK_ATTRIBUTE(CKA.MODIFIABLE,    CK_BBOOL.FALSE),
            new CK_ATTRIBUTE(CKA.KEY_TYPE,      keyType)
        };
        errStr = "Key Generation";
        CryptokiEx.C_CreateObject(session, template, template.length, hKey);
    }
    
    static byte[] symetricSign(CK_SESSION_HANDLE session,
            CK_MECHANISM mechanism,
            CK_OBJECT_HANDLE hSigningKey,
            byte[] data) throws IOException
    {
        byte[] wrappedKey = null;
        LongRef lRef = new LongRef();

        CryptokiEx.C_SignInit(session, mechanism, hSigningKey);
        CryptokiEx.C_Sign(session, data, data.length, null, lRef);

        /* allocate space */
        byte[] tag = new byte[(int)lRef.value];
        
        errStr = "Single Sign";
        CryptokiEx.C_Sign(session, data, data.length, tag, lRef);
        return tag;
    }

    static boolean symetricVerify(CK_SESSION_HANDLE session,
            CK_MECHANISM mechanism,
            CK_OBJECT_HANDLE hSigningKey,
            byte[] data,
            byte[] tag) throws IOException
    {
        byte[] wrappedKey = null;

        errStr = "Single Verify";
        CryptokiEx.C_VerifyInit(session, mechanism, hSigningKey);
        try {
            CryptokiEx.C_Verify(session, data, data.length, tag, tag.length);
        }
        catch (CKR_Exception ex)
        {
            if ( ex.ckrv == CKR.SIGNATURE_INVALID )
                return false;
            else
                throw (ex);
        }

        return true;
    }
}

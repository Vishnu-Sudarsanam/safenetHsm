
import javax.crypto.*;
import javax.crypto.spec.*;

import java.math.*;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.*;
import java.nio.charset.*;

/**
 * This sample code shows the use of Encryption / Decryption using a generated
 * secret DES key.
 *
 */
public class Encrypt
{
    static public Provider provider = null;
    static byte[] iv = new byte[0] ;

    /** simplified use of System.out.println */
    static void println(String s)
    {
        System.out.println(s);
    }

    /**
     * Transform the specified byte into a Hex String form.
     *
     * @param bArray    The byte array to transform.
     * @return        The Hex String.
     */
    public static final String bytesToHexStr(byte[] bArray)
    {
        String lookup = "0123456789abcdef";
        StringBuffer s = new StringBuffer(bArray.length * 2);

        for (int i = 0; i < bArray.length; i++)
        {
            s.append(lookup.charAt((bArray[i] >>> 4) & 0x0f));
            s.append(lookup.charAt(bArray[i] & 0x0f));
        }

        return s.toString();
    }

    /**
     * Transform the specified Hex String into a byte array.
     *
     * @param s        the hex string to convert.
     * @return        The resulting byte array.
     */
    public static final byte[] hexStrToBytes(String    s)
    {
        byte[]    bytes;

        bytes = new byte[s.length() / 2];

        for (int i = 0; i < bytes.length; i++)
        {
            bytes[i] = (byte)Integer.parseInt(
                    s.substring(2 * i, 2 * i + 2), 16);
        }

        return bytes;
    }

    // Encrypt, Symmetric Algorithm
    public static byte[] encrypt(String algorithm,
                                 String mode,
                                 String padding,
                                 SecretKey secretKey,
                                 byte[] clearBytes) throws GeneralSecurityException
    {
        // Instantiate Cipher
        Cipher cipher = Cipher.getInstance(algorithm + "/" + mode + "/" + padding, provider.getName());

        // Initialise Cipher
        if (mode.equals("CBC"))
        {
            // If IV not yet set, generate random IV
            if (iv.length == 0)
            {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                iv = cipher.getIV();
            }
            else
            {
                // If IV set, use it
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            }
        }
        else
        {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        }

        // Encrypt and Return Encrypted Bytes
        return cipher.doFinal(clearBytes);
    }


    // Decrypt, Symmetric Algorithm
    public static byte[] decrypt(String algorithm,
                                 String mode,
                                 String padding,
                                 SecretKey secretKey,
                                 byte[] encryptedBytes) throws GeneralSecurityException
    {
        // Instantiate Cipher
        Cipher cipher = Cipher.getInstance(algorithm + "/" + mode + "/" + padding, provider.getName());

        // Initialise Cipher
        if (mode.equals("CBC"))
        {
            cipher.init(Cipher.DECRYPT_MODE, secretKey,
                        new IvParameterSpec(iv));
        }
        else
        {
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
        }

        // Decrypt and Return Decrypted Bytes
        return cipher.doFinal(encryptedBytes);
    }



   public static void main(String[] args)
    {
        String keyName = "test_key";
        String plainText = "If it was so, it might be; and it were so, it would be; but as it isn't, it ain't. That's logic. - Lewis Carrol ";
        byte[] cipherText = null;
        String decryptText = null;

        String password = null; /* if we are logging into adapter */

        try
        {
            /* make sure that we have access to the safenet provider */
        	/* SAFENETProvider(<N>) constructor is available. 
        	 * Default SAFENETProvider() constructor operates with a default slot of 0.
        	 * <N> := 0 - 63
        	 * Slot <N> must be created!
        	 */
            if(Security.getProvider("SAFENET") == null)
            {
                System.out.println("Adding Provider dynamically");
                String providerClass = "au.com.safenet.crypto.provider.SAFENETProvider";
                Class<?> c = Class.forName(providerClass);
                Class<? extends Provider> t = c.asSubclass(Provider.class);

                @SuppressWarnings("deprecation")
                Provider p = t.newInstance();

                Security.addProvider(p);
            }

            provider = Security.getProvider("SAFENET");

            System.out.println("Loaded provider " + provider.toString());
            /*
             * Normally at this point we should create a secure source of random
             * numbers for the creation of keys. However, the Safenet hardware
             * has this built in, so we do not need to create or do a getInstance
             * for a SecureRandom object.
             *
             * If a SecureRandom object is needed it is passed into the
             * Cipher.init method.
             */

            /* Create a secret des key to do our Encrypt decrypt */
            println("");
            println("Create secret DES key");
            KeyGenerator keyGen = KeyGenerator.getInstance("DES", provider.getName());
            keyGen.init( 64 );
            SecretKey skey = keyGen.generateKey();

            /* ENCRYPT -- use created key to encrypt supplied plain text */
            println("");
            println("Plain text before encryption with DES key : \n"+plainText);
            cipherText = encrypt("DES", "ECB", "PKCS5Padding", skey, plainText.getBytes(StandardCharsets.US_ASCII));

            /* display resulting bytes */
            String hexStr = bytesToHexStr(cipherText);
            println("");
            System.out.println("Result of Encrypt : \n"+hexStr);

            /* DECRYPT -- use key to decrypt supplied hex string representing cipher text */
            println("");
            System.out.println("Now decrypt bytes using secret key");
            byte[] decryptBytes = decrypt("DES", "ECB", "PKCS5Padding", skey, cipherText);
            decryptText = new String(decryptBytes, StandardCharsets.US_ASCII);
            System.out.println("Decrypted : \n"+decryptText);
            println("");
            println("");
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
    }
}

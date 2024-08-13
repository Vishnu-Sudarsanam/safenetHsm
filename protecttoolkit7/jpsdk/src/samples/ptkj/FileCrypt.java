/*
 * $Id: prod/jprov_sfnt/samples/safenet/ptkj/samples/filecrypt/FileCrypt.java 1.1 2009/11/05 10:29:22GMT-05:00 Sorokine, Joseph (jsorokine) Exp  $
 * $Author: Sorokine, Joseph (jsorokine) $
 *
 * Copyright (c) 1997-1998 SAFENET Pty. Ltd.
 * All Rights Reserved - Proprietary Information of SAFENET Pty. Ltd.
 * Not to be Construed as a Published Work.
 *
 * $Source: prod/jprov_sfnt/samples/safenet/ptkj/samples/filecrypt/FileCrypt.java $
 * $Revision: 1.1 $
 * $Date: 2009/11/05 10:29:22GMT-05:00 $
 * $State: Exp $
 */


import java.io.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import au.com.safenet.crypto.*;

/**
 * An application for performing public-key based file encryption.
 * <p>
 * This application will take it's standard input and encrypt or
 * decrypt it and write the result to standard output.
 * <p>
 * The encrypted file format is as follows;
 * <table>
 * <tr><th>Field    <th>Length (bytes)
 * <tr><td>KeyLength    <td>4
 * <tr><td>KeyBytes    <td>As specified by KeyLength
 * <tr><td>AlgParamsLength    <td>4
 * <tr><td>AlgParams        <td>As specified by AlgParamsLength
 * <tr><td>MacLength    <td>4
 * <tr><td>Mac        <td>As specified by MacLength
 * <tr><td>Encrypted Data    <td>Remainder of file
 * </table>
 */
public class FileCrypt
{

    static final String PROVIDER = "SAFENET";
    static final String WRAP_KEYSTORE = "CRYPTOKI";
    static final String WRAP_TRANSFORM = "RSA/ECB/PKCS1Padding";
    static final String MAC_ALGORITHM = "DES";
    static final String BULK_TRANSFORM = "DES/CBC/PKCS5Padding";
    static final String BULK_ALGORITHM = "DES";
    static final String KS_NAME = "CRYPTOKI";

    static final int READ_BUFFER = 50;

    /**
     * This method will generate a random SecretKey for the
     * given Cipher algorithm and provider.
     */
    SecretKey generateSecretKey(String algorithm, String provider)
    throws NoSuchAlgorithmException, NoSuchProviderException
    {
        KeyGenerator keyGen = KeyGenerator.getInstance(
            algorithm, provider);

        return keyGen.generateKey();
    }

    /**
     * Encrypt the SecretKey with the provided PublicKey
     * using the WrappingKeyStore interface.  This allows
     * the SecretKey to be encrypted in hardware so that
     * it may be exported in an encrypted form.
     */
    byte[] encryptKey(PublicKey wrapKey, SecretKey key)
    throws GeneralSecurityException, NoSuchProviderException
    {
        WrappingKeyStore keyStore;
        keyStore = WrappingKeyStore.getInstance(WRAP_KEYSTORE,PROVIDER);
        return keyStore.wrapKey(wrapKey, WRAP_TRANSFORM, key);
    }

    /**
     * Encode the algorithm parameters for the given Cipher
     * as a byte array.  Currently only encodes the initialisation
     * vector as this is the only parameter supported by the
     * SAFENET provider.
     */
    byte[] encodeParameters(Cipher cipher)
    {
        byte[] iv = cipher.getIV();
        return iv;
    }

    /**
     * Encrypt the data on the given InputStream and return a MAC
     * value which can be used to verify the integrity of the
     * decrypted data.  The given Cipher will be used to perform
     * the encryption and the given Mac to produce the MAC value.
     * The encrypted data will be written to the provided OutputStream.
     */
    byte[] encrypt(Cipher cipher, Mac mac, InputStream in, OutputStream out)
    throws BadPaddingException, IllegalBlockSizeException, IOException
    {
        byte[] block = new byte[READ_BUFFER];
        int len;
        while ((len = in.read(block)) != -1)
        {
            /*
             * update our MAC value
             */
            mac.update(block, 0, len);

            /*
             * encipher the data
             */
            byte[] enc = cipher.update(block, 0, len);
            if (enc != null)
            {
                /*
                 * output the enciphered data
                 */
                out.write(enc);
            }
        }

        /*
         * output the final block if required
         */
        byte[] finalBlock = cipher.doFinal();
        if (finalBlock != null)
        {
            out.write(finalBlock);
        }

        return mac.doFinal();
    }

    /**
     * Encrypt the given InputStream to the given OutputStream.  This
     * method will generate a random session key, encrypt that key
     * with the provided PublicKey and then write that Key, any algorithm
     * parameters, a MAC value and finally the encrypted data to the
     * OutputStream.
     */
    void encryptFile(InputStream in, OutputStream out, PublicKey publicKey)
    throws GeneralSecurityException,
        BadPaddingException, IllegalBlockSizeException,
        NoSuchAlgorithmException, NoSuchProviderException,
        NoSuchPaddingException, InvalidKeyException,
        IOException
    {
        /*
         * Create a random SecretKey and encrypt it using
         * the recipient's PublicKey
         */
        SecretKey secretKey = generateSecretKey(BULK_ALGORITHM,
            PROVIDER);
        byte[] wrappedKey = encryptKey(publicKey, secretKey);

        /*
         * Create and initialise the Cipher used to encrypt the document
         */
        Cipher bulkCipher = Cipher.getInstance(BULK_TRANSFORM,PROVIDER);
        bulkCipher.init(Cipher.ENCRYPT_MODE, secretKey);

        /*
         * Encode the algorithm parameters for the Cipher
         */
        byte[] algParams = encodeParameters(bulkCipher);

        /*
         * Create the Mac instance and initialise it with our
         * session key
         */
        Mac mac = Mac.getInstance(MAC_ALGORITHM, PROVIDER);
        mac.init(secretKey);

        /*
         * Encrypt the document to an internal buffer and
         * calculate the MAC value of the plain text
         */
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        byte[] macValue = encrypt(bulkCipher, mac, in, bOut);

        /*
         * Encode the output file
         */
        DataOutputStream dOut = new DataOutputStream(out);

        /*
         * Write out the key
         */
        dOut.writeInt(wrappedKey.length);
        dOut.write(wrappedKey);

        /*
         * Write out the parameters, note these may be null
         */
        if (algParams != null)
        {
            dOut.writeInt(algParams.length);
            dOut.write(algParams);
        }
        else
        {
            dOut.writeInt(0);
        }

        /*
         * Write out the MAC
         */
        dOut.writeInt(macValue.length);
        dOut.write(macValue);

        /*
         * And finally the encrypted document
         */
        bOut.writeTo(dOut);
    }

    /**
     * Decrypt the SecretKey with the provided PrivateKey
     * using the WrappingKeyStore interface.  This allows
     * the SecretKey to be decrypted in hardware and saved
     * there directly.
     */
    Key decryptKey(PrivateKey wrapKey, byte[] wrappedKey)
    throws GeneralSecurityException, NoSuchProviderException
    {
        WrappingKeyStore keyStore;
        keyStore = WrappingKeyStore.getInstance(WRAP_KEYSTORE,PROVIDER);

        return keyStore.unwrapKey(wrapKey, WRAP_TRANSFORM,
            wrappedKey, BULK_ALGORITHM);
    }

    /**
     * This method will decrypt the data on the InputStream and write
     * back the decrypted data to the OutputStream.  A MAC value will
     * be calculated for the decrypted data and returned by this method.
     * The provided Cipher instance will be used to perform the decryption
     * and the Mac instance to calculate the MAC value.  Both these
     * objects should be correctly initialised before calling this function.
     */
    byte[] decrypt(Cipher cipher, Mac mac, InputStream in, OutputStream out)
    throws BadPaddingException, IllegalBlockSizeException, IOException
    {
        /*
         * read the input in chunks and process each chunk
         */
        byte[] block = new byte[READ_BUFFER];
        int len;
        while ((len = in.read(block)) != -1)
        {
            /*
             * decipher the data
             */
            byte[] plain = cipher.update(block, 0, len);
            if (plain != null)
            {
                /*
                 * update our MAC value
                 */
                mac.update(plain);

                /*
                 * output the deciphered data
                 */
                out.write(plain);
            }
        }

        /*
         * output the final block if required
         */
        byte[] finalBlock = cipher.doFinal();
        if (finalBlock != null)
        {
            /*
             * update our MAC value
             */
            mac.update(finalBlock);

            /*
             * output the deciphered data
             */
            out.write(finalBlock);
        }

        return mac.doFinal();
    }

    /**
     * This method will decrypt the InputStream and write out the
     * plaintext to the given OutputStream.  This method will recover
     * the session key using the provided PrivateKey and then decrypt
     * the data.  If the calculated MAC value does not match the value
     * saved in the file (ie the file has been tampered with) no output
     * will be written to the output stream and a GeneralSecurityException
     * will be thrown.
     */
    void decryptFile(InputStream in, OutputStream out,PrivateKey privateKey)
    throws GeneralSecurityException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IOException
    {
        /*
         * Decode the input file
         */
        DataInputStream dIn = new DataInputStream(in);

        /*
         * recover the encrypted Key data
         */
        int keyLen = dIn.readInt();
        byte[] keyBytes = new byte[keyLen];
        dIn.readFully(keyBytes);

        /*
         * recover the algorithm parameters
         */
        int algLen = dIn.readInt();
        byte[] algBytes = null;
        if (algLen > 0)
        {
            algBytes = new byte[algLen];
            dIn.readFully(algBytes);
        }

        /*
         * recover the stored MAC value
         */
        int macLen = dIn.readInt();
        byte[] fileMac = new byte[macLen];
        dIn.readFully(fileMac);

        /*
         * recreate the session key
         */
        Key secretKey = decryptKey(privateKey, keyBytes);

        /*
         * Create our Cipher and initialise it with our key
         * and algorithm parameters.
         */
        Cipher bulkCipher = Cipher.getInstance(BULK_TRANSFORM,PROVIDER);
        if (algBytes != null)
        {
            AlgorithmParameterSpec params;
            params = new IvParameterSpec(algBytes);

            bulkCipher.init(Cipher.DECRYPT_MODE, secretKey, params);
        }
        else
        {
            bulkCipher.init(Cipher.DECRYPT_MODE, secretKey);
        }

        /*
         * Initialise the Mac we use to verify the file integrity
         */
        Mac mac = Mac.getInstance(MAC_ALGORITHM, PROVIDER);
        mac.init(secretKey);

        /*
         * Decrypt the file to a temporary buffer
         */
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        byte[] calculatedMac = decrypt(bulkCipher, mac, in, bOut);

        /*
         * verify the stored MAC value with the calculated value
         */
        if (!Array_equals(fileMac, calculatedMac))
        {
            throw new GeneralSecurityException(
                "File has been tampered with.");
        }
        else
        {
            /*
             * save the decrypted output to the outputstream
             */
            bOut.writeTo(out);
        }
    }

    static boolean Array_equals(byte[] b1, byte[] b2)
    {
        if (b1.length != b2.length)
        {
            return false;
        }

        for (int i = 0; i < b1.length; i++)
        {
            if (b1[i] != b2[i])
            {
                return false;
            }
        }

        return true;
    }

    /**
     * Create an instance of a KeyStore we can use to determine
     * the Public or Private Key to use.
     */
    static KeyStore loadKeyStore()
    throws NoSuchProviderException, KeyStoreException
    {
        KeyStore ks = KeyStore.getInstance(KS_NAME, PROVIDER);
        try
        {
            ks.load(null, null);
        }
        catch (Exception e)
        {
            throw new KeyStoreException(
                "Failed to initialise keystore: "
                + e.getMessage());
        }

        return ks;
    }

    /**
     * This is the main entry point to our application.  This method
     * will process the command line arguments, look up the public-key
     * Key required and the call the encryptFile() or decryptFile()
     * method.
     * <p>
     * Currently this application only supports the input file
     * from standard input and will write the output file to standard
     * output.  Be aware that under DOS this will not work.
     */
    public static void main(String[] args)
    throws Exception
    {
        boolean encrypt = false;
        boolean decrypt = false;

        String keyName = null;

        /*
         * examine all the command line arguments
         */
        for (int i = 0; i < args.length; i++)
        {
            if (args[i].equals("-encrypt"))
            {
                encrypt = true;
            }
            else if (args[i].equals("-decrypt"))
            {
                decrypt = true;
            }
            else if (args[i].equals("-key"))
            {
                keyName = args[++i];
            }
        }

        /*
         * validate the arguments
         */
        if (encrypt == decrypt)
        {
            if (encrypt)
            {
                System.err.println(
                    "Cannot encrypt and decrypt file!");
            }
            else
            {
                System.err.println(
                    "Must specify -encrypt or -decrypt.");
            }
            System.exit(1);
        }

        if (keyName == null)
        {
            System.err.println("Missing key name.");
            System.exit(1);
        }

        java.security.Security.addProvider(new au.com.safenet.crypto.provider.SAFENETProvider());

        FileCrypt fileCrypt = new FileCrypt();
        KeyStore ks = FileCrypt.loadKeyStore();

        if (encrypt)
        {
            /*
             * determine the recipient's PublicKey
             */
            PublicKey publicKey = (PublicKey)ks.getKey(keyName,
                null);

            if (publicKey == null)
            {
                System.err.println("Cannot load key " + keyName);
                System.exit(1);
            }

            /*
             * encrypt the file
             */
            fileCrypt.encryptFile(System.in,System.out,publicKey);
        }
        else
        {
            /*
             * determine our PrivateKey
             */
            PrivateKey privateKey = (PrivateKey)ks.getKey(keyName,
                null);

            if (privateKey == null)
            {
                System.err.println("Cannot load key " + keyName);
                System.exit(1);
            }

            /*
             * decrypt the file
             */
            fileCrypt.decryptFile(System.in,System.out,privateKey);
        }
    }
}


/*
 * $Id: prod/jprov_sfnt/samples/safenet/ptkj/samples/reencrypt/Reencrypt.java 1.1 2009/11/05 10:30:12GMT-05:00 Sorokine, Joseph (jsorokine) Exp  $
 * $Author: Sorokine, Joseph (jsorokine) $
 *
 * Copyright (c) 2002 Safenet Technologies
 * All Rights Reserved - Proprietary Information of Safenet Technologies
 * Not to be Construed as a Published Work.
 *
 * $Source: prod/jprov_sfnt/samples/safenet/ptkj/samples/reencrypt/Reencrypt.java $
 * $Revision: 1.1 $
 * $Date: 2009/11/05 10:30:12GMT-05:00 $
 * $State: Exp $
 */



import java.util.Arrays;
import java.security.Provider;
import java.security.Security;
import java.security.Key;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import java.nio.charset.*;

import au.com.safenet.crypto.provider.SAFENETProvider;
import au.com.safenet.crypto.WrappingKeyStore;

/** Sample program demonstrating the usage of WrappingKeyStore to perform
 * secure re-encryption.
 *
 * A very common scenario, where re-encryptrion is required is PIN validation
 * in EFT systems. There are two parties involved in this applications: the
 * Acquirer, and the Issuer. The Issuer issue the cards to the customers, and
 * the Acquirers get the encrypted PIN from the POS devices in the field.
 *
 * The Acquirers have a key set-up for the encrypted communication path from
 * the POS device to its offices. It is also a trusted party for the Issuer,
 * and has (limited) access to the issuer key. When a PIN validation request is
 * received by the acquirer branch office, the requrest is encrypted under the
 * Acquirer's key. Then the request is re-encrypted under the Issuer's key in
 * such a way that the clear PIN validation request is never available. Then,
 * the new PIN validation request, encrypted under the Issuer's key is sent to
 * the Issuer for validation.
 *
 * In this sample, we will demonstrate how the protectoolkit j product can be
 * used to implement a secure message re-encryption scheme.
 *
 * The program will first create two temporary keys. Then it will encrypt some
 * data using the first key. The encrypted data will then be re-encrypted (in a
 * secure manner) under the second key. Finally, the cryptogram will be
 * decrypted using the second key, and compared against the original data to
 * ensure that the operation was successful.
 */
public class Reencrypt
{
    /** Main entry point.
     * Construct an instance of Reencrypt, and run it.
     */
    public static void main(String args[])
    {
        if (args.length != 0)
        {
            usage();
        }

        try
        {
            Reencrypt prog = new Reencrypt();
            prog.run();
        }
        catch (Exception ex)
        {
            println("Exception caught: " + ex.getMessage());
            ex.printStackTrace(System.out);
        }
    }

    /** A copy of the provider we want to use in this example (SAFENETProvider).
     */
    private Provider provider;

    /** This method executes the test application.
     */
    public void run()
        throws Exception
    {
        provider = new SAFENETProvider();

        /* Add the SAFENET provider to the list. */
        Security.addProvider(provider);

        /* Generate the first key (used to encrypt the original data) */
        KeyGenerator des3KeyGen = KeyGenerator.getInstance("DESede", provider.getName());
        SecretKey des3Key = des3KeyGen.generateKey();

        /* Generate the second key (used to decrypt the re-encrypted data */
        KeyGenerator ideaKeyGen = KeyGenerator.getInstance("IDEA", provider.getName());
        SecretKey ideaKey = ideaKeyGen.generateKey();

        /* Prepare the input string.Make sure it is not a multiple of block
         * length for DES (or IDEA) - this will allow us to test the padding
         * capabilities. */
        byte [] input = "This string is 29 bytes long".getBytes(StandardCharsets.US_ASCII);

        /* Encrypt some data using the first key */
        byte [] encData1 = encryptData(des3Key, input);

        /* Reencrypt the data to use the second key without revealing the data
         * in the clear on the host system. */
        byte [] encData2 = reencryptData(des3Key, ideaKey, encData1);

        /* Decrypt the data using the second key, and compare against the
         * original.
         */
        byte [] out = decryptData(ideaKey, encData2);

        if (Arrays.equals(input, out)) {
            println("Re-encryption was successful");
        } else {
            println("Re-encryption failed");
        }
    }

    /** Encrypt a byte array.
     * This function encrypts a byte array using the specified key.
     */
    private byte [] encryptData(Key key, byte [] input)
        throws Exception
    {
        Cipher cipher = Cipher.getInstance(
            key.getAlgorithm() + "/ECB/PKCS5Padding",
            provider.getName() );
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(input);
    }

    /** Decrypt a byte array.
     * This function decrypts a byte array using the specified key.
     */
    private byte [] decryptData(Key key, byte [] input)
        throws Exception
    {
        Cipher cipher = Cipher.getInstance(
            key.getAlgorithm() + "/ECB/PKCS5Padding",
            provider.getName() );
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(input);
    }

    /** Reencrypt a byte array.
     *  This funtction transforms an encrypted byte array to another byte array
     *  encrypted under a different key without revealing any data.
     */
    private byte [] reencryptData(Key currentKey, Key newKey, byte [] input)
        throws Exception
    {
        /* SAFENET Extension: Create a wrapping key store */
        WrappingKeyStore wks = WrappingKeyStore.getInstance(
            "CRYPTOKI",
            provider.getName() );

        /* Create the cleartext inside the secure storage. */
        Key temp = wks.unwrapKey(currentKey,
                                 currentKey.getAlgorithm() + "/ECB/PKCS5Padding",
                                 input,
                                 "GENERIC");

        /* Get the re-encrypted data */
        return wks.wrapKey(newKey,
                           newKey.getAlgorithm() + "/ECB/PKCS5Padding",
                           temp);
    }

    /** simplified use of System.out.println */
    public static void println(String s)
    {
        System.out.println(s);
    }

    /** Describe the arguments of the program, end exit. */
    public static void usage()
    {
        println("java ...Reencrypt");
        println("");
        System.exit(0);
    }

}


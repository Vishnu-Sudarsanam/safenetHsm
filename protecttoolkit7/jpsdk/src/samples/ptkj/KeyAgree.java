/*
 * $Id: prod/jprov_sfnt/samples/safenet/ptkj/samples/keyagree/KeyAgree.java 1.1 2009/11/05 10:29:29GMT-05:00 Sorokine, Joseph (jsorokine) Exp  $
 * $Author: Sorokine, Joseph (jsorokine) $
 *
 * Copyright (c) 2002 Safenet Technologies
 * All Rights Reserved - Proprietary Information of Safenet Technologies
 * Not to be Construed as a Published Work.
 *
 * $Source: prod/jprov_sfnt/samples/safenet/ptkj/samples/keyagree/KeyAgree.java $
 * $Revision: 1.1 $
 * $Date: 2009/11/05 10:29:29GMT-05:00 $
 * $State: Exp $
 *
 * Created on 3 October 2002, 09:27
 */


import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;

import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.charset.*;

import au.com.safenet.crypto.provider.SAFENETProvider;
import au.com.safenet.crypto.spec.*;
import au.com.safenet.crypto.provider.*;



/**
 * Key Agreement sample code. Alice and Bob each generate a key pair. They
 * then use their private keys and the other's public key to create separately
 * a shared secret key. This can then be used to encrypt / decrypt data.
 *
 */
public class KeyAgree
{
	static public Provider provider = null;
	static byte[] iv = new byte[0] ;
	
	private static DHParameterSpec dhPar = null;
	private static DSAParameterSpec dsaPar = null;
	private static BigInteger p1, g1, p2, g2, q;
	
	/** simplified use of System.out.println */
	static void println(String s)
	{
		System.out.println(s);
	}
	
	public static void initDefaultSpec()
	{
		/* Set DH Parameter Spec */
		p1 = new BigInteger(
			"d899ab2f685748b9ecc46f2065f15d10894423707bdbc353"
			+ "835c52b03556e6516d91d817d74a858ec9ac325c979853"
			+ "52867e6692ab18337ab7159c447befc10b", 16);
		g1 = new BigInteger("2");
		dhPar = new DHParameterSpec(p1, g1);
		
		/* Set DSA Parameter Spec */
		p2 = new BigInteger(
			"fca682ce8e12caba26efccf7110e526db078b05edecbcd1e"
			+ "b4a208f3ae1617ae01f35b91a47e6df63413c5e12ed089"
			+ "9bcd132acd50d99151bdc43ee737592e17", 16);
		q = new BigInteger(
			"962eddcc369cba8ebb260ee6b6a126d9346e38c5", 16);
		g2 = new BigInteger(
			"678471b27a9cf44ee91a49c5147db1a9aaf244f05a434d64"
			+ "86931d2d14271b9e35030b71fd73da179069b32e293563"
			+ "0e1c2062354d0da20a6c416e50be794ca4", 16);
		dsaPar = new DSAParameterSpec(p2, q, g2);
	}
	
	/** Get Default Parameter Spec */
	public static AlgorithmParameterSpec getDefaultSpec(String algorithm)
	{
		if (algorithm.equals("DH") || algorithm.equals("DiffieHellman"))
		{
			dhPar = new DHParameterSpec(p1, g1);
			return dhPar;
		}
		else if (algorithm.equals("DSA"))
		{
			dsaPar = new DSAParameterSpec(p2, q, g2);
			return dsaPar;
		}
		else
		{
			return null;
		}
	}
	
	/** Generate Random Key Pair based on key size */
	public static KeyPair generateKeyPair(String algorithm, int keySize)
		throws GeneralSecurityException
	{
		/* Instantiate Key Pair Generator */
		KeyPairGenerator keyPairGenerator
			= KeyPairGenerator.getInstance(algorithm, provider.getName());
		
		/* Initialise Key Pair Generator */
		keyPairGenerator.initialize(keySize);
		
		/* Generate Key Pair */
		return keyPairGenerator.generateKeyPair();
	}
	
	/** Generate Random Key Pair from Given Parameters */
	public static KeyPair generateKeyPair(String algorithm, AlgorithmParameterSpec spec)
	throws GeneralSecurityException
	{
		/* Instantiate Key Pair Generator */
		KeyPairGenerator keyPairGenerator
			= KeyPairGenerator.getInstance(algorithm, provider.getName());
		
		/* Initialise Key Pair Generator */
		keyPairGenerator.initialize(spec);
		
		/* Generate Key Pair */
		return keyPairGenerator.generateKeyPair();
	}
	
	
	/**
	 * Transform the specified byte into a Hex String form.
	 *
	 * @param bArray	The byte array to transform.
	 * @return		The Hex String.
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
	
	
	public static void main(String[] args)
	{
		try
		{
			/* make sure that we have access to the safenet provider */
			provider = new SAFENETProvider();
			Security.addProvider(provider);
			
			/* Initialise the default keyspecs */
			println("Initialize");
			initDefaultSpec();
			
			/* use Diffie-Hellman key pairs */
			String algorithm		= "DH" ;
			
			/* The key agreement will use a shared DES key */
			String keyType			= "DES";
			
			/* First create an algorithm spec based on Diffie-Hellman */
			AlgorithmParameterSpec spec = getDefaultSpec(algorithm);
			
			/* Create alice's key pair */
			println("Create Alice's Key Pair");
			KeyPair aliceKeyPair = generateKeyPair(algorithm, spec);
			PublicKey alicePub = aliceKeyPair.getPublic();
			PrivateKey alicePriv = aliceKeyPair.getPrivate();
			
			/* Alice encodes her public key, and sends it over to Bob. */
			byte[] alicePubKeyEnc = alicePub.getEncoded();
			
			/* Bob now uses alice's public key to get the parameters */
			KeyFactory bobKeyFac = KeyFactory.getInstance(algorithm, provider.getName());
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc);
			PublicKey alicePubKey = bobKeyFac.generatePublic(x509KeySpec);

			
			/* Bob gets the DH parameters associated with Alice's public key.
			 * He must use the same parameters when he generates his own key
			 * pair. Likewise Bob will then send his encrypted public key to
			 * Alice.
			 */
			println("Create Bob's Key Pair");
			DHParameterSpec	dhParamSpec = ((DHPubKey)alicePubKey).getParams();
			
			/* Create bob's key pair */
			KeyPair bobKeyPair = generateKeyPair(algorithm, dhParamSpec);
			PublicKey bobPub = bobKeyPair.getPublic();
			PrivateKey bobPriv = bobKeyPair.getPrivate();
			
			/* Bob encodes his public key, and sends it over to Alice. */
			byte[] bobPubEnc = bobPub.getEncoded();
			
			
			/* Alice extracts Bob's public key */
			println("Alice performs Key Agreement and generates a shared DES key");
			KeyFactory aliceKeyFac = KeyFactory.getInstance(algorithm, provider.getName());
			x509KeySpec = new X509EncodedKeySpec(bobPubEnc);
			PublicKey bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);

			
			/* Get instance of Key Agreement for Alice */
			KeyAgreement keyAgreementAlice = KeyAgreement.getInstance(algorithm, provider.getName());
			
			/* Initialise Key Agreement with Private Key */
			keyAgreementAlice.init(alicePriv);
			
			/* Do Alice's KeyAgreement Phase with Bob's Public Key */
			keyAgreementAlice.doPhase( bobPubKey, true);
			
			/* Generate Alice's Secret Value */
			SecretKey aliceSecretKey = keyAgreementAlice.generateSecret(keyType);
			
			
			
			/* Now Instantiate Key Agreement for Bob */
			println("Bob performs Key Agreement and generates a shared DES key");
			KeyAgreement keyAgreementBob = KeyAgreement.getInstance(algorithm, provider.getName());
			
			/* Initialise Key Agreement with Private Key */
			keyAgreementBob.init(bobPriv);
			
			/* Do Bob's KeyAgreement Phase with Alice's Public Key */
			keyAgreementBob.doPhase( alicePubKey, true);
			
			/* Generate Bob's secret value */
			SecretKey bobSecretKey = keyAgreementBob.generateSecret(keyType);
			
			/*
			 * Verify that they are the same by enciphering some text
			 * with Bob's secret key, then decrypting with Alice's secret
			 * key. Since they are shared secrets the decryption should recover
			 * the plain text.
			 */
			println("Bob encrypts sample text and Alice decrypts the result using shared key");
			println("Plain text is:\n"+"This is a test of shared secret keys");
			
			Cipher bobCipher = Cipher.getInstance("DES/ECB/PKCS5Padding",
                                    provider.getName());
			
			/* set up cipher to encrypt using Bob's secret key */
			bobCipher.init(Cipher.ENCRYPT_MODE, bobSecretKey);
			
			byte[] cleartext = "This is a test of shared secret keys".getBytes(StandardCharsets.US_ASCII);
			
			/* encrypt the plain text and display the cipher text */
			byte[] ciphertext = bobCipher.doFinal(cleartext);
			println("Cipher text from Bob:\n"+ bytesToHexStr(ciphertext));
			
			
			
			/*
			 * Alice decrypts the cipher text, using DES in ECB mode
			 * using the shared secret key.
			 */
			println("Alice decrypts cipher text");
			
			Cipher aliceCipher = Cipher.getInstance("DES/ECB/PKCS5Padding",
                                    provider.getName());
			
			/* initialize Alice's cipher to decrypt using alice's secret key */
			aliceCipher.init(Cipher.DECRYPT_MODE, aliceSecretKey);
			
			/* do the decryption and display the resulting text */
			byte[] decrypt_text = aliceCipher.doFinal(ciphertext);
			String resultText = new String(decrypt_text, StandardCharsets.US_ASCII);
			println("Decrypted cipher text:\n"+ resultText);
			
			/* Is Alice's decrypted text the same as Bob's plain text ? */
			if (java.util.Arrays.equals(cleartext, decrypt_text))
			{
				System.out.println("DES in ECB mode: clear text and decrypted text are the SAME");
			}
			else /* Alice did not recover the plain text */
			{
				println("DES in ECB mode: decrypted text does not match cleartext");
			}
		}
		catch (RuntimeException ex)
		{
			ex.printStackTrace();
		}
		catch (Exception ex)
		{
			ex.printStackTrace();
		}
		
	}
}

/*
 * $Id: prod/jprov_sfnt/samples/safenet/ptkj/samples/signverify/SignVerify.java 1.1 2009/11/05 10:30:17GMT-05:00 Sorokine, Joseph (jsorokine) Exp  $
 * $Author: Sorokine, Joseph (jsorokine) $
 *
 * Copyright (c) 2002 Safenet Technologies
 * All Rights Reserved - Proprietary Information of Safenet Technologies
 * Not to be Construed as a Published Work.
 *
 * $Source: prod/jprov_sfnt/samples/safenet/ptkj/samples/signverify/SignVerify.java $
 * $Revision: 1.1 $
 * $Date: 2009/11/05 10:30:17GMT-05:00 $
 * $State: Exp $
 * Created on 3 October 2002, 11:10
 */

/**
 * SignVerify is a small application that creates a key pair then uses the
 * private key to sign a block of text and then uses the public key to verify
 * the signature. The test is run twice, firstly with a generated key pair
 * then with a key pair created using a KeySpecification.
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
 * Sign and verify a message. This class demonstrates how to 
 * sign and verify a message using RSA and DSA.
 *
 */
public class SignVerify
{
	
	static public Provider provider = null;
	static SecureRandom randomizer = null;
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
	
	/** Generate Random Key Pair based */
	public static KeyPair generateKeyPair(String algorithm, int keySize)
		throws GeneralSecurityException
	{
		/* Instantiate Key Pair Generator */
		KeyPairGenerator keyPairGenerator
			= KeyPairGenerator.getInstance(algorithm, provider.getName());
		
		/* Initialise Key Pair Generator */
		keyPairGenerator.initialize(keySize, randomizer);
		
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
		keyPairGenerator.initialize(spec, randomizer);
		
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
	
	
	/** 
	 * Sign and verify message using RSA. 
	 * @param text is a String we wish to sign then verify.
	 */
	public static final boolean signVerifyRSA(String text)
	{
		try {
			/* RSA key key-size */
			int    keySize			= 512;
			
			/* Create key pair */
			println("Create RSA Key Pair for Alice");
			KeyPair keyPair = null;
			
			/* creating an 'algorithm' key pair based on the desired key size */
			keyPair = generateKeyPair("RSA", keySize);
			PublicKey pubKey = keyPair.getPublic();
			PrivateKey privKey = keyPair.getPrivate();
			
			println("");
			println("Key Pair created");
			
			/*
			 * Now we have a key pair we need a signing algorithm to generate the
			 * signature. We will need an RSA based one.
			 *
			 * Available sign/verify algorithms are:
			 *		DSARaw, MD2WithRSA, MD5WithRSA, PKCS#1RSA, RIPEMD128withRSA,
			 *		RIPEMD160withRSA, SHA1withDSA, SHA1withRSA, X.509RSA
			 */
			String sigAlgorithm = "MD5WithRSA";
			println("");
			println("Sign block of text using "+sigAlgorithm);
			
			/* get an instance of a signature object
			 */
			Signature signature = Signature.getInstance( sigAlgorithm, provider.getName());
			
			/* initialize the object using our private key */
			signature.initSign(privKey);
			
			/* update the signature with the text, repeat with as many blocks
			 * of text as needed
			 */
			signature.update(text.getBytes(StandardCharsets.US_ASCII));
			/* extract the signature bytes */
			byte[] sigBytes = signature.sign();
			
			println("Value of signature is:\n"+bytesToHexStr(sigBytes));
			println(""); println("");
			
			println("Verify block of text");
			
			/* Verification is similar to generating the signature, 
			 * first get an instance and initialize 
			 */
			Signature verifySig = Signature.getInstance(sigAlgorithm, provider.getName());
			verifySig.initVerify(pubKey);
			
			/* update with the message bytes */
			verifySig.update(text.getBytes(StandardCharsets.US_ASCII));
			
			/* pass the supplied signature and get back a boolean on the result */
			if ( verifySig.verify(sigBytes) == false )
				return false;

			/*
			 * Lets reuse the key pair with a different signing algorithm.
			 * Lets use SHA224withRSA
			 */
			sigAlgorithm = "SHA224WithRSA";
			println("");
			println("Sign block of text using "+sigAlgorithm);
			
			/* get an instance of a signature object
			 */
			signature = Signature.getInstance( sigAlgorithm, provider.getName());
			
			/* initialize the object using our private key */
			signature.initSign(privKey);
			
			/* update the signature with the text, repeat with as many blocks
			 * of text as needed
			 */
			signature.update(text.getBytes(StandardCharsets.US_ASCII));
			/* extract the signature bytes */
			sigBytes = signature.sign();
			
			println("Value of signature is:\n"+bytesToHexStr(sigBytes));
			println(""); println("");
			
			println("Verify block of text");
			
			/* Verification is similar to generating the signature, 
			 * first get an instance and initialize 
			 */
			verifySig = Signature.getInstance(sigAlgorithm, provider.getName());
			verifySig.initVerify(pubKey);
			
			/* update with the message bytes */
			verifySig.update(text.getBytes(StandardCharsets.US_ASCII));
			
			/* pass the supplied signature and get back a boolean on the result */
			return verifySig.verify(sigBytes);
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
		
		return false;
	}
	
	
	/** Sign and verify message using DSA */
	public static final boolean signVerifyDSA(String text)
	{
		try {
			String sigAlgorithm = "SHA1withDSA";
			
			/* create an algorithm spec based on DSA */
			AlgorithmParameterSpec spec = getDefaultSpec("DSA");
			
			println("Create DSA Key Pair");
			println("");
			
			/* Create the key pair based on the default DSA key spec */
			KeyPair keyPair = generateKeyPair("DSA", spec);
			
			PublicKey pubKey = keyPair.getPublic();
			PrivateKey privKey = keyPair.getPrivate();
			
			/* initialize the signature */
			println("Sign block of text using "+sigAlgorithm);
			Signature signature = Signature.getInstance(sigAlgorithm, provider.getName());
			signature.initSign(privKey);
			
			/* update the signature using the same block of text */
			signature.update(text.getBytes(StandardCharsets.US_ASCII));
			
			/* get bytes representing the signature */
			byte[] sigBytes = signature.sign();
			
			println("Value of signature is:\n"+bytesToHexStr(sigBytes));
			println(""); println("");
			
			println("Verify block of text");
			
			/* initialize for verification */
			Signature verifySig = Signature.getInstance(sigAlgorithm, provider.getName());
			verifySig.initVerify(pubKey);
			
			/* update with the message bytes */
			verifySig.update(text.getBytes(StandardCharsets.US_ASCII));
			
			/* get the boolean verification by passing in the signature */
			return  verifySig.verify(sigBytes);
			
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
		
		return false;
	}
	
	
	/**
	 * @param args the command line arguments
	 */
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
			
			/* Part 1: Sign and verify a block of text using generated keys */
			println("");
			println("Part 1: Sign and verify a block of text using generated keys");
			println("");
			
			/* Create Diffie-Hellman (DH), DSA or RSA key pairs */
			/* Choose RSA so that we can test using keys without KeySpecs */

			/* set the text of the message to sign */
			String text = "Twas brillig, and the slithy toves did gyre and gimble in the wabe. - Lewis Carrol";
			
			if (signVerifyRSA(text))
			{
				println("");
				println("Signature verification SUCCEEDED");
				println("");
			}
			else
			{
				println("");
				println("Signature verification FAILED");
				println("");
			}
			
			/* ---------------------------------------------------------- */
			/*
			 * Part 2: Sign and verify a block of text using keys
			 * based on KeySpecifications. In this case DSA for the public key
			 * mechanism and SHA1withDSA for the signature algorithm.
			 *
			 */
			println("");
			println("");
			println("");
			println("Part 2: Sign and verify a block of text using keys");
			println("based on KeySpecifications.");
			println("");
			
			
			/* show the results */
			if (signVerifyDSA(text))
			{
				println("");
				println("Signature verification SUCCEEDED");
				println("");
			}
			else
			{
				println("");
				println("Signature verification FAILED");
				println("");
			}
		}
		catch (Exception ex)
		{
			ex.printStackTrace();
		}
	}
}

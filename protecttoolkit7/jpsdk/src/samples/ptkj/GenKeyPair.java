/*
 * $Id: prod/jprov_sfnt/samples/safenet/ptkj/samples/keypair/GenKeyPair.java 1.1 2009/11/05 10:29:36GMT-05:00 Sorokine, Joseph (jsorokine) Exp  $
 * $Author: Sorokine, Joseph (jsorokine) $
 *
 * Copyright (c) 2002 Safenet Technologies
 * All Rights Reserved - Proprietary Information of Safenet Technologies
 * Not to be Construed as a Published Work.
 *
 * $Source: prod/jprov_sfnt/samples/safenet/ptkj/samples/keypair/GenKeyPair.java $
 * $Revision: 1.1 $
 * $Date: 2009/11/05 10:29:36GMT-05:00 $
 * $State: Exp $
 *
 * Created on 3 October 2002, 16:20
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

import au.com.safenet.crypto.provider.SAFENETProvider;
import au.com.safenet.crypto.spec.*;
import au.com.safenet.crypto.provider.*;

/**
 * Generate a key pair. This sample generates key pairs for Diffie-Hellman, DSA
 * or RSA (512 or 1024 bits).
 *
 */
public class GenKeyPair
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
	
	/** Creates default key specifications for Diffie-Hellman and DSA */
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
	 * MAIN
	 */
	public static void main(String[] args)
	{
		try
		{
			/* make sure that we have access to the safenet provider */
			provider = new SAFENETProvider();
			Security.addProvider(provider);
			
			/* Initialise the default keyspecs */
			println("");
			println("Initialize");
			initDefaultSpec();
			
			/* use Diffie-Hellman (DH), DSA or RSA key pairs */
			String algorithm		= "RSA" ; /* can have values DH DSA or RSA */
			
			/* RSA key key-size */
			int    keySize			= 512;
			
			
			KeyPair keyPair = null;
			
			/* Instantiate Key Pair Generator */
			KeyPairGenerator keyPairGenerator
				= KeyPairGenerator.getInstance(algorithm, provider.getName());
			
			/* Initialise Key Pair Generator */
			if (algorithm.equals("DH") || algorithm.equals("DSA"))
			{
				AlgorithmParameterSpec spec = getDefaultSpec(algorithm);
				keyPairGenerator.initialize(spec);
			}
			else if (algorithm.equals("RSA"))
			{
				keyPairGenerator.initialize(keySize);
			}
			else
			{
				println("Unsupported Key Pair algorithm");
				System.exit(0);
			}
			
			/* generate the key pair */
			/* Create alice's key pair */
			println("Create "+algorithm+" Key Pair");
			keyPair = keyPairGenerator.generateKeyPair();
			
			PublicKey pubKey = keyPair.getPublic();
			//PrivateKey privKey = keyPair.getPrivate();
			
			/* show the public key */
			println("Key Pair created");
			if (algorithm.equals("RSA"))
				println("Public Key (hex):\n"+ ((RSAPublicKey)pubKey).getPublicExponent().toString(16));
			else if (algorithm.equals("DH"))
				println("Public Key (hex):\n"+ ((DHPubKey)pubKey).getY().toString(16));
			else if (algorithm.equals("DSA"))
				println("Public Key (hex):\n"+ ((DSAPublicKey)pubKey).getY().toString(16));
			
			println(""); println("");
			
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

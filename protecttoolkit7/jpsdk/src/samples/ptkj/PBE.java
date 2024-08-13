/*
 * Copyright (c) 2002 Safenet Technologies
 * All Rights Reserved - Proprietary Information of Safenet Technologies
 * Not to be Construed as a Published Work.
 */


import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.charset.*;

import au.com.safenet.crypto.provider.SAFENETProvider;
import au.com.safenet.crypto.spec.*;



/**
 * Sample code for Password Based Encryption.
 *
 */
public class PBE
{
	static public Provider provider = null;
	
	/** simplified use of System.out.println */
	static void println(String s)
	{
		System.out.println(s);
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
	 * Transform the specified Hex String into a byte array.
	 *
	 * @param s		the hex string to convert.
	 * @return		The resulting byte array.
	 */
	public static final byte[] hexStrToBytes(String	s)
	{
		byte[]	bytes;
		
		bytes = new byte[s.length() / 2];
		
		for (int i = 0; i < bytes.length; i++)
		{
			bytes[i] = (byte)Integer.parseInt(
			s.substring(2 * i, 2 * i + 2), 16);
		}
		
		return bytes;
	}
	
	
	
	/** Encrypt, Password Based Algorithm */
	public static byte[] encrypt(String algorithm,
								String password,
								String salt,
								int iterationCount,
								byte[] clearBytes) throws GeneralSecurityException
	{
		/* Generate Secret Key */
		PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(
		algorithm, provider.getName());
		SecretKey secretKey = keyFactory.generateSecret(pbeKeySpec);
		
		/* Set Salt and Iteration Count */
		PBEParameterSpec pbeParameterSpec
		= new PBEParameterSpec(salt.getBytes(StandardCharsets.US_ASCII), iterationCount);
		
		/* Instantiate Cipher */
		Cipher cipher = Cipher.getInstance(algorithm, provider.getName());
		
		/* Initialise Cipher */
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, pbeParameterSpec);
		
		/* Encrypt and Return Encrypted Bytes */
		return cipher.doFinal(clearBytes);
	}
	
	
	/** Decrypt, Password Based Algorithm */
	public static byte[] decrypt(String algorithm,
								String password,
								String salt,
								int iterationCount,
								byte[] encryptedBytes) throws GeneralSecurityException
	{
		/* Generate Secret Key */
		PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(algorithm, provider.getName());
		SecretKey secretKey = keyFactory.generateSecret(pbeKeySpec);
		
		/* Set Salt and Iteration Count */
		PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt.getBytes(StandardCharsets.US_ASCII), iterationCount);
		
		/* Instantiate Cipher */
		Cipher cipher = Cipher.getInstance(algorithm, provider.getName());
		
		/* Initialise Cipher */
		cipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParameterSpec);
		
		/* Decrypt and Return Decrypted Bytes */
		return cipher.doFinal(encryptedBytes);
	}
	
	

	public static void main(String[] args)
	{
		/* Specify the plain text that is to be encrypted */
		String plainText = "If it was so, it might be; and it were so, it would be; but as it isn't, it ain't. That's logic. - Lewis Carrol ";
		
		byte[] cipherText = null;
		String decryptText = null;
		
		/* ... and the password to be used to construct our key */
		String password = "myTestPwd";
		/* the 'salt' with the password will generate our key */
		String salt = "12345";
		
		try
		{
			/* make sure that we have access to the safenet provider */
			provider = new SAFENETProvider();
			Security.addProvider(provider);
			
			
			/* ENCRYPT using PBE. We will use PBEWithSHA1AndTripleDES */
			/*
			 * Supported PBE algorithms are:
			 *		PBEWithMD2AndDES
			 *		PBEWithMD5AndCAST
			 *		PBEWithMD5AndDES
			 *		PBEWithSHA1AndCAST
			 *		PBEWithSHA1AndTripleDES
			 */
			//			String algorithm = "PBEWithMD2AndDES";
			//			String algorithm = "PBEWithMD5AndCAST";
			//			String algorithm = "PBEWithMD5AndDES";
			//			String algorithm = "PBEWithSHA1AndCAST";
			String algorithm = "PBEWithSHA1AndTripleDES";
			println("");
			println("Password Based Encryption. Algorithm: "+algorithm);
			println("");
			println("Plain text before encryption : \n"+plainText);
			cipherText = encrypt(algorithm, password, salt, 16, plainText.getBytes(StandardCharsets.US_ASCII));
			
			/* display resulting bytes */
			String hexStr = bytesToHexStr(cipherText);
			println("");
			System.out.println("Result of Encrypt : \n"+hexStr);
			
			/* DECRYPT -- same algorithm / password / salt / iteration count */
			println("");
			System.out.println("Now decrypt bytes using PBE");
			byte[] decryptBytes = decrypt(algorithm, password, salt, 16, cipherText);
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

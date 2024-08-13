/*
 * $Id: prod/jprov_sfnt/samples/safenet/ptkj/samples/keywrap/KeyWrap.java 1.1 2009/11/05 10:29:51GMT-05:00 Sorokine, Joseph (jsorokine) Exp  $
 * $Author: Sorokine, Joseph (jsorokine) $
 *
 * Copyright (c) 2002 Safenet Technologies
 * All Rights Reserved - Proprietary Information of Safenet Technologies
 * Not to be Construed as a Published Work.
 *
 * $Source: prod/jprov_sfnt/samples/safenet/ptkj/samples/keywrap/KeyWrap.java $
 * $Revision: 1.1 $
 * $Date: 2009/11/05 10:29:51GMT-05:00 $
 * $State: Exp $
 */


import javax.crypto.*;
import javax.crypto.spec.*;

import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.*;

import au.com.safenet.crypto.provider.SAFENETProvider;
import au.com.safenet.crypto.WrappingKeyStore;
import au.com.safenet.crypto.spec.*;

/**
 * Class to demonstrate the Wrap/Unwrap features of ptkj.
 *
 * It should be noted that these features are <b>NOT</b> part of the
 * standard JCA/JCE interface - they are proprietary extensions.
 */
public class KeyWrap
{
	/** simplified use of System.out.println */
	static void println(String s)
	{
		System.out.println(s);
	}
	
	/** program usage */
	static void usage()
	{
		println("java ...KeyWrap [-list] -wrapKey <wrapkeyname> -unwrapKey <unwrapkeyname> [-password <password>] [-wrapData <data>]");
		println("");
		println("list           list names of keys");
		println("wrapkeyname    name of the key to use for wrapping");
		println("unwrapkeyname  name of the key to use for unwrapping");
		println("password       keystore password. Required if the wrap/unwrap keys are private");
		println("");
		
		System.exit(1);
	}
	
	/** main entry point */
	public static void main(String[] args)
	{
		String wrapKeyName = null;
		String unwrapKeyName = null;
		String password = null;
		boolean listStore = false;
		
		/*
		 * process command line arguments. Supports:
		 *		wrap a key
		 *		unwrap a key
		 *		password to keystore
		 *		list all accessible keys in keystore
		 */
		for (int i = 0; i < args.length; ++i)
		{
			if (args[i].equalsIgnoreCase("-wrapKey"))
			{
				if (++i >= args.length)
				{
					println("wrapKey not found");
					usage();
				}
				
				wrapKeyName = args[i];
			}
			else if (args[i].equalsIgnoreCase("-unwrapKey"))
			{
				if (++i >= args.length)
				{
					println("unwrapKey not found");
					usage();
				}
				
				unwrapKeyName = args[i];
			}
			else if(args[i].equalsIgnoreCase("-password"))
			{
				if (++i >= args.length)
				{
					println("password not found");
					usage();
				}
				
				password = args[i];
			}
			else if (args[i].equalsIgnoreCase("-list"))
			{
				listStore = true;
			}
			else
			{
				println("unknown param at i="+i);
				usage();
			}
		}

		try
		{
			Provider provider = new SAFENETProvider();
			
			/* make sure that we have access to the safenet provider */
			Security.addProvider(provider);
			
			/* get the safenet keystore - access to the adapter */
			KeyStore keyStore = KeyStore.getInstance("CRYPTOKI", provider.getName());
			
			/* load the keystor - presenting the password if required */
			if (password == null)
			{
				keyStore.load(null, null);
			}
			else
			{
				keyStore.load(null, password.toCharArray());
			}
			
			/* if selected list all the aliases of keys in the store */
			if (listStore)
			{
				try
				{
					for (Enumeration<String> enumKeys = keyStore.aliases() ;enumKeys.hasMoreElements();)
					{
						println(enumKeys.nextElement().toString());
					}
					System.exit(0);
				}
				catch (KeyStoreException kse)
				{
					println("Error: "+kse.getMessage());
					usage();
				}
			}
			
			/* Make sure we have the information we require */
			if (wrapKeyName == null || unwrapKeyName == null)
			{
				println("wrapKeyName or unwrapKeyName is null");
				usage();
			}
			
			/*
			 * Validate that the specified keys exist
			 */
			if (!keyStore.isKeyEntry(wrapKeyName))
			{
				println(wrapKeyName + " is not a recognised key");
				System.exit(2);
			}
			
			if (!keyStore.isKeyEntry(unwrapKeyName))
			{
				println(unwrapKeyName + " is not a recognised key");
				System.exit(2);
			}
			
			/*
			 * Get the wrap and unwrap keys
			 */
			
			println("Get wrap/unwrap keys from keystore");
			Key wrapKey = keyStore.getKey(wrapKeyName, null);
			Key unwrapKey = keyStore.getKey(unwrapKeyName, null);
			
			/*
			 * The wrapping transformation depends on the key type
			 */
			
			String transformation = null;
			String wrapAlg = wrapKey.getAlgorithm();
			
			println("Wrap key algorithm found was: "+wrapAlg);
			
			if (wrapAlg.equals("DES"))
			{
				transformation = "DES/ECB/NoPadding";
			}
			else if (wrapAlg.equals("DESede"))
			{
				transformation = "DESede/ECB/NoPadding";
			}
			else if (wrapAlg.equals("RSA"))
			{
				transformation = "RSA/ECB/NoPadding";
			}
			else if (wrapAlg.equals("RC4"))
			{
				transformation = "RC4";
			}
			else
			{
				/* there are others, but for this sample we don't care */
				println("unsupported wrapping key type : " + wrapAlg);
				System.exit(3);
			}
			

			/* Create a temporary key to be wrapped */
			KeyGenerator desKeyGen = KeyGenerator.getInstance("DES", provider.getName());
			Key desKey = desKeyGen.generateKey();

			/* wrap the generated key */

			/* get access to the wrapping functionality */
			WrappingKeyStore wrapKeyStore = WrappingKeyStore.getInstance("CRYPTOKI", provider.getName());

			/* get the algorithm of the key we are going to wrap */
			String alg = desKey.getAlgorithm();

			/* wrap the temporary key we generated */
			byte[] wrappedKey = wrapKeyStore.wrapKey(wrapKey, transformation, desKey);

			println(alg + " key wrapped using " + wrapKeyName + " and the " +
			transformation + " transformation");

			/* unwrap the key */
			Key unwrappedKey = wrapKeyStore.unwrapKey(unwrapKey,
								transformation,
								wrappedKey,
								alg);

			println(alg + " key unwrapped using " + unwrapKeyName + " and the " +
			transformation + " transformation");
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


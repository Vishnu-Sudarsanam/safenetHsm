/*
 * $Id: prod/jprov_sfnt/samples/safenet/ptkj/samples/keystore/KeyStoreSample.java 1.1 2009/11/05 10:29:43GMT-05:00 Sorokine, Joseph (jsorokine) Exp  $
 * $Author: Sorokine, Joseph (jsorokine) $
 *
 * Copyright (c) 2002 Safenet Technologies
 * All Rights Reserved - Proprietary Information of Safenet Technologies
 * Not to be Construed as a Published Work.
 *
 * $Source: prod/jprov_sfnt/samples/safenet/ptkj/samples/keystore/KeyStoreSample.java $
 * $Revision: 1.1 $
 * $Date: 2009/11/05 10:29:43GMT-05:00 $
 * $State: Exp $
 *
 * Created on 30 September 2002, 14:08
 */


import javax.crypto.*;
import javax.crypto.spec.*;

import java.math.*;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.*;




/**
 * Sample code for the use of the KeyStore with the SAFENET provider. Note that
 * this example does a 'load' by default. 'Save's make no sense since once a
 * key is added to the key store it is already 'saved' to the hardware.
 *
 * It is not possible to save the SAFENET keystore to a file.
 */
public class KeyStoreSample
{
	/** simplified use of System.out.println */
	static void println(String s)
	{
		System.out.println(s);
	}
	
	/** program usage */
	static void usage()
	{
		println("java ...KeyStoreSample [-list] -password <password> -add <keyname> -delete <keyname>");
		println("");
		println("list           list names of keys in store");
		println("password       for access to private keys");
		println("add            add a random des key");
		println("delete         remove a named key");
		println("");
		
		System.exit(1);
	}
	
	
	/** main entry point */
	public static void main(String[] args)
	{
		String addKeyName = null;
		String delKeyName = null;
		String password = null;
		
		boolean listStore = false;
		
		if (args.length == 0)
			usage();
		
		/*
		 * process command line arguments. Supported functions are:
		 *		list
		 *		password
		 *		add a key
		 *		delete a key
		 */
		for (int i = 0; i < args.length; ++i)
		{
			if (args[i].equalsIgnoreCase("-list"))
			{
				listStore = true;
			}
			else if (args[i].equalsIgnoreCase("-password"))
			{
				if (++i >= args.length || args[i].charAt(0) == '-')
				{
					usage();
				}
				
				password = args[i];
			}
			else if(args[i].equalsIgnoreCase("-add"))
			{
				if (++i >= args.length)
				{
					usage();
				}
				
				addKeyName = args[i];
			}
			else if(args[i].equalsIgnoreCase("-delete"))
			{
				if (++i >= args.length || args[i].charAt(0) == '-')
				{
					usage();
				}
				
				delKeyName = args[i];
			}
			else
			{
				println("unknown param at i="+i);
				usage();
			}
		}
		
		
		
		try
		{
			/* make sure that we have access to the safenet provider */
			Provider p = new au.com.safenet.crypto.provider.SAFENETProvider();
			Security.addProvider(p);
			
			/* get the safenet keystore - access to the adapter */
			KeyStore keyStore = KeyStore.getInstance("CRYPTOKI", p.getName());
			
			/* LOAD the keystore from the adapter - presenting the password if required */
			if (password == null)
			{
				keyStore.load(null, null);
			}
			else
			{
				keyStore.load(null, password.toCharArray());
			}
			
			/* ADD a random des key to the store */
			if (addKeyName != null)
			{
				/* This key cannot be added to the keystore if it already exists */
				if (keyStore.containsAlias(addKeyName))
				{
					println("");
					println("Key name already exists");
					println("");
					usage();
				}

				/*
				 * The usual practice when creating keys is to create or get an 
				 * instance of a SecureRandom object as a secure source of random
				 * numbers. For the SAFENET provider however this is not necessary
				 * since a secure random number source is supplied internally.
				 *
				 * Hence, here we will not use a SecureRandom object.
				 */
				
				/*
				 * Generate a secret DES key. Get a key generator instance,
				 * initialize it and then generate the Key. We will be creating
				 * a DES key using the SAFENET provider.
				 */
				KeyGenerator keyGen = KeyGenerator.getInstance("DES", p.getName());
				
				/*
				 * init the generator with the key size in bits
				 */
				keyGen.init( 64 );
				
				/* create the key */
				SecretKey skey = keyGen.generateKey();

				/* 
				 * Add the key to the key store. ERACAOM does not support
				 * key by key password access, if a password was supplied 
				 * then a login session to the default slot has been made
				 * and any keys created will be private. No password will
				 * be needed to add the keys to the key store.
				 */
				keyStore.setKeyEntry(addKeyName, skey, null, null);
			}
			
			/* DELETE a key from the keystore */
			if (delKeyName != null)
			{
				/*
				 * Validate that the specified key exists
				 */
				if (!keyStore.isKeyEntry(delKeyName))
				{
					println(delKeyName + " is not a recognised key");
					System.exit(2);
				}
				/* the key exists so delete it */
				keyStore.deleteEntry(delKeyName);
			}
			
			/* LIST all the aliases of keys in the store */
			if (listStore)
			{
				try
				{
					/* get an enumeration of all the key names (aliases), print each one */
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
			
			
		}
		catch (Exception ex)
		{
			ex.printStackTrace();
		}
	}
}


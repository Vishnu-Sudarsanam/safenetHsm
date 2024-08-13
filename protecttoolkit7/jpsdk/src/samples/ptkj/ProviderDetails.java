/*
 * Copyright (c) 2002 Safenet Technologies
 * All Rights Reserved - Proprietary Information of Safenet Technologies
 * Not to be Construed as a Published Work.
 */


import javax.crypto.*;
import javax.crypto.spec.*;

import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;

/**
 * Provider Details. Options include the ability to list the names of all
 * the loaded providers or to display the details of a named provider.
 */
public class ProviderDetails
{
    /** simplified use of System.out.println */
    static void println(String s)
    {
        System.out.println(s);
    }

    static void usage()
    {
        println("java ...ProviderDetails  [-list] -providerName <providername>");
        println("");
        println("list               list available providers");
        println("providername       Name of an existing provider");
        println("");

        System.exit(1);
    }

    public static void main(String[] args)
    {
        String providerClass = null;
        String providerName = null;
        boolean listProviders = false;

        /*
         * process command line arguments
         * Supported features:
         *        list all provider names
         *        providerName -- print details of the named provider
         */
        for (int i = 0; i < args.length; ++i)
        {
            if (args[i].equalsIgnoreCase("-providerName"))
            {
                if (++i >= args.length)
                    usage();

                providerName = args[i];
            }
            else if (args[i].equalsIgnoreCase("-list"))
            {
                listProviders = true;
            }
            else
            {
                usage();
            }
        }

        /* One option must be selected: providerName for details
         * or a request for list
         */
        if (providerName == null && !listProviders)
        {
            usage();
        }

        try
        {
            try
            {
                AddProvider("au.com.safenet.crypto.provider.SAFENETProvider");
            }
            catch (ClassNotFoundException classEx)
            {
                println("Cannot find SAFENET Provider. Please check that the provider is in the Java search path");
            }

            println("");
            /* check if list of providers requested */
            if (listProviders)
            {
                /* list all the providers */
                for (Provider p: Security.getProviders())
                {
                    println(p.getName());
                }
            }
            else
            {
                /* display details of the named provider */
                /*
                * NOTE: SecurityProvider is not part of ptkj but can be found
                * in the same directory as this file.
                */
                SecurityProvider secProv = new SecurityProvider(providerName);
                Provider p = secProv.getProvider();

                println(secProv.getName());
                println("Info:");
                println("    " + p.getInfo());
                secProv.dumpAll();
            }
            println("");
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
    }

    static Provider AddProvider(String providerClass) throws Exception
    {
        Class<?> c = Class.forName(providerClass);
        Class<? extends Provider> t = c.asSubclass(Provider.class);

        @SuppressWarnings("deprecation")
        Provider p = (Provider)t.newInstance();

        Security.addProvider(p);

        return p;
    }
}

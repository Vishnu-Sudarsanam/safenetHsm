/*
 * Copyright (c) 2002 Safenet Technologies
 * All Rights Reserved - Proprietary Information of Safenet Technologies
 * Not to be Construed as a Published Work.
 *
 */

import javax.crypto.*;
import javax.crypto.spec.*;

import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;

import java.util.*;

public class SecurityProvider
{
    public static void main(String args[])
    {
        System.out.println("This is not a standalone sample program");
        System.out.println("This class is used by the ProviderDetails sample");
        System.exit(0);
    }
    public SecurityProvider(String name) throws Exception
    {
        m_provider = Security.getProvider(name);

        if (m_provider == null)
        {
            throw new Exception("Provider " + name + " not found");
        }

        loadProperties();
    }

    public Provider getProvider()           {return m_provider;}

    public List<String> getCiphers()              {return m_ciphers;}
    public List<String> getKeyGenerators()        {return m_keyGenerators;}
    public List<String> getKeyPairGenerators()    {return m_keyPairGenerators;}
    public List<String> getDigests()              {return m_digests;}
    public List<String> getSignatures()           {return m_signatures;}
    public List<String> getMacs()                 {return m_macs;}
    public List<String> getKeyAgreements()        {return m_keyAgreements;}
    public List<String> getSecretKeyFactories()   {return m_secretKeyFactories;}
    public List<String> getKeyFactories()         {return m_keyFactories;}
    public List<String> getAlgorithmParameters()  {return m_algorithmParameters;}
    public List<String> getKeyStores()            {return m_keyStores;}
    public List<String> getSecureRandoms()        {return m_secureRandoms;}
    public List<String> getMisc()                 {return m_misc;}

    public String getName()                 {return m_provider.getName();}

    public void dumpCiphers()
    {
        System.out.println("Ciphers:");
        dumpProperties(m_ciphers);
    }

    public void dumpKeyGenerators()
    {
        System.out.println("KeyGenerators:");
        dumpProperties(m_keyGenerators);
    }

    public void dumpKeyPairGenerators()
    {
        System.out.println("KeyPairGenerators:");
        dumpProperties(m_keyPairGenerators);
    }

    public void dumpDigests()
    {
        System.out.println("Digests:");
        dumpProperties(m_digests);
    }

    public void dumpSignatures()
    {
        System.out.println("Signatures:");
        dumpProperties(m_signatures);
    }

    public void dumpMacs()
    {
        System.out.println("Macs:");
        dumpProperties(m_macs);
    }

    public void dumpKeyAgreements()
    {
        System.out.println("KeyAgreements:");
        dumpProperties(m_keyAgreements);
    }

    public void dumpSecretKeyFactories()
    {
        System.out.println("SecretKeyFactories:");
        dumpProperties(m_secretKeyFactories);
    }

    public void dumpKeyFactories()
    {
        System.out.println("KeyFactories:");
        dumpProperties(m_keyFactories);
    }

    public void dumpAlgorithmParameters()
    {
        System.out.println("AlgorithmParameters:");
        dumpProperties(m_algorithmParameters);
    }

    public void dumpKeyStores()
    {
        System.out.println("KeyStores:");
        dumpProperties(m_keyStores);
    }

    public void dumpSecureRandoms()
    {
        System.out.println("SecureRandoms:");
        dumpProperties(m_secureRandoms);
    }

    public void dumpMisc()
    {
        System.out.println("Miscelaneous:");
        dumpProperties(m_misc);
    }

    public void dumpAll()
    {
        dumpCiphers();
        dumpDigests();
        dumpMacs();
        dumpSignatures();
        dumpSecretKeyFactories();
        dumpKeyFactories();
        dumpKeyGenerators();
        dumpKeyAgreements();
        dumpKeyPairGenerators();
        dumpAlgorithmParameters();
        dumpSecureRandoms();
        dumpKeyStores();
        dumpMisc();
    }

    void dumpProperties(List<String> set)
    {
        for(String property:set)
        {
            System.out.println("    " + property);
        }
    }

    void loadProperties()
    {
        m_ciphers = new Vector<String>();
        m_keyGenerators = new Vector<String>();
        m_keyPairGenerators = new Vector<String>();
        m_digests = new Vector<String>();
        m_signatures = new Vector<String>();
        m_macs = new Vector<String>();
        m_keyAgreements = new Vector<String>();
        m_secretKeyFactories = new Vector<String>();
        m_keyFactories = new Vector<String>();
        m_algorithmParameters = new Vector<String>();
        m_keyStores = new Vector<String>();
        m_secureRandoms = new Vector<String>();
        m_misc = new Vector<String>();
        Hashtable<String, List<String> > map = new Hashtable<String, List<String> >();
        map.put("Cipher.", m_ciphers);
        map.put("KeyGenerator.",m_keyGenerators);
        map.put("KeyPairGenerator.",m_keyPairGenerators);
        map.put("MessageDigest.",m_digests);
        map.put("Signature.",m_signatures);
        map.put("Mac.",m_macs);
        map.put("KeyAgreement.",m_keyAgreements);
        map.put("SecretKeyFactory.",m_secretKeyFactories);
        map.put("KeyFactory.",m_keyFactories);
        map.put("AlgorithmParameters.",m_algorithmParameters);
        map.put("KeyStore.",m_keyStores);
        map.put("SecureRandom.",m_secureRandoms);

        Enumeration<?> e = m_provider.propertyNames();

        while (e.hasMoreElements())
        {
            String property = e.nextElement().toString();
            if(property.startsWith("Alg.Alias."))
                property = property.substring("Alg.Alias.".length());
            boolean found = false;

            for(Map.Entry<String, List<String> > entry: map.entrySet())
            {
                String k = entry.getKey();
                List<String> v = entry.getValue();
                if( property.startsWith(k))
                {
                    v.add(
                        property.substring(property.indexOf(k)+k.length())
                        );
                        found = true;
                        break;
                }
            }
            if(!found)
            {
                m_misc.add(property);
            }
        }
    }

    Provider m_provider;

    List<String> m_ciphers;
    List<String> m_keyGenerators;
    List<String> m_keyPairGenerators;
    List<String> m_digests;
    List<String> m_signatures;
    List<String> m_macs;
    List<String> m_keyAgreements;
    List<String> m_secretKeyFactories;
    List<String> m_keyFactories;
    List<String> m_algorithmParameters;
    List<String> m_keyStores;
    List<String> m_secureRandoms;
    List<String> m_misc;
}

/*
 * This code sample relates to token Cloning
 * Environment variables:
 * 1/ SW Emulator:
 * Path=<pat_to_jcprov.dll>;<path_to_cryptoki.dll>;%PATH%
 * 2/ HSM:
 * set ET_HSM_NETCLIENT_SERVERLIST=<server_IP_address>
 * Add <path_to_ethsm.dll> to PATH environment variable.
 **********
 * Compile:
 * javac.exe -cp .\;<path_to_jcprov.jar> CloneToken.java
 * Run:
 * java.exe -cp .\;<path_to_jcprov.jar> CloneToken
 */

import safenet.jcprov.*;
import safenet.jcprov.constants.*;
import safenet.jcprov.params.*;
import java.nio.charset.*;
import java.io.IOException;

public class CloneToken
{
    static String line = null;
    static String errStr = null;

    static boolean f_verbose;

    /** easy access to System.out.println */
    static public void println(String s)
    {
        System.out.println(s);
    }

    /** display runtime usage of the class */
    public static void usage()
    {
        println("java ...CloneToken [-src <slotId>] [-dst <slotId>] -password <password>");
        println("");
        println("-src   slot containing the source token");
        println("-dst   slot containing the target token");
        println("<password> user password of the slot.");
        println("");

        System.exit(1);
    }

   public static void replicateToken(boolean f_verbose, long srcSlot, long[] dstSlot, byte[] password)  throws IOException, CKR_Exception 
   {
    int i;
    /* replicate the source token to all destination tokens */
    for (i = 0; i < dstSlot.length; i++) {
        CK_SESSION_HANDLE targetSession = new CK_SESSION_HANDLE();
        long        targetslot = dstSlot[i];
        CK_OBJECT_HANDLE  targethKTC = new CK_OBJECT_HANDLE();

        CK_SESSION_HANDLE sourceSession = new CK_SESSION_HANDLE();
        CK_OBJECT_HANDLE  sourcehKTC = new CK_OBJECT_HANDLE();
        long          sourceKTC_len;
        LongRef lRef = new LongRef();

        if (f_verbose)
            System.out.println("Replicating " + srcSlot + " --> " + targetslot);

        /*Create a session on both source and target tokens*/

        long sesflags = CKF.RW_SESSION | CKF.SERIAL_SESSION;

        CryptokiEx.C_OpenSession(srcSlot, sesflags, null, null, sourceSession);
        CryptokiEx.C_OpenSession(targetslot, sesflags, null, null, targetSession);

        /* login as the user*/
        CryptokiEx.C_Login(sourceSession, CKU.USER, password, password.length);
        CryptokiEx.C_Login(targetSession, CKU.USER, password, password.length);

        /*Generate KTCs (Key Transport Cert) */

        CK_MECHANISM ktkmech = new CK_MECHANISM(CKM.GEN_KTK_ECC_P521);
        if (f_verbose)
            System.out.format("\tGenerating ephemeral certificates...");

        CryptokiEx.C_GenerateKey(sourceSession, ktkmech, null, 0, sourcehKTC);
        CryptokiEx.C_GenerateKey(targetSession, ktkmech, null, 0, targethKTC);
        if (f_verbose)
            println("done");

        /*Extract each KTC (Key Transport Cert) to provide to the other end*/
         CTUtilEx.CTU_GetAttributeValue(sourceSession, sourcehKTC,
                                               CKA.VALUE,
                                               null,
                                               0,
                                               lRef);

        /* allocate space for the cert attribute */
        byte[]     sourceKTC = new byte[(int)lRef.value];

        /* get the cert attribute */
        CTUtilEx.CTU_GetAttributeValue(sourceSession, sourcehKTC,
                                               CKA.VALUE,
                                               sourceKTC,
                                               sourceKTC.length,
                                               lRef);
         /* Get target Cert */
         CTUtilEx.CTU_GetAttributeValue(targetSession, targethKTC,
                                               CKA.VALUE,
                                               null,
                                               0,
                                               lRef);

        /* allocate space for the cert attribute */
        byte[]     targetKTC = new byte[(int)lRef.value];

        /* get the label attribute */
        CTUtilEx.CTU_GetAttributeValue(targetSession, targethKTC,
                                               CKA.VALUE,
                                               targetKTC,
                                               targetKTC.length,
                                               lRef);

        /* Form the KDE (Key Data Encrypt)*/
        CK_OBJECT_HANDLE             hTmp = new CK_OBJECT_HANDLE();

        if (f_verbose)
            System.out.format("\tDeriving shared secret...");

        /*Remember it's the peer's KTC you're passing*/
        CK_KDE_ECCP521_DERIVE_PARAMS kdeparams = new CK_KDE_ECCP521_DERIVE_PARAMS(targetKTC);
        CK_MECHANISM                 kdemech   = new CK_MECHANISM(CKM.GEN_KDE_ECC_P521_DERIVE_SEND, kdeparams);

        CryptokiEx.C_DeriveKey(sourceSession, kdemech, sourcehKTC, null, 0, hTmp);
        /*Copy the bMacTagout, to swap later on*/
        byte[] sourceMacTag = kdeparams.bMacTagOut.clone();

        kdeparams = new CK_KDE_ECCP521_DERIVE_PARAMS(sourceKTC);
        kdemech   = new CK_MECHANISM(CKM.GEN_KDE_ECC_P521_DERIVE_RECV, kdeparams);

        CryptokiEx.C_DeriveKey(targetSession, kdemech, targethKTC, null, 0, hTmp);
        /*Copy the bMacTagout, to swap later on*/
        byte[] targetMacTag = kdeparams.bMacTagOut.clone();

        if (f_verbose)
            println("done");
     
        /*Call token encryption/decryption*/
        if (f_verbose)
            System.out.format("\tTransferring slot %d...", srcSlot);

        /*Extract from the source*/
        /*Remember it's the peer's MacTag you're passing*/
        CK_KDE_TOKEN_WRAP_PARAMS tokparams   = new CK_KDE_TOKEN_WRAP_PARAMS(targetMacTag);
        CK_MECHANISM             tokmech     = new CK_MECHANISM (CKM.TOKEN_WRAP_KTK_ECC_P521, tokparams);

        CryptokiEx.C_EncryptInit(sourceSession, tokmech, new CK_OBJECT_HANDLE(CK.INVALID_HANDLE));

        /*Length prediction*/
        CryptokiEx.C_Encrypt(sourceSession, null, 0, null, lRef);

        byte[] largebuffer = new byte[(int)lRef.value];
        CryptokiEx.C_Encrypt(sourceSession, null, 0, largebuffer, lRef);

        /*Now pass the data over to the target*/
        tokparams   = new CK_KDE_TOKEN_WRAP_PARAMS(sourceMacTag);
        tokmech     = new CK_MECHANISM (CKM.TOKEN_WRAP_KTK_ECC_P521, tokparams);

        CryptokiEx.C_DecryptInit(targetSession, tokmech, new CK_OBJECT_HANDLE(CK.INVALID_HANDLE));

        CryptokiEx.C_Decrypt(targetSession, largebuffer, lRef.value, null, lRef);
        if (f_verbose)
            println("done");

        if (f_verbose)
            System.out.println("Replicating " + srcSlot + " --> " + targetslot + " successfully");

       Cryptoki.C_CloseSession(sourceSession);
       Cryptoki.C_CloseSession(targetSession);
     }
    }

    /** main execution method
     * @throws IOException */
    @SuppressWarnings("unused")
    public static void main(String[] args) throws IOException
    {
        long srcSlotId = 0;
        long dstSlotId = 1;
        CK_MECHANISM mech = null;//new CK_MECHANISM(CKM.INVALID_VALUE);
        String password = "";

        println("CloneToken Test - Start");

        /*
         * process command line arguments
         */

        for (int i = 0; i < args.length; ++i)
        {
            if(args[i].equalsIgnoreCase("-src"))
            {
                if (++i >= args.length)
                    usage();

                srcSlotId = Integer.parseInt(args[i]);
            } else
            if(args[i].equalsIgnoreCase("-dst"))
            {
                if (++i >= args.length)
                    usage();

                dstSlotId = Integer.parseInt(args[i]);
            }
            else if (args[i].equalsIgnoreCase("-password"))
            {
                if (++i >= args.length)
                    usage();

                password = args[i];
            }
            else if (args[i].equalsIgnoreCase("-v"))
            {
                f_verbose = true;
            }
            else
            {
                usage();
            }
        }

        /*
        * check parameters
        */
        if (password.length() == 0)
        {
            println("Password required - supply -password parameter");
            System.exit(1);
        }

        if (srcSlotId == dstSlotId)
        {
            println("srcSlotId must not equal dstSlotId");
            System.exit(1);
        }

        try
        {
            /*
             * Initialize Cprov
             */
           CK_C_INITIALIZE_ARGS initArgs = new CK_C_INITIALIZE_ARGS(0);
           CryptokiEx.C_Initialize(initArgs);

           long[] dstSlots = new long[1];
           dstSlots[0] = dstSlotId;   // just put one target slot in the list

           replicateToken(f_verbose, srcSlotId, dstSlots, password.getBytes(StandardCharsets.US_ASCII));

           println("Test Complete OK");
        }
        catch (CKR_Exception ex)
        {
           /*
            * A Cryptoki related exception was thrown
            */
           ex.printStackTrace();
           println(errStr + " Operation FAILED");
        }
        catch (Exception ex)
        {
           ex.printStackTrace();
        }
        finally
        {
            /*
             * All done with Cryptoki
             *
             * Note that we are not using CryptokiEx.
             */
             Cryptoki.C_Finalize(null);
         }
    }
}


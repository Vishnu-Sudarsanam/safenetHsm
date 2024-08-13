import safenet.jcprov.*;
import safenet.jcprov.constants.*;
import java.nio.charset.*;

/**
 * This class demonstrates the listing of Token objects.
 * <p>
 * Usage : java ...ListObjects [-slot &lt;slotId&gt;] [-password &lt;password&gt;]
 * <li><i>slotId</i>   slot containing the token objects to list - default (0)
 * <li><i>password</i> user password of the slot. If specified, private objects are also listed
 */
public class ListObjects
{

    /** easy access to System.out.println */
    static public void println(String s)
    {
        System.out.println(s);
    }

    /** display runtime usage of the class */
    public static void usage()
    {
        println("java ...ListObjects [-slot <slotId>] [-password <password>]");
        println("");
        println("<slotId>   slot containing the token objects to list - default (0)");
        println("<password> user password of the slot. If specified, private objects are also listed.");
        println("");

        System.exit(1);
    }

    /** main execution method */
    public static void main(String[] args)
    {
        CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
        long slotId = 0;
        String password = "";

        /*
         * process command line arguments
         */

        for (int i = 0; i < args.length; ++i)
        {
            if(args[i].equalsIgnoreCase("-slot"))
            {
                if (++i >= args.length)
                    usage();

                slotId = Integer.parseInt(args[i]);
            }
            else if (args[i].equalsIgnoreCase("-password"))
            {
                if (++i >= args.length)
                    usage();

                password = args[i];
            }
            else
            {
                usage();
            }
        }

        try
        {
            /*
             * Initialize Cprov so that the library takes care
             * of multithread locking
             */
            CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));

            /*
             * Open a session
             */
            CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION, null, null, session);

            /*
             * Login - if we have a password
             */
            if (password.length() > 0)
            {
                CryptokiEx.C_Login(session, CKU.USER, password.getBytes(StandardCharsets.US_ASCII), password.length());
            }

            println("Slot " + slotId + " Objects :-");
            listObjects(session);
        }
        catch (CKR_Exception ex)
        {
            /*
             * A Cryptoki related exception was thrown
             */
            ex.printStackTrace();
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
        }
        finally
        {
            /*
             * Logout in case we logged in.
             *
             * Note that we are not using CryptokiEx and we are not checking the
             * return value. This is because if we did not log in then an error
             * will be reported - and we don't really care because we are shutting down.
             */
            Cryptoki.C_Logout(session);

            /*
             * Close the session.
             *
             * Note that we are not using CryptokiEx.
             */
            Cryptoki.C_CloseSession(session);

            /*
             * All done with Cryptoki
             *
             * Note that we are not using CryptokiEx.
             */
             Cryptoki.C_Finalize(null);
        }
    }

    public static void listObjects(CK_SESSION_HANDLE session)
    {
        /* array of one object handles */
        CK_OBJECT_HANDLE[] hObjects = {new CK_OBJECT_HANDLE()};

        /* to receive the number of objects located */
        LongRef objectCount = new LongRef();

        /* for working with the located object */
        CK_OBJECT_HANDLE hObject = null;

        /* variables for string formatting */
        byte[] temp = new byte[512];
        LongRef lRef = new LongRef();

        /* string representations of the attribute values */
        String classString = null;
        String labelString = null;
        String privateString = null;


        /* initialise to find all objects */
        CryptokiEx.C_FindObjectsInit(session, null, 0);

        do
        {
            /* find the first/next object */
            CryptokiEx.C_FindObjects(session, hObjects, hObjects.length, objectCount);

            if (objectCount.value == 1)
            {
                hObject = hObjects[0];

                /*
                 * We have a few choices here. To get the attributes that we are
                 * interested in we could :-
                 *  1. create a CK_ATTRIBUTE template and get several at once
                 *  2. get them one at a time using CTU_GetAttributeValue
                 *
                 * We will get some attributes with each method.
                 */

                /*
                 * get the object class and timeStamp - by using a template
                 *
                 * Note that the initial values of the attributes does not matter,
                 * as they are output arguments.
                 */
                CK_ATTRIBUTE[] template =
                {
                    new CK_ATTRIBUTE(CKA.CLASS,         new CK_OBJECT_CLASS()),
                    new CK_ATTRIBUTE(CKA.PRIVATE,       new CK_BBOOL()),
                };

                CryptokiEx.C_GetAttributeValue(session,
                                               hObject,
                                               template,
                                               template.length);

                /* format the string representation of the object class attribute */
                lRef.value = temp.length;
                CTUtilEx.CTU_GetObjectClassString((CK_OBJECT_CLASS)(template[0].pValue),
                                                  temp,
                                                  lRef);

                classString = new String(temp, 0, (int)lRef.value, StandardCharsets.US_ASCII);

                /* format the string representation of the private attribute */
                privateString = "" + (CK_BBOOL)template[1].pValue;

                /*
                 * get the label attribute - using CTU_GetAttriubteValue.
                 *
                 * Before getting the attribute value, first we will determine the size
                 * of the attribute.
                 */
                CTUtilEx.CTU_GetAttributeValue(session,
                                               hObject,
                                               CKA.LABEL,
                                               null,
                                               0,
                                               lRef);

                /* allocate space for the label attribute */
                byte[] label = new byte[(int)lRef.value];

                /* get the label attribute */
                CTUtilEx.CTU_GetAttributeValue(session,
                                               hObject,
                                               CKA.LABEL,
                                               label,
                                               label.length,
                                               lRef);

                /* format the string representation of the label attribute */
                labelString = new String(label, 0, (int)lRef.value, StandardCharsets.US_ASCII);

                /* bring it all together */
                println("Class (" + classString + ") " +
                        "Label (" + labelString + ") " +
                        "Private (" + privateString + ")");
            }

        } while (objectCount.value == 1);

        /* all done */
        CryptokiEx.C_FindObjectsFinal(session);
    }
}

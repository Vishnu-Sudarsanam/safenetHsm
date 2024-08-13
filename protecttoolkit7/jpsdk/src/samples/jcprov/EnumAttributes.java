import safenet.jcprov.*;
import safenet.jcprov.constants.*;
import java.nio.charset.*;

/**
 * This class demonstrates the Eracom Technologies extension to enumerate all 
 * attributes of an object.
 * <p>
 * Usage : java ...EnumAttributes -name &lt;objectname&gt; [-slot &lt;slotId&gt;] [-password &lt;password&gt;]
 * <li><i>objectName</i>    name (label) of the object to enumerate over
 * <li><i>slotId</i>        slot containing the object - default (0)
 * <li><i>password</i>      user password of the slot. If specified, a private object is used
 */
public class EnumAttributes
{

    /** easy access to System.out.println */
    static public void println(String s)
    {
        System.out.println(s);
    }

    /** display runtime usage of the class */
    public static void usage()
    {
        println("java ...EnumAttributes -name <objectname> [-slot <slotId>] [-password <password>]");
        println("");
        println("<objectname>   name (label) of the object to enumerate over");
        println("<slotId>       slot containing the object - default (0)");
        println("<password>     user password of the slot. If specified, a private object is used");
        println("");

        System.exit(1);
    }

    /** main execution method */
    public static void main(String[] args)
    {
        CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
        long slotId = 0;
        String objectName = "";
        String password = "";
        boolean bPrivate = false;

        /*
         * process command line arguments
         */

        for (int i = 0; i < args.length; ++i)
        {
            if (args[i].equalsIgnoreCase("-name"))
            {
                if (++i >= args.length)
                    usage();

                objectName = args[i];
            }
            else if(args[i].equalsIgnoreCase("-slot"))
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

        if (objectName.length() == 0)
            usage();

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

                bPrivate = true;
            }

            /*
             * Locate the object
             */
            CK_OBJECT_HANDLE hObject = null;

            hObject = findObject(session, objectName, bPrivate);

            if (!hObject.isValidHandle())
            {
                println((bPrivate?"private ":"") +
                        "object (" + objectName + ") not found");
            }
            else
            {
                DisplayAttributes(session, hObject);
            }
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

    /**
     * Locate the specified object. We could not use CTUtil.CTU_FindObject, because
     * we do not know the object class, and we want to specify the PRIVATE attribute.
     *
     * @param session
     *  handle to an open session
     *
     * @param name
     *  name (label) of the object to locate
     *
     * @param bPrivate
     *  true if the object to locate is a private object
     */
    static CK_OBJECT_HANDLE findObject(CK_SESSION_HANDLE session,
                                       String name,
                                       boolean bPrivate)
    {
        /* array of one object handles */
        CK_OBJECT_HANDLE[] hObjects = {new CK_OBJECT_HANDLE()};

        /* to receive the number of objects located */
        LongRef objectCount = new LongRef();

        /* setup the template of the object to search for */
        CK_ATTRIBUTE[] template =
        {
            new CK_ATTRIBUTE(CKA.LABEL,     name.getBytes(StandardCharsets.US_ASCII)),
            new CK_ATTRIBUTE(CKA.PRIVATE,   new CK_BBOOL(bPrivate))
        };

        CryptokiEx.C_FindObjectsInit(session, template, template.length);

        CryptokiEx.C_FindObjects(session, hObjects, hObjects.length, objectCount);

        CryptokiEx.C_FindObjectsFinal(session);

        if (objectCount.value == 1)
        {
            /* return the handle of the located object */
            return hObjects[0];
        }
        else
        {
            /* return an object handle which is invalid */
            return new CK_OBJECT_HANDLE();
        }
    }

    /**
     * Display the attributes of the specified object.
     *
     * @param session
     *  handle to an open session
     *
     * @param hObject
     *  handle to the objects whose attributes are to be displayed
     */
    static void DisplayAttributes(CK_SESSION_HANDLE session,
                                  CK_OBJECT_HANDLE hObject)
    {
        /*
         * Special template for enumerating attributes.
         */
        CK_ATTRIBUTE[] template =
        {
            new CK_ATTRIBUTE()
        };

        /* we will do error checking manually, not using exceptions */
        CK_RV rv = null;

        while (true)
        {
            /*
             * Set the attribute type to the special value for enumeration.
             *
             * We can not use a CKA constant attribute type because the type of the
             * attribute is set by the call to C_GetAttributeValue.
             */
            template[0].type = new CK_ATTRIBUTE_TYPE(CKA.ENUM_ATTRIBUTE.longValue());

            /*
             * We can not set the pValue object of the attriubte because we do not know
             * what to set it to until we know the attribute type.
             */
            template[0].pValue = null;

            /* just for completeness */
            template[0].valueLen = 0;

            /*
             * Get the type and length of the next attribute
             */
            rv = Cryptoki.C_GetAttributeValue(session, hObject, template, 1);

            if (rv.equals(CKR.ATTRIBUTE_TYPE_INVALID))
            {
                /* all done, there are no more attriubtes */
                return;
            }
            else if (rv.equals(CKR.ATTRIBUTE_SENSITIVE))
            {
                /*
                 * We have the attribute type and length, but it is sensitive, so
                 * we can not get the value
                 */

                println(AttributeName(template[0].type) +
                        " Length:" + template[0].valueLen +
                        " Value:**SENSITIVE**");
            }
            else if (rv.equals(CKR.OK))
            {
                /*
                 * We have the attribute type and length.
                 *
                 * To get the value we have to call C_GetAttributeValue again, making
                 * sure that we pass in the correct data type for the attribute type.
                 *
                 * In the interests of brevity, we will only list a couple here.
                 */

                if (template[0].type.equals(CKA.CLASS))
                    template[0].pValue = new CK_OBJECT_CLASS();

                else if (template[0].type.equals(CKA.KEY_TYPE))
                    template[0].pValue = new CK_KEY_TYPE();

                else if (template[0].type.equals(CKA.LABEL) ||
                         template[0].type.equals(CKA.TIME_STAMP))
                    template[0].pValue = new byte[(int)template[0].valueLen];

                else if (template[0].type.equals(CKA.PRIVATE) ||
                         template[0].type.equals(CKA.ENCRYPT) ||
                         template[0].type.equals(CKA.DECRYPT))
                    template[0].pValue = new CK_BBOOL();

                else
                    template[0].pValue = null;

                if (template[0].pValue != null)
                {
                    /*
                     * Get the value.
                     *
                     * Note that we are using the exception version of the API here
                     * because we know that it should all work :-)
                     */
                    CryptokiEx.C_GetAttributeValue(session, hObject, template, 1);

                    /*
                     * Finally, format the display.
                     *
                     * We will not get too fancy here.
                     */
                    String valueString = null;

                    if (template[0].valueLen == 0)
                    {
                        /* there really was no need to call C_GetAttributeValue a second time */
                        valueString = "<no value>";
                    }
                    else
                    {
                        /* some working variables to get string representations */
                        byte[] str = null;
                        LongRef lRef = new LongRef();

                        if (template[0].pValue instanceof CK_OBJECT_CLASS)
                        {
                            CK_OBJECT_CLASS value = (CK_OBJECT_CLASS)template[0].pValue;

                            CTUtilEx.CTU_GetObjectClassString(value, str, lRef);
                            str = new byte[(int)lRef.value];
                            CTUtilEx.CTU_GetObjectClassString(value, str, lRef);

                            valueString = new String(str, StandardCharsets.US_ASCII);
                        }
                        else if (template[0].pValue instanceof CK_KEY_TYPE)
                        {
                            CK_KEY_TYPE value = (CK_KEY_TYPE)template[0].pValue;

                            CTUtilEx.CTU_GetKeyTypeString(value, str, lRef);
                            str = new byte[(int)lRef.value];
                            CTUtilEx.CTU_GetKeyTypeString(value, str, lRef);

                            valueString = new String(str, StandardCharsets.US_ASCII);
                        }
                        else if (template[0].pValue instanceof CK_BBOOL)
                        {
                            /* we could really leave this for the else clause */
                            valueString = template[0].pValue.toString();
                        }
                        else if (template[0].pValue instanceof byte[])
                        {
                            valueString = new String((byte[])template[0].pValue, StandardCharsets.US_ASCII);
                        }
                        else
                        {
                            valueString = template[0].pValue.toString();
                        }
                    }

                    println(AttributeName(template[0].type) +
                            " Length:" + template[0].valueLen +
                            " Value:" + valueString);
                }
                else
                {
                    println(AttributeName(template[0].type) +
                            " Length:" + template[0].valueLen +
                            " <value not retrieved>");
                }
            }
            else
            {
                /* something went wrong */
                throw new CKR_Exception("CTU_GetAttributeValue", rv);
            }
        }
    }

    static String AttributeName(CK_ATTRIBUTE_TYPE type)
    {
        byte[] str = null;
        LongRef lRef = new LongRef();

        CTUtilEx.CTU_GetAttributeTypeString(type, str, lRef);
        str = new byte[(int)lRef.value];
        CTUtilEx.CTU_GetAttributeTypeString(type, str, lRef);

        /* lets make sure that the string is a fixed length */
        String spaces = "                   ";
        String result = new String(str, StandardCharsets.US_ASCII) + spaces;

        /* this is a bit rough, we could be truncating the original value here */
        return result.substring(0, spaces.length());
    }
}

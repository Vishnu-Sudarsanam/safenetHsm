import safenet.jcprov.*;
import safenet.jcprov.constants.*;
import safenet.jcprov.params.*;
import java.nio.charset.*;

/**
 * This class demonstrates the use of the vendor defined
 * CKM.PP_LOAD_SECRET mechanism.
 * <p>
 * Usage : java ...UsePinPad [-slot &lt;slotId&gt;] [-password &lt;password&gt;] [-maskInput] [-convert (none|octal|decimal)]
 * <li><i>slotId</i>    slot number to use to create the temporary object - default (0)
 * <li><i>password</i>  user password of the slot. If specified, user is logged into the token before creating the temporary object.
 * <li><i>maskInput</i> If specified, mask the user input. Otherwise, input is in the clear.
 * <li><i>convert</i>   Specifies how the conversion from inpout data to actual data will be performed. If none, no conversion is done, if octal or decimal, input characters are grouped in threes, and converted from base 8 and 10, respectively. Default is none.
 */
public class UsePinpad
{

    /** easy access to System.out.println */
    static public void println(String s)
    {
        System.out.println(s);
    }

    /** display runtime usage of the class */
    public static void usage()
    {
        println("java ...UsePinpad [-slot <slotId>] [-password <password>] [-maskInput] [-convert (none|decimal|octal)]");
        println("");
        println("<slotId>    slot number to use to create the temporary object - default (0)");
        println("<password>  user password of the slot. If specified, user is logged into the token before creating the temporary object.");
        println("<maskInput> If specified, mask the user input. Otherwise, input is in the clear.");
        println("<convert>   Specifies how the conversion from inpout data to actual data will be performed. If none, no conversion is done, if octal or decimal, input characters are grouped in threes, and converted from base 8 and 10, respectively. Default is none.");
        println("");

        System.exit(1);
    }

    /** main execution method */
    public static void main(String[] args)
    {
        CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
        long slotId = 0;
        String password = "";
        CK_BBOOL bMaskInput = CK_BBOOL.FALSE;
        int convert = CK_PP_LOAD_SECRET_PARAMS.CK_PP_CT_NONE;

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
            else if (args[i].equalsIgnoreCase("-maskInput"))
            {
                bMaskInput = CK_BBOOL.TRUE;
            }
            else if (args[i].equalsIgnoreCase("-convert"))
            {
                if (++i >= args.length)
                    usage();

                if (args[i].equalsIgnoreCase("none"))
                {
                    convert = CK_PP_LOAD_SECRET_PARAMS.CK_PP_CT_NONE;
                }
                else if (args[i].equalsIgnoreCase("octal"))
                {
                    convert = CK_PP_LOAD_SECRET_PARAMS.CK_PP_CT_OCTAL;
                }
                else if (args[i].equalsIgnoreCase("decimal"))
                {
                    convert = CK_PP_LOAD_SECRET_PARAMS.CK_PP_CT_DECIMAL;
                }
                else
                {
                    usage();
                }
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

            println("Testing the pinpad routines:-");
            testPinpad(session, bMaskInput, convert);
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

    public static void testPinpad(CK_SESSION_HANDLE hSession,
                                  CK_BBOOL bMaskInput,
                                  int convert)
    {
        CK_OBJECT_HANDLE hData = new CK_OBJECT_HANDLE();
        CK_PP_LOAD_SECRET_PARAMS ppParams;

        String display = "Please Enter:\n";

        /* Construct the mechanism parameters */
        ppParams = new CK_PP_LOAD_SECRET_PARAMS(bMaskInput,
                                                convert,
                                                10,
                                                display.getBytes(StandardCharsets.US_ASCII));

        CK_MECHANISM mech = new CK_MECHANISM(CKM.PP_LOAD_SECRET,
                                             ppParams);

        /* Only input a screenful of digits :-
         *    Screen is 16 characters for Kobil Kaan. So in Deciaml or
         *    Octal conversion, we will want 5 bytes (15 characters used).
         *    In no conversion, we will want 15 bytes.\
         */
        int dataLen = 15;

        if (convert == CK_PP_LOAD_SECRET_PARAMS.CK_PP_CT_DECIMAL ||
            convert == CK_PP_LOAD_SECRET_PARAMS.CK_PP_CT_OCTAL)
        {
            dataLen = 5;
        }

        /* Construct the attributes for the temporary object */
        CK_ATTRIBUTE[] tmpObjAttrs = {
            new CK_ATTRIBUTE(CKA.CLASS,     CKO.SECRET_KEY),
            new CK_ATTRIBUTE(CKA.KEY_TYPE,  CKK.GENERIC_SECRET),
            new CK_ATTRIBUTE(CKA.VALUE_LEN, dataLen),
            new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.FALSE)
        };

        /* Create the temporary object from the pinpad input. */
        CryptokiEx.C_GenerateKey(hSession,
                                 mech,
                                 tmpObjAttrs,
                                 tmpObjAttrs.length,
                                 hData);

        /* If successful, dump the object value. */
        CK_ATTRIBUTE[] valueAttr = {
            new CK_ATTRIBUTE()
        };

        valueAttr[0].type = CKA.VALUE;
        valueAttr[0].pValue = null;
        valueAttr[0].valueLen = 0;

        CryptokiEx.C_GetAttributeValue(hSession,
                                       hData,
                                       valueAttr,
                                       valueAttr.length);

        valueAttr[0].pValue = new byte[(int)valueAttr[0].valueLen];

        CryptokiEx.C_GetAttributeValue(hSession,
                                       hData,
                                       valueAttr,
                                       valueAttr.length);

        println("The value of the object is: " +
                bytesToHexString((byte[])valueAttr[0].pValue));
    }

    /**
     * Convert a byte array to a hex string.
     *
     * Each byte of the input is convert into two hex characters. There is no
     * space added between the character pairs.
     *
     * @param data
     *  hex data to convert
     */
    static String bytesToHexString(byte[] data)
    {
        final String hexCodes = "0123456789ABCDEF";

        int len = data.length;

        char[] ret = new char[len * 3 - 1];

        byte digit;
        int j = 0;

        for (int i = 0; i < len; ++i)
        {
            // mask & get the first 4 bits of the byte
            digit = (byte) ((data[i] & 0xF0l) >>> 4);

            // convert to hex
            ret[j++] = hexCodes.charAt(digit);

            // mask & get the last 4 bits of the byte
            digit = (byte) (data[i] & 0x0Fl);

            // convert to hex
            ret[j++] = hexCodes.charAt(digit);

            if (i != len - 1) {
                ret[j++] = ':';
            }
        }

        return (new String(ret));
    }
}

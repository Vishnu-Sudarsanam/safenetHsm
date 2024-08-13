/*
 * This code sample relates to NistSp800_38F publication,
 * which describes AES_KW, AES_KWP, TDEA_TKW wrapping/unwrapping mechanisms.
 * Environment variables:
 * 1/ SW Emulator:
 * Path=<pat_to_jcprov.dll>;<path_to_cryptoki.dll>;%PATH%
 * 2/ HSM:
 * set ET_HSM_NETCLIENT_SERVERLIST=<server_IP_address>
 * Add <path_to_ethsm.dll> to PATH environment variable.
 **********
 * Compile:
 * javac.exe -cp .\;<path_to_jcprov.jar> WrapUnwrap.java
 * Run:
 * java.exe -cp .\;<path_to_jcprov.jar> WrapUnwrap
 * Result:
	AES KW wrapping start...
	Expected Wrapped Text:  031F6BD7E61E643DF68594816F64CAA3F56FABEA2548F5FB
	Generated Wrapped Text: 031F6BD7E61E643DF68594816F64CAA3F56FABEA2548F5FB
	Test PASSED!
	AES KW unwrapping start...
	Expected Unwrapped Text:  9C4E675277A3BDC3A071048B327A011E
	Generated Unwrapped Text: 9C4E675277A3BDC3A071048B327A011E
	Test PASSED!
	AES KWP wrapping start...
	Expected Wrapped Text:  36F20123EFDA2830593E096D7DD3A32877BFB6F45B8B5ADA
	Generated Wrapped Text: 36F20123EFDA2830593E096D7DD3A32877BFB6F45B8B5ADA
	Test PASSED!
	AES KWP unwrapping start...
	Expected Unwrapped Text:  D398DD357BE9799DF240210D
	Generated Unwrapped Text: D398DD357BE9799DF240210D
	Test PASSED!
	TDEA TKW wrapping start...
	Expected Wrapped Text:  83E66A63D0942F480FE42CB3B71777F3
	Generated Wrapped Text: 83E66A63D0942F480FE42CB3B71777F3
	Test PASSED!
	TDEA TKW unwrapping start...
	Expected Unwrapped Text:  2FFD56320F1DFF99
	Generated Unwrapped Text: 2FFD56320F1DFF99
	Test PASSED!
 */

import safenet.jcprov.*;
import safenet.jcprov.constants.*;
import java.nio.charset.*;
import java.io.IOException;

public class WrapUnwrap
{
	static boolean DO_WRAP_UNWRAP = true;
    static byte[] wrappingKeyBytes = null;
    static byte[] wrappeeKeyBytes = null;
    static byte[] xB = null;//Plain text binary representation
    static byte[] yB = null;//cipher/wrapped text in binary representation
    static String line = null;
	static String sCount = "";
	static String errStr = null; 
	
    /** easy access to System.out.println */
    static public void println(String s)
    {
        System.out.println(s);
    }

    public static void cleanVariables (int number) {
    	wrappingKeyBytes = null;
    	wrappeeKeyBytes = null;
    	xB = null;
    	yB = null;
    	line = null;
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
    static String bytesToHex(byte[] data)
    {
        final String hexCodes = "0123456789ABCDEF";
        int len = data.length;
        char[] ret = new char[len * 2];
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
        }

        return (new String(ret));
    }
	
	public static byte[] hexToBin(String str)
    {
        int len = str.length();
        byte[] out = new byte[len / 2];
        int endIndx;

        for (int i = 0; i < len; i = i + 2)
        {
            endIndx = i + 2;
            if (endIndx > len)
                endIndx = len - 1;
            out[i / 2] = (byte) Integer.parseInt(str.substring(i, endIndx), 16);
        }
        return out;
    }
	public static int strstr(String haystack, String needle){
		if (needle.length() == 0) {
			return 0;
		}
	    for(int i = 0; i < haystack.length(); i++ ) {
	        for(int j = 0; j < needle.length() && 
	                        i+j < haystack.length(); j++ ) {
	            if(needle.charAt(j) != haystack.charAt(i+j)) {
	                break;
	            } else if (j == needle.length()-1) {
	                return i;
	            }
	        }
	    }
	    return -1;
	}
    /** main execution method 
     * @throws IOException */
    @SuppressWarnings("unused")
	public static void main(String[] args) throws IOException
    {
        CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
        long slotId = 0;
        CK_MECHANISM mech = null;//new CK_MECHANISM(CKM.INVALID_VALUE);
        String password = "";
        String pFile = "";
        boolean bPrivate = false;
        String outFile = "";
        boolean encryptFlag = true;
        boolean completionFlag = false;
		int recordNumber = 0;
		int errorCount = 0;
		String wrappingKeyName = null;
		String wrappeeKeyName = null;
		//KW AD:
		String sKekKwAd = new String("1cbd2f79078b9500fae23696311953eb");
		String sCKwAd = new String("ecbd7a17c5da3cfdfe2225d2bf9ac7abce78c2b2aefa6eac");
		String sPKwAd = new String("9c4e675277a3bdc3a071048b327a011e");
		//KW AE:
		String sKekKwAe = new String("7575da3a93607cc2bfd8cec7aadfd9a6");
		String sCKwAe = new String("031f6bd7e61e643df68594816f64caa3f56fabea2548f5fb");
		String sPKwAe = new String("42136d3c384a3eeac95a066fd28fed3f");
		//KWP AD:
		String sKekKwpAd = new String("b9d14c277cf7698077f2402757d5e667");
		String sCKwpAd = new String("e751d0d62a14776ed4864011549949368236ac72aac5e155");
		String sPKwpAd = new String("d398dd357be9799df240210d");
		//KWP AE:
		String sKekKwpAe = new String("6a245260e4fb9cecfda70efe8fa60279");
		String sCKwpAe = new String("36f20123efda2830593e096d7dd3a32877bfb6f45b8b5ada");
		String sPKwpAe = new String("6a27dcbefdc1404516");
		//TKW AD:
		String sKekTkwAd = new String("e373cd9d7310a873b5103d5773464938d352b54f265dd945");
		String sCTkwAd = new String("10a38310b604b48f94357d67");
		String sPTkwAd = new String("2ffd56320f1dff99");
		//TKW AE:
		String sKekTkwAe = new String("b97375e9131985ad575e76e08f9845f1d6f78a64ea2f9d25");
		String sCTkwAe = new String("83e66a63d0942f480fe42cb3b71777f3");
		String sPTkwAe = new String("38250083bce61b46f10e299e");
        try
        {
            /*
             * Initialize Cprov 
             */
        	CK_C_INITIALIZE_ARGS initArgs = new CK_C_INITIALIZE_ARGS(0);
            CryptokiEx.C_Initialize(initArgs);

            /*
             * Open a session
             */
            CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION, null, null,
                    session);

            /*
             * Login - if we have a password
             */
            if (password.length() > 0)
            {
                CryptokiEx.C_Login(session, CKU.USER, password.getBytes(StandardCharsets.US_ASCII),
                        password.length());

                bPrivate = true;
            }
		    //Process Test Vectors:
			wrappingKeyName = "WrappingKey";
			wrappeeKeyName = "WrappeeKey";
			//AES, KW:
			println("AES KW wrapping start...");
			mech = new CK_MECHANISM(CKM.AES_KW);
			//Wrap:
			wrappingKeyBytes = hexToBin(sKekKwAe);
			CK_OBJECT_HANDLE hWrappingKey = new CK_OBJECT_HANDLE();
			CK_OBJECT_HANDLE hWrappeeKey = new CK_OBJECT_HANDLE();
			xB = hexToBin(sPKwAe);
			yB = hexToBin(sCKwAe);
			//Create wrapping key:
			createKey(session, CKK.AES, wrappingKeyBytes, wrappingKeyName, hWrappingKey);
			//Create wrappee key:
			createKey(session, CKK.AES, xB, wrappeeKeyName, hWrappeeKey);
			symetricWrap(session, hWrappingKey, hWrappeeKey, mech);
			CryptokiEx.C_DestroyObject(session, hWrappeeKey);
			CryptokiEx.C_DestroyObject(session, hWrappingKey);
			cleanVariables(0);
			//Unwrap:
			println("AES KW unwrapping start...");
			wrappingKeyBytes = hexToBin(sKekKwAd);
			xB = hexToBin(sPKwAd);
			yB = hexToBin(sCKwAd);
			hWrappingKey = new CK_OBJECT_HANDLE();
			hWrappeeKey = new CK_OBJECT_HANDLE();
			//Create wrapping key:
			createKey(session, CKK.AES, wrappingKeyBytes, wrappingKeyName, hWrappingKey);
			symetricUnwrap(session, hWrappingKey, yB, mech);
			CryptokiEx.C_DestroyObject(session, hWrappingKey);
			cleanVariables(0);
			//KWP
			mech = new CK_MECHANISM(CKM.AES_KWP);
			//Wrap:
			println("AES KWP wrapping start...");
			wrappingKeyBytes = hexToBin(sKekKwpAe);
			hWrappingKey = new CK_OBJECT_HANDLE();
			hWrappeeKey = new CK_OBJECT_HANDLE();
			xB = hexToBin(sPKwpAe);
			yB = hexToBin(sCKwpAe);
			//Create wrapping key:
			createKey(session, CKK.AES, wrappingKeyBytes, wrappingKeyName, hWrappingKey);
			//Create wrappee key:
			createWrappeeSecretKey(session, xB, wrappeeKeyName, hWrappeeKey);
			symetricWrap(session, hWrappingKey, hWrappeeKey, mech);
			CryptokiEx.C_DestroyObject(session, hWrappeeKey);
			CryptokiEx.C_DestroyObject(session, hWrappingKey);
			cleanVariables(0);
			//Unwrap:
			println("AES KWP unwrapping start...");
			wrappingKeyBytes = hexToBin(sKekKwpAd);
			xB = hexToBin(sPKwpAd);
			yB = hexToBin(sCKwpAd);
			hWrappingKey = new CK_OBJECT_HANDLE();
			hWrappeeKey = new CK_OBJECT_HANDLE();
			//Create wrapping key:
			createKey(session, CKK.AES, wrappingKeyBytes, wrappingKeyName, hWrappingKey);
			symetricUnwrap(session, hWrappingKey, yB, mech);
			CryptokiEx.C_DestroyObject(session, hWrappingKey);
			cleanVariables(0);					
			
			//TDEA, wrap:
			println("TDEA TKW wrapping start...");
        	mech = new CK_MECHANISM(CKM.TDEA_TKW);
			wrappingKeyBytes = hexToBin(sKekTkwAe);
			xB = hexToBin(sPTkwAe);	
			yB = hexToBin(sCTkwAe);
			hWrappingKey = new CK_OBJECT_HANDLE();
			hWrappeeKey = new CK_OBJECT_HANDLE();
			//Create wrapping key:
			createKey(session, CKK.DES3, wrappingKeyBytes, wrappingKeyName, hWrappingKey);
			createWrappeeSecretKey(session, xB, wrappeeKeyName, hWrappeeKey);
			symetricWrap(session, hWrappingKey, hWrappeeKey, mech);
			CryptokiEx.C_DestroyObject(session, hWrappeeKey);
			CryptokiEx.C_DestroyObject(session, hWrappingKey);
			cleanVariables(0);
			//TDEA, unwrap:
			println("TDEA TKW unwrapping start...");
			wrappingKeyBytes = hexToBin(sKekTkwAd);
			xB = hexToBin(sPTkwAd);
			yB = hexToBin(sCTkwAd);						
			hWrappingKey = new CK_OBJECT_HANDLE();
			//hWrappeeKey = new CK_OBJECT_HANDLE();
			//Create wrapping key:
			createKey(session, CKK.DES3, wrappingKeyBytes, wrappingKeyName, hWrappingKey);
			symetricUnwrap(session, hWrappingKey, yB, mech);
			CryptokiEx.C_DestroyObject(session, hWrappingKey);
			cleanVariables(0);
		}
		catch (CKR_Exception ex)
		{
			/*
			 * A Cryptoki related exception was thrown
			 */
			//ex.printStackTrace();
			println(errStr + " Operation FAILED");
			cleanVariables(recordNumber);
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
             * will be reported - and we don't really care because we are
             * shutting down.
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
    public static void createKey(CK_SESSION_HANDLE session,
            CK_KEY_TYPE keyType,
            byte[] keyBytes,
            String keyName,
            CK_OBJECT_HANDLE hKey)
	{
		CK_ATTRIBUTE[] template =
		{
			new CK_ATTRIBUTE(CKA.CLASS,         CKO.SECRET_KEY),
			new CK_ATTRIBUTE(CKA.TOKEN,         CK_BBOOL.FALSE),
			new CK_ATTRIBUTE(CKA.SENSITIVE,     CK_BBOOL.FALSE),
			new CK_ATTRIBUTE(CKA.LABEL,         keyName.getBytes(StandardCharsets.US_ASCII)),
			new CK_ATTRIBUTE(CKA.VALUE_LEN,     keyBytes.length),
			new CK_ATTRIBUTE(CKA.VALUE,         keyBytes, keyBytes.length),
			new CK_ATTRIBUTE(CKA.ENCRYPT,       CK_BBOOL.TRUE),
			new CK_ATTRIBUTE(CKA.DECRYPT,       CK_BBOOL.TRUE),
			new CK_ATTRIBUTE(CKA.WRAP,          CK_BBOOL.TRUE),
			new CK_ATTRIBUTE(CKA.UNWRAP,       CK_BBOOL.TRUE),
			new CK_ATTRIBUTE(CKA.EXTRACTABLE,   CK_BBOOL.TRUE),
			new CK_ATTRIBUTE(CKA.EXPORTABLE,   CK_BBOOL.TRUE),
			new CK_ATTRIBUTE(CKA.MODIFIABLE,    CK_BBOOL.TRUE),
			new CK_ATTRIBUTE(CKA.KEY_TYPE,      keyType)
		};
		errStr = "Key Generation";
        CryptokiEx.C_CreateObject(session, template, template.length, hKey);
	}
    
    public static void createWrappeeSecretKey(CK_SESSION_HANDLE session,
            byte[] keyBytes,
            String keyName,
            CK_OBJECT_HANDLE hKey)
	{
		CK_KEY_TYPE kt = CKK.GENERIC_SECRET;

		CK_ATTRIBUTE[] template =
		{
			new CK_ATTRIBUTE(CKA.CLASS,         CKO.SECRET_KEY),
			new CK_ATTRIBUTE(CKA.TOKEN,         CK_BBOOL.FALSE),
			new CK_ATTRIBUTE(CKA.SENSITIVE,     CK_BBOOL.FALSE),
			new CK_ATTRIBUTE(CKA.LABEL,         keyName.getBytes(StandardCharsets.US_ASCII)),
			new CK_ATTRIBUTE(CKA.VALUE_LEN,     keyBytes.length),
			new CK_ATTRIBUTE(CKA.VALUE,         keyBytes, keyBytes.length),
			new CK_ATTRIBUTE(CKA.WRAP,          CK_BBOOL.TRUE),
			new CK_ATTRIBUTE(CKA.UNWRAP,       CK_BBOOL.TRUE),
			new CK_ATTRIBUTE(CKA.EXTRACTABLE,   CK_BBOOL.TRUE),
			new CK_ATTRIBUTE(CKA.EXPORTABLE,   CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.KEY_TYPE,      kt)
		};
        CryptokiEx.C_CreateObject(session, template, template.length, hKey);
	}

    static void symetricWrap(CK_SESSION_HANDLE session,
            CK_OBJECT_HANDLE hWrappingKey,
			CK_OBJECT_HANDLE hWrappeeKey,
            CK_MECHANISM mechanism) throws IOException
	{
		byte[] wrappedKey = null;
		LongRef lRefWrap = new LongRef();
		errStr = "Key Wrap";
		CryptokiEx.C_WrapKey(session, mechanism, hWrappingKey, hWrappeeKey, null, lRefWrap);
		/* allocate space */
		wrappedKey = new byte[(int)lRefWrap.value];
		
		/* Wrap */
		CryptokiEx.C_WrapKey(session, mechanism, hWrappingKey, hWrappeeKey, wrappedKey, lRefWrap);
		//Print encrypted text:
		line = bytesToHex(wrappedKey);//contains cipher text itself
		println("Expected Wrapped Text:  " + bytesToHex(yB));
		println("Generated Wrapped Text: " + line);
		//compare:
		if (strstr(line, bytesToHex(yB)) != -1) {
			println("Test PASSED!");
		} else {
			println("Test FAILED!" + "\n");
		}
	}

    static void symetricUnwrap(CK_SESSION_HANDLE session,
            CK_OBJECT_HANDLE hUnwrappingKey,
			byte[] wrappedKey,
            CK_MECHANISM mechanism) throws IOException
	{
		errStr = "Key unwrap";
		//LongRef lRefUnwrap = new LongRef();
		String decryptedText = null;
		CK_OBJECT_HANDLE hKey = new CK_OBJECT_HANDLE();
		if (xB == null) return;

		int len = xB.length;
		byte[] unwrappedKey = new byte[len];
		/*
		 * Attribute template for the unwrapped key.
		 */
		CK_ATTRIBUTE tplUnwrappedKey[] = 
		{
			new CK_ATTRIBUTE(CKA.TOKEN,     CK_BBOOL.FALSE),
			new CK_ATTRIBUTE(CKA.KEY_TYPE,  CKK.GENERIC_SECRET),
			new CK_ATTRIBUTE(CKA.WRAP,  CK_BBOOL.TRUE),
			new CK_ATTRIBUTE(CKA.UNWRAP,  CK_BBOOL.TRUE),
			new CK_ATTRIBUTE(CKA.EXTRACTABLE,  CK_BBOOL.TRUE),
			new CK_ATTRIBUTE(CKA.EXPORTABLE,  CK_BBOOL.TRUE),
			new CK_ATTRIBUTE(CKA.SENSITIVE,  CK_BBOOL.FALSE),
		};
		int tplUnwrappedKeySize = tplUnwrappedKey.length;
		/* get the size of the plain text */
		CryptokiEx.C_UnwrapKey(session,
					mechanism,
					hUnwrappingKey,
					wrappedKey,
					wrappedKey.length,
					tplUnwrappedKey,
					tplUnwrappedKeySize,
					hKey);
		CK_ATTRIBUTE getValueTpl[] = {
			new CK_ATTRIBUTE(CKA.VALUE, unwrappedKey, len),
		};
		CryptokiEx.C_GetAttributeValue(session, hKey, getValueTpl, getValueTpl.length);
		CryptokiEx.C_DestroyObject(session, hKey);
		decryptedText = bytesToHex(unwrappedKey);
		println("Expected Unwrapped Text:  " + bytesToHex(xB));
		println("Generated Unwrapped Text: " + decryptedText);
		//compare:
		if (strstr(decryptedText, bytesToHex(xB)) != -1) {
			println("Test PASSED!");
		} else {
			println("Test FAILED!" + "\n");
		}
	}
}

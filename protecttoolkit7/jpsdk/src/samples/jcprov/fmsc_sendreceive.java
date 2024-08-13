/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2016 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: fmsc_sendreceive.java
 */

/**
 * @file
 * fmsc_sendreceive class FM : This sample demonstrates the use of extension function FMSC_SendReceive() introduced in cryptoki library
 * to send and receive response from a custom FM. Before running this test make sure you have created a 1024-bit rsa key with label "TEST_RSA_KEY" 
 * and DES3 key with label "TEST_DES3_KEY" on slot 0.
*/
import java.nio.charset.*;

import safenet.jcprov.*;
import safenet.jcprov.constants.*;

public class fmsc_sendreceive
{
    static byte FMCMD_RSA_ENC = 0x0C;
    static byte FMCMD_DES3_ENC = 0x0D;
    static int FM_ID = 0x0100;
    static int BUFF_SIZE = 256;

    public static void main(String[] args)
    {
	    String t = "";
	    int loop = 1;
	    int count;

	    String clrTxt = "Test Message";

	    if(args.length < 1 || args.length > 2)
	    {
		    Usage();
	    }
	    else
	    {
		    if(args.length == 2)
		    {
			    loop = Integer.parseInt(args[1]);
		    }

		    if(args[0].equals("rsa"))
		    {
			    t = "rsa";
		    }
		    else if(args[0].equals("tdes"))
		    {
			    t = "tdes";
		    }
		    else
		    {
			    System.out.println("Unsupported algorithm specified ["+args[0]+"]");
			    Usage();
			    return;
		    }
	    }
	    CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));

	    for(count = 0; count<loop; count++)
	    {
	        int rv = fmhostcall(t, clrTxt);
	        if(rv != 0) System.out.println("Error with call #" + count);
	    }

	    Cryptoki.C_Finalize(null);

	    return;
    }

    public static int fmhostcall(String test, String in)
    {
	    CK_SESSION_HANDLE hSession = new CK_SESSION_HANDLE();
	    long slot = 0;
	    LongRef fmstat = new LongRef();
	    LongRef recvlen = new LongRef();
	    String keyId = "";
	    byte keyIdlen = 0, inlen =0;
	    byte cmd = 0;
	    int fmId = FM_ID;
	    int requestlen, responselen = BUFF_SIZE;
	    int i=0,k=0;
	    byte[] response = new byte[responselen];
	    responselen = BUFF_SIZE;

	    if(test.equals("rsa"))
	    {
		    cmd = FMCMD_RSA_ENC;
		    keyId = "TEST_RSA_KEY";
	    }
	    else if(test.equals("tdes"))
	    {
		    cmd = FMCMD_DES3_ENC;
		    keyId = "TEST_DES3_KEY";
	    }

	    keyIdlen = (byte)keyId.length();
	    inlen = (byte)in.length();

	    byte[] kId = keyId.getBytes(StandardCharsets.US_ASCII);
	    byte[] input = in.getBytes(StandardCharsets.US_ASCII);

        // Format of req : cmd[2] | idlen[2] | id | inlen[4] | <in>
        // i.e. cmd is a short(16bit), idlen is a short(16bit) and inlen is a long(32bit)
        // All integers are Big Endian i.e. MSB is first
	    requestlen = 2*2 + 4 + keyIdlen+inlen;
	    byte[] request = new byte[requestlen];

	    request[k++] = (byte)((cmd >> 8) & 0xff);
	    request[k++] = (byte)(cmd & 0xff);
	    request[k++] = keyIdlen;
	    for(i=0;i<kId.length;i++)
	        request[k++] = kId[i];
	    request[k++] = (byte)((inlen >> 24) & 0xff);
	    request[k++] = (byte)((inlen >> 16) & 0xff);
	    request[k++] = (byte)((inlen >> 8 ) & 0xff);
	    request[k++] = (byte)((inlen      ) & 0xff);
	    for(i=0;i<input.length;i++)
	        request[k++] = input[i];

	    System.out.printf("REQUEST[%d]: ", requestlen);
	    for(i=0;i<request.length;i++)
	        System.out.printf("%02X", request[i]);
	    System.out.println();

	    CryptokiEx.C_OpenSession(slot, CKF.SERIAL_SESSION|CKF.RW_SESSION, null, null, hSession);

	    CryptokiEx.FMSC_SendReceive(hSession, fmId, request, requestlen, response, responselen, recvlen, fmstat);

	    if(fmstat.value == 0)
	    {
		    System.out.printf("RESPONSE[%d]: ", (int)recvlen.value);
		    for(k=0;k<(int)recvlen.value;k++)
			    System.out.printf("%02X", response[k]);
	    }
	    else
	    {
		    System.out.printf("FM returned: %02X", fmstat.value);
	    }
		System.out.println();

	    CryptokiEx.C_CloseSession(hSession);
	    return (int)fmstat.value;
    }

    public static void Usage()
    {
        System.out.println();
        System.out.println("Usage:");
        System.out.println("<alg> [iteration]");
        System.out.println("alg = tdes or rsa");
        System.out.println("iteration = count (numeric)");
        System.out.println();
    }
}

/**
 *
 * Copyright (c) 20082 Safnet
 * All Rights Reserved - Proprietary Information of Safenet
 * Not to be Construed as a Published Work.
 *
 * @author  Brian Franklin
 * @version 0.1
 *
 */
 
import safenet.jhsm.*;
import safenet.jhsm.constants.*;
import safenet.jhsm.misc.*;

import java.lang.*;
import java.nio.ByteBuffer;

class sendrecv
{
    private  final static String msg = new StringBuffer().append("\n Usage : sendrecv [-h] [-d x] [-l x] [-v] where :")
                                                         .append("\n         -h  This help menu                    ")
                                                         .append("\n         -d  HSM device number x               ")
                                                         .append("\n         -l  Loops x (default is 1)              ")
                                                         .append("\n         -v  Verbose mode                      ")
                                                         .append("\n                                               ")
                                                         .append("\n Example : sendrecv -d 0 -q -v                 ")
                                                         .append("\n                                               ")
                                                         .toString();


	/** Useful constants */
	private	 final static short FM_NUMBER_HIFACE = 0x0000;

	private	 final static int RC_OK = 0x0000;
	private	 final static int RC_GENERAL_ERR = 0x0001;
	private	 final static int RC_BAD_OUTPUT = 0x0002;
	                                             
    /** Bit flags for setting options */
    private  final static int VERBOSE = 0x00000001;
    private  final static int LOOP    = 0x00000002;
    private  final static int HELP    = 0x00000004;
    private  final static int HSM     = 0x00000008;
    private  final static int OFF     = 0;

	/** runtime variables */
    private  static int hsm_num       = 0;
    private  static int loops      	  = 1;
    private  static int option        = 0x00000000;


    /** Our simple help */
    private  static void usage()
    {
        System.out.println(msg);
        System.exit(0);
    }

    /** DEBUG */
    private  static void DEBUG(String msg)
    {
        System.out.println(msg);
    }

    /** Method to parse command line arg */
    private  static void parseArg(String[] args)
    {
      int i   = 0;

      if(args.length<1)
      {
		return;
   	  }
   	  
      for (i=0; i<args.length; i++)
      {   
          if(args[i].startsWith("-"))
          {
            /** Check whar arg we have */
            if(args[i].equals("-v") || args[i].equals("-V")) option = option | VERBOSE;
            if(args[i].equals("-h") || args[i].equals("-H")) option = option | HELP;
            if(args[i].equals("-d") || args[i].equals("-D"))
            {
              /** Extract number */
              if(i<args.length)
              {
                i++;
                option = option | HSM;
                hsm_num = Integer.valueOf(args[i]).intValue();
              }
              else
                  System.out.println("\nNo HSM number specified !");
            }
            if(args[i].equals("-l") || args[i].equals("-L"))
            {
              /** Extract number */
              if(i<args.length)
              {
                i++;
                option = option | LOOP;
                loops = Integer.valueOf(args[i]).intValue();
              }
              else
                  System.out.println("\nNo loop count specified !");
            }
        }
      }
    }
     
	public static int byteArrayToInt(byte[] data)
	{
		int val = 0;

		for (int i = 0; i < data.length; i++)
		{
			val = val << 8 | data[i];
		}
		return val;	
	}

	public static short byteArrayToShort(byte[] data)
	{
		return (short)byteArrayToInt(data);
	}


	public static byte[] encodeShort(short srt)
	{
		ByteBuffer buff = ByteBuffer.allocate(2);
		buff.putShort(srt);
		return buff.array();
	}

	public static byte[] encodeInt(int i)
	{
		ByteBuffer buff = ByteBuffer.allocate(4 /* Int.SIZE */);
		buff.putInt(i);
		return buff.array();
	}
    
    private static int callEchoCmd(int deviceNum)
    {
		/* format of echo Request
		** CMD | LEN | UNUSED | msg
		** Where CMD and LEN and UNUSED are Big Endian 32 bit integers
		** CMD = 1
		** LEN = length of 'msg'
		** UNUSED = reserved field set to zero
		**
		** 'msg' is any length char array. The reply contains 'msg' only.
		*/

		byte[] FMCMD_ECHO = { 0x00, 0x00, 0x00, 0x01 };
		byte[] msg = { 0x01, 0x23, 0x45, 0x67 };

	    Md_Buffer[] req = new Md_Buffer[5];
	    Md_Buffer[] rep = new Md_Buffer[2];
	    
	    int[] rxLen  = new int[1];
	    int[] fmStat = new int[1];
		
		
	   	/** Build HIFACE ECHO_CMD so that we can ping HSM */
		req[0] = new Md_Buffer(FMCMD_ECHO);
		req[1] = new Md_Buffer(encodeInt(msg.length));
		req[2] = new Md_Buffer(encodeInt(0));
		req[3] = new Md_Buffer(msg);
		
		/** 
		  * We must terminate last buffer by NULL,
			otherwise MD will continue to assume there is more Md_Buffer
		  */
		req[4] = new Md_Buffer();
		
		
		/** The reply message size is always equal to what the user sends */
		rep[0] = new Md_Buffer(msg.length);	
		
		/** 
		  * Same case for reply buffer. Must be terminated by null buffer.
		  */
		rep[1] = new Md_Buffer();	
				
		MD_RV rv =
		Md.MD_SendReceive( deviceNum,
		  			   		 0, 				/** OriginatorId */
							 FM_NUMBER_HIFACE,
						   	 req,
						     0, 				/** Reserved, always zero */
						   	 rep,
						   	 rxLen,				/** Received length */
						   	 fmStat);			/** application status */
 			
 		/** check for any transport errors */
		if ( rv.intValue() != 0 )
		{
			/* transport error - fmstat is invalid */
			DEBUG("Transport error "+rv.intValue());
			return RC_GENERAL_ERR;
		}

		/* check for application errors */
		int rc = fmStat[0];
		if (rc != 0)
			/* ignore output data if there is an app error */
			return rc;

		/* extract reply and check it is correct */
		byte[] reply = rep[0].getData();
		int replyLen = rep[0].size();

		if (replyLen != msg.length)
		{
			DEBUG("Bad reply length, expected "+msg.length+" got "+replyLen);
			return RC_BAD_OUTPUT;
		}
		
		for(int i=0; i<msg.length; ++i)
			if (reply[i] != msg[i])
			{
				DEBUG("Bad reply value at offset "+i+" expected "+msg[i]+" got "+reply[i]);
				return RC_BAD_OUTPUT;
			}
 
		return rc;
	}

	   
    public static void main(String[] args)
    {
        int count=0;
        String msg;
        
		/** Parse command line args */
        parseArg(args);
		if ( (option & HELP) != 0 )
			usage();
        
		/** hello message */
		System.out.println("sendrecv HSM="+hsm_num+" loops="+loops);

        /** Initialize HSM */
        MdEx.MD_Initialize(null);
		int rv = 0;
        for(count=0; count<loops; count++)
        {
    		rv = callEchoCmd(hsm_num);
			if (rv != 0)
				break;
			if ( (option & VERBOSE) != 0 )
				System.out.println("i="+(count+1));
	    }

		if (rv != 0)
			System.out.println("sendrecv complete with Error: "+rv);
		else
			System.out.println("sendrecv complete OK");
    
    	MdEx.MD_Finalize(null);	
     }
}

/**
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: samples/javahsmstate/hsmstate.java
 * $Date: 2014/09/15 12:40:07GMT-05:00 $
 */
 
import safenet.jhsm.*;
import safenet.jhsm.constants.*;
import safenet.jhsm.misc.*;

import java.lang.*;

class hsmstate
{
    private  final static String msg = new StringBuffer().append("\n Usage : hsmstate [-h] [-d x] [-q] [-v] where :")
                                                         .append("\n         -h  This help menu                    ")
                                                         .append("\n         -d  HSM device number x               ")
                                                         .append("\n         -q  Quick mode. Do not ping HSM       ")
                                                         .append("\n         -v  Verbose mode                      ")
                                                         .append("\n         -a  Show all HSM. Overrides -d        ")
                                                         .append("\n                                               ")
                                                         .append("\n Example : hsmstate -d 0 -q -v                 ")
                                                         .append("\n                                               ")
                                                         .toString();


	/** Useful constants */
	private	 final static short FM_NUMBER_HIFACE = 0x0000;
	                                             
    /** Bit flags for setting options */
    private  final static int VERBOSE = 0x00000001;
    private  final static int QUICK   = 0x00000002;
    private  final static int HELP    = 0x00000004;
    private  final static int HSM     = 0x00000008;
    private  final static int ALL     = 0x00000010;
    private  final static int OFF     = 0;

    private  static int hsm_num       = 0;
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
	      	usage();
	      	System.exit(0);
   	  }
   	  
      for (i=0; i<args.length; i++)
      {   
          if(args[i].startsWith("-"))
          {
            /** Check whar arg we have */
            if(args[i].equals("-v") || args[i].equals("-V")) option = option | VERBOSE;
            if(args[i].equals("-q") || args[i].equals("-Q")) option = option | QUICK;
            if(args[i].equals("-h") || args[i].equals("-H")) option = option | HELP;
            if(args[i].equals("-a") || args[i].equals("-A")) option = option | ALL;

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
        }
      }
    }
     
    
    private static boolean isAdapterAlive(int deviceNum)
    {

	    Md_Buffer[] req = new Md_Buffer[2];
	    Md_Buffer[] rep = new Md_Buffer[2];
	    
	    /** Prepare a CMD_ECHO buffer to ping the HSM. */
	    echo_cmd hsm_cmd = new echo_cmd(20,(byte)0xff);
	    
	    int[] rxLen  = new int[1];
	    int[] fmStat = new int[1];
		
		
	   	/** Build HIFACE ECHO_CMD so that we can ping HSM */
		req[0] = new Md_Buffer(hsm_cmd.cmd());
		
		/** 
		  * We must terminate last buffer by NULL,otherwise MD will continue to assume
		  * there is more Md_Buffer
		  */
		req[1] = new Md_Buffer(0);
		
		
		
		/** The reply message size is always equal to what the user sends */
		rep[0] = new Md_Buffer(hsm_cmd.payload_size());	
		
		/** 
		  * Same case for reply buffer. Must be terminated by null buffer.
		  */
		rep[1] = new Md_Buffer(0);	
				
		MdEx.MD_SendReceive( deviceNum,
		  			   		 0, 				/** OriginatorId */
							 FM_NUMBER_HIFACE,
						   	 req,
						     0, 				/** Reserved, always zero */
						   	 rep,
						   	 rxLen,				/** Recevied length */
						   	 fmStat);			/** application status */
 			
 		/** If we passed this point, it means adapter is OK */
		return true;
	}

	   
    public static void main(String[] args)
    {
        int count=0;
        String msg;
        
        /** We only allow size of 1 int */
        int[] deviceCount = new int[1];
        int[] errorCode   = new int[1];
        HSM_STATE[] state = new HSM_STATE[1];

        state[0] = HSMS.HALT;
        
		/** Parse command line args */
        parseArg(args);
        
        /** Make sure we have at least a valid HSM number */
        if((option & HSM)==0)
        {
          System.out.println("\nNo valid HSM specified...");
          System.exit(0);
        }

        /** Initialize HSM */
        MdEx.MD_Initialize(null);


        /** Check how many HSM we have */
        MdEx.MD_GetHsmCount(deviceCount);

        /** Perform sanity check on device count and specified device number */
        if(deviceCount[0]<=0)
        {
          System.out.println("\nNo HSM device found...");
          MdEx.MD_Finalize(null);
          System.exit(0);
        }
          
        /** HSM number starts from 0 */
        if(hsm_num+1>deviceCount[0])
        {
          System.out.println("\nCannot find HSM number "+hsm_num);
          MdEx.MD_Finalize(null);
          System.exit(0);
        }

        
        for(count=0; count<=hsm_num; count++)
        {
        	/** Check HSM state */
        	MdEx.MD_GetHsmState(hsm_num, state, errorCode);

        	msg = new String("\nHSM device:"+count+"\t HSM in " + HSMS.errorString(state[0].longValue()) + " mode.");

     	
        	/** If quick mode is not specified, we perform a ping on adapter */
        	if((option & QUICK)==OFF && (option & VERBOSE)!=OFF)
        	{
	        	if(state[0].equals(HSMS.NORMAL_OPERATION))
	        	{
	        		if(isAdapterAlive(count))	
	        			msg = new StringBuffer().append(msg)
	        			                        .append(" RESPONDING to requests.")
	        			                        .toString();
	        		else
	        			msg = new StringBuffer().append(msg)
	        			                        .append(" NOT RESPONDING to requests.")
	        			                        .toString();
        		}
        	}
        	
        	System.out.println(msg);
        	
    	
    	
    	    /** Print more info if verbose is specified */
    	    if((option & VERBOSE)!=OFF)
    	    {
	    	
	    	    msg = new String("\nState = (0x"+Integer.toHexString((int)state[0].intValue())+", 0x"
	    	                                +Integer.toHexString((int)errorCode[0])+")\n");
	    	        System.out.println(msg);
	    	
			    if(state[0].equals(HSMS.NORMAL_OPERATION))
	    		    System.out.println("\n"+statestr.E8KSS_getMbox3HifaceAsString(errorCode[0]));
	    		
	    	    if(state[0].equals(HSMS.WAIT_ON_TAMPER) || state[0].equals(HSMS.POST))
    			    System.out.println("\n"+statestr.E8KSS_getMbox3PostAsString(errorCode[0]));
    		
    		    if(state[0].equals(HSMS.HALT))
    		    {
	    		
	    		    if((errorCode[0] & 0xFFFF0000L)!=0)
	    			    /** halt after normal operation, mb3 has HIFACE version */
					    System.out.println("\n"+statestr.E8KSS_getMbox3HifaceAsString(errorCode[0]));
				    else
					    /** Assumes SCFS codes are less than 0xffff0000 */
					    System.out.println("\n"+statestr.E8KSS_getMbox3PostAsString(errorCode[0]));
			    }	
    		
		    }
	    }
   
    
    	MdEx.MD_Finalize(null);	
        	
     }
}

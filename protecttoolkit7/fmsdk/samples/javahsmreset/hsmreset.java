/*
 *  This file is provided as part of the SafeNet Protect Toolkit FM SDK.
 *
 *  (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
 *  This file is protected by laws protecting trade secrets and confidential
 *  information, as well as copyright laws and international treaties.
 *
 *  Filename: samples/javahsmstate/hsmreset.java
 * $Date: 2014/09/15 12:40:06GMT-05:00 $
 */
 
import safenet.jhsm.*;
import safenet.jhsm.constants.*;
import safenet.jhsm.misc.*;

import java.lang.*;
import java.lang.reflect.Array;

class hsmreset
{
    private  final static String msg = new StringBuffer().append("\n Usage : hsmreset [-h] [-f] [-v] [-d x] where :")
                                                         .append("\n         -h  This help menu                    ")
                                                         .append("\n         -v  Verbose mode                      ")
                                                         .append("\n         -f  Forced reset                      ")
                                                         .append("\n         -d  HSM device number x               ")
                                                         .append("\n Example : hsmstate -d 0	                   ")
                                                         .append("\n                                               ")
                                                         .toString();


	/** Useful constants */
	private	 final static short FM_NUMBER_HIFACE = 0x0000;
	                                             
    /** Bit flags for setting options */
    private  final static int VERBOSE = 0x00000001;
    private  final static int FORCE   = 0x00000002;
    private  final static int HELP    = 0x00000004;
    private  final static int HSM     = 0x00000008;
    private  final static int OFF     = 0;
    
    private  final static int EXIT_FAILURE = 1;
    private  final static int EXIT_OK      = 0;
    
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
            if(args[i].equals("-f") || args[i].equals("-F")) option = option | FORCE;
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
        }
      }
    }
      	
    private static void checkErr(MD_RV rv, boolean finalize)
    {
      String errStr = new String("\nHSM operation unsuccessful");

      if(!rv.equals(MDR.OK))
      {
        if((option & VERBOSE)!=0)
        {
            /** Ok, user wants more info */
            errStr = new StringBuffer().append(errStr)
                                       .append(": Err. code = ")
                                       .append(MDR.errorString(rv))
                                       .toString();
        }

        /** Send MD_Finalize if requested */
        if(finalize)
            Md.MD_Finalize(null);

        System.out.println(errStr);
        System.exit(EXIT_FAILURE);
      }
    }
    
    private static boolean isAdapterAlive(int deviceNum)
    {
	    MD_RV rv;
   
	    Md_Buffer[] req = new Md_Buffer[2];
	    Md_Buffer[] rep = new Md_Buffer[2];
	    int i           = 0;
	    
	    /** 
	      * Prepare a CMD_ECHO buffer to ping the HSM. This sample illustrates the use 
	      * of patterns with different values. 
	      */
	    byte [] pattern = new byte[20];
	    
	    for(i=0;i<20; i++)
	       pattern[i] = (byte)i;
	    
	    echo_cmd hsm_cmd = new echo_cmd(pattern);

	    int[] rxLen  = new int[1];
	    int[] fmStat = new int[1];
	    
	    /** Build HIFACE ECHO_CMD so that we can ping HSM */	
		req[0] = new Md_Buffer(hsm_cmd.cmd());
		
		/** 
		  * We must terminate last buffer by NULL,otherwise MD will continue to assume
		  * there is more Md_Buffer
		  */
		req[1] = new Md_Buffer(0);
		
		
		/** Return bytes is always =  payload for this command */
		rep[0] = new Md_Buffer(hsm_cmd.payload_size());
		rep[1] = new Md_Buffer(0);

		rv = Md.MD_SendReceive( deviceNum,
                                        0, 				    /** OriginatorId */
                                        FM_NUMBER_HIFACE,
                                        req,
                                        0, 			     	/** Reserved, always zero */
                                        rep,
                                        rxLen,				/** Recevied length */
                                        fmStat);			/** application status */
						   		
		
 		checkErr(rv,true);
 		
 		/** If we passed this point, it means adapter is OK */
		return true;
	}

	   
    public static void main(String[] args)
    {
        MD_RV rv;
        int count=0;
        String msg;
        
        /** We only allow size of 1 int */
        int[] deviceCount     = new int[1];
        int[] errorCode       = new int[1];
        HSM_STATE[] state     = new HSM_STATE[1];
        Integer [] paramValue  = new Integer[1];

        
        /** Parse command line args */
        parseArg(args);
        
        /** Make sure we have at least a valid HSM number */
        if((option & HSM)==0)
        {
          System.out.println("\nNo valid HSM specified...");
          System.exit(EXIT_FAILURE);
        }

        /** Initialize HSM */
        rv = Md.MD_Initialize(null);
        checkErr(rv,false);

        /** Check how many HSM we have */
        rv = Md.MD_GetHsmCount(deviceCount);
        checkErr(rv,true);

        /** Perform sanity check on device count and specified device number */
        if(deviceCount[0]<=0)
        {
          System.out.println("\nNo HSM device found...");
          Md.MD_Finalize(null);
          System.exit(EXIT_FAILURE);
        }
          
	  		
        /** Get system parameters - Provided as an example. Not required for resetting HSM */
     	paramValue[0] = new Integer(0);
	
        rv = Md.MD_GetParameter(MDP.MAX_BUFFER_LENGTH, paramValue);
        checkErr(rv,true);
        msg = new String("\nHSM parameter is 0x" + Long.toHexString(paramValue[0].longValue()));
	
        if((option & VERBOSE)!=OFF)
        	System.out.println(msg);
   
   
        /** HSM number starts from 0 */
        if(hsm_num+1>deviceCount[0])
        {
          System.out.println("\nCannot find HSM number "+hsm_num);
          Md.MD_Finalize(null);
          System.exit(EXIT_FAILURE);
        }        
        
        /** Check HSM state */
        rv = Md.MD_GetHsmState(hsm_num, state, errorCode);
        checkErr(rv,true);
        msg = new String("\nHSM state is 0x" + Long.toHexString(state[0].longValue()));

        if((option & VERBOSE)!=OFF)
        	System.out.println(msg);
     
        if(!state[0].equals(HSMS.NORMAL_OPERATION))
        {
	        msg = new StringBuffer().append("\nHSM is not in normal mode")
	                                .append("\nError code : 0x"+Long.toHexString(errorCode[0]))
			                        .append("\nYou can use the hsmstate tool for more information.")
			                        .toString();
		}
		
		else
		{	
	        if(isAdapterAlive(hsm_num))	
	        {
	        		msg = new StringBuffer().append("\nHSM is in normal mode. Resetting it might disturb")
	        			                    .append("\nother applications.")
	        			                    .toString();
            }
	        			                   
	       	else
	       	{
	        		
	        		msg = new StringBuffer().append("\nThe HSM reports to be in normal mode, ")
	        		                        .append("\nbut does not respond to requests.")
	        		                        .append("\nA reset might fail to restart the HSM in ")
	        		                        .append("\nthis situation. When this happens a")
	        		                        .append("\npower cycle is required.")
	        		                        .toString();
        	}
        }
        	
        System.out.println(msg);
        
        if((option & FORCE)==OFF)
        {
        	System.out.println("\nContinue [y/N]" );
        	
        	try
        	{
        		char choice = (char) System.in.read();
        		if(choice!='y' && choice!='Y')
        		{
	        		System.out.println("\nReset HSM aborted...");
	        		System.exit(EXIT_OK);
        		}
    		}
    		
    		catch(Exception e)
    		{
	    		System.out.println(e);
    		}
        	
        	
    	}
    	
    	/** If we reached this point, it means we are proceeding with reset. */
    	if((option & VERBOSE)>0)
    		System.out.println("\nAttempting to reset HSM...");
    	
    	rv = Md.MD_ResetHsm(hsm_num);
    	checkErr(rv,true);
    	
    	if((option & VERBOSE)>0)
    		System.out.println("success");
    	/** 
    	  * Need to delay until device driver gets reset interrupt.
          * Delay of 2s should be enough, as 1024 bit DH Params are now created
	      * in the POST Thread.
	      */
        try
	    {
	    	Thread.sleep(2000);  
    	}
    	
    	catch(Exception e)
    	{
	    		System.out.println(e);
    	}
	     
    	/** 
    	  * Wait until adapter comes back either in Halt or Normal mode.
	 	  * We do not, and can not have a timeout on this
	      * (the adapter can stay indefinitely in the S_WAIT_FOR_TAMPER state.
	      */

   		do
   		{
	   		rv = Md.MD_GetHsmState(hsm_num, state, errorCode);
	   		if(!rv.equals(MDR.OK))
	   		{
		   		System.out.println("\nCannot query HSM state (0x"+Long.toHexString(errorCode[0])+")\n");
		   		System.exit(EXIT_FAILURE);
	   		}
   		}while(!state[0].equals(HSMS.NORMAL_OPERATION) && !state[0].equals(HSMS.HALT));
    
   		/** 
   		  * If it is in Halt mode,
	      * Do not need to test whether can talk to it or not.
	      * won't be able to.
	      */
		if(state[0].equals(HSMS.HALT))
		{
			System.out.println("\nHSM reset failed.");
			System.out.println("\nThe HSM is in Halt mode");
			System.out.println("\nYou can use hsmstate command for more information.");
			System.exit(EXIT_FAILURE);
		}
		
		/** Allow 5 s for all other threads inside adapter to run after POST has finished. */
		try
	    {
	    	Thread.sleep(5000);  
    	}
    	
    	catch(Exception e)
    	{
	    		System.out.println(e);
    	}
		
		if(isAdapterAlive(hsm_num))	
		{
			System.out.println("\nHSM responds to requests.");
			Md.MD_Finalize(null);	
			System.exit(EXIT_OK);
		}
			
	    else
	    {
		    System.out.println("\nHSM reset failed.");
		    
			if((option & VERBOSE)>0)
			{
				rv = Md.MD_GetHsmState(hsm_num, state, errorCode);
				
				if(!rv.equals(MDR.OK))
					System.out.println("\nCannot query HSM state. Error code 0x"+Long.toHexString(rv.longValue()));
				else
					System.out.println("\nHSM in state 0x"+Long.toHexString(state[0].longValue()));
				
			}
			
			Md.MD_Finalize(null);
			System.exit(EXIT_FAILURE);
     	}
 	}
}

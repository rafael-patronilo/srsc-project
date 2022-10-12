/*
 * StreamingServerPrintStats.java 
 * This is an auxiliary class to be used to obtain and to print
 * experimental observatons from instrumenation results for
 * streaming conditions, as measured dyamically by the
 * Streaming Server 
 * 
 * You must design and implement this, with the required methods
 * to print the rrquired statistics for the experimental evaluation of
 * different cryptographic configurations used for the required
 * RTSSP protocol
*/

// ..... Implement the code

// For the required statistics use this as reference for
// the observations you must print from your new Streaming Server
// implementation to support the RTSSP protocol

    // PrintStats
    // You must implement th code to compute and obtain
    // the statistics and metrics for each received stream
    // processed and delivered by the Box (to the media player)
    // The idea is to capture the necessary instrumentation of
    // received and processed streams using the input variables
    // for PritStats to print (in the end of each streaming) the
    // related experimental observations for practical analysis
    // The idea is to capture the statistics below


    private void PrintStats(String movie, String csuite, String ks,
			    int ksize, String hic,
			    int nf, int afs, int ms, int etm,
			    int frate, int tput)
    {

    System.out.println("---------------------------------------------");
    System.out.println("Streaming Server observed Indicators and Statistics");
    System.out.println("---------------------------------------------");
    System.out.println("Streamed Movie and used Cryptographic Configs");
    System.out.println("---------------------------------------------");
    System.out.println("Movie (streamed):" +movie );
    System.out.println("Used ciphersuite ALG/MODE/PADDING: " +csuite);
    System.out.println("Used Key (hexadecimal rep.): "+ks);
    System.out.println("Used Keysize: " +ksize);
    System.out.println("Used Hash or Mac for integrty checks: " +hic);
    System.out.println();
    System.out.println("---------------------------------------------");
    System.out.println("Performance indicators of streaming" );
    System.out.println("delivered to receiver Box(es)");
    System.out.println("---------------------------------------------");
    System.out.println("Nr of sent frames: " + nf);
    System.out.println("Average frame size: " + afs);
    System.out.println("Movie size sent (all frames): " + ms);
    System.out.println("Total elapsed time of streamed movie: " + etm);
    System.out.println("Average sent frame rate (frames/sec): " +frate);
    System.out.println("Observed troughput (KBytes/sec): " + tput);

    }

// ..... complete ...
}


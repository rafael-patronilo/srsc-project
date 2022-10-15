/* PrintStats to be used by the Box, 22/23
 * Need to implement this ...
 */

    // PrintStats
    // You must implement th code to compute and obtain
    // the statistics and metrics for each received stream
    // processed and delivered by the Box (to the media player)
    // The idea is to capture the necessary instrumentation of
    // received and processed streams using the input variables
    // for PritStats to print (in the end of each streaming) the
    // related experimental observations for practical analysis

    // The idea is to capture the statistics below
    // Quite similar to the Statistics that will be also observed in the Streaming Server


    private void PrintStats(String movie, String csuite, String hic,
			    String ks, int ksize,
			    int nf, int afs, int ms, int etm,
			    int frate, int tput)
    {

	System.out.println("---------------------------------------------");
	System.out.println("BOX Indicators and Statistics");	
	System.out.println("---------------------------------------------");
        System.out.println();
	System.out.println("---------------------------------------------");
	System.out.println("Receved Movie and used Cryptographic Configs");
	System.out.println("---------------------------------------------");
	System.out.println("Received movie (receoved streamed):" +movie );
	System.out.println("Used ciphersuite ALG/MODE/PADDING: " +csuite);
	System.out.println("Used Key (hexadecimal rep.): "+ks);
	System.out.println("Used Keysize: " +ksize);
	System.out.println("Used Hash for integrty checks: " +hic);

	System.out.println();	
	System.out.println("---------------------------------------------");
	System.out.println("Performance indicators of received stream" );
	System.out.println("processed delivered to the media player");
	System.out.println("---------------------------------------------");
	System.out.println("avg size of the received encrypted segments: " + asesegments);
	System.out.println("avg size of the decrypted segments: " + asdecsegments);
	System.out.println("Nr of received frames: " + nf);
	System.out.println("Processed average frame size: " + afs);
	System.out.println("Received movie size (all frames): " + ms);
	System.out.println("Total elapsed time of received movie: " + etm);
	System.out.println("Average frame rate (frames/sec): " +frate);
	System.out.println("Box observed troughput (KBytes/sec): " + tput);
	System.out.println("Nr of segments w/ integrity invalidation \n(filtered and not sent to the media player) " + csegments);	
	System.out.println("---------------------------------------------");

	  // Coplete the PrintStats (......) as required
	  // can include other observations/instrumentations proposed as interesting
	  // for experimental observations


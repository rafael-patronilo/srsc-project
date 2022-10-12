/*
 * 
 * hjStreamServer.java 
 * Implementatio of a Java-based Streaming Server allowing the
 * the real time streaming of movies encoded in local files
 * The Streaming Server transmits the video frames for real time streaming
 * based (carried in)  UDP packets.
 * Clients can play the streams in real time if they are able to
 * decode the content of the frames in the UDP packets (FFMPEG encoding)
 *
 * To start the Streaming Server use:
 * hjStreamServer <file> <ip address for dissemination> <port dissemination>
 * 
 * Example: hjStreamServer cars.dat localhost 9999
 * In this case the Streaming server will send the movie to localhost port 999
 * where "someone" - a user using a visualizaton tool such as VLC or a BOX
 * is waiting for.
 * There are some available movies in the directory movies. This is the
 * the directory where the server has the movies it can send.
*/

import java.io.*;
import java.net.*;

class hjStreamServer {

	public static void main( String []args ) throws Exception {
	        if (args.length != 3)
	        {
                   System.out.println ("Use: hjSteramServer <movie> <ip-multicast-address> <port>");
	           System.out.println("  or: hjStreamServer <movie> <ip-unicast-address> <port>");
		   
	           System.exit(-1);
                }
      
		int size=0;
		int count=0;
 		long time=0;

                // Variables for instrumentation parameters and
		// statistics. This instrumentation must be implemented
		// for TP1
		String movie = "";
		String ciphersuite=""; //configured ciphersuite
		String hcheck=""; //config. cryptographic hash function
		String key=""; //configured key in hexadecimal representation
		int ksize=0; //key size used
		int nf=0; // number of sent frames in the stream
		int afs=0; // average size of sent frames
		int ms=0; // total size of the stremed movie
		int etm=0; // total elapsed time of the sent movie
		int frate=0; // achieved frame rate in #frames/sec
		int tput=0;// achieved throughput in transmissoin in Kbytes/sec
		    
		
		DataInputStream g = new
		    DataInputStream( new FileInputStream(args[0]) );
		// The file with the movie-media content (encoded frames)
		
		byte[] buff = new byte[4096];
		// Probably you must use a bigger buff size for the
		// purpose of TP1, because in the TP1 you will use the
		// buffer to process encrypted streams together with
		// with hash-based integrity checks as required for
		// TP1 implementation

		DatagramSocket s = new DatagramSocket();
		InetSocketAddress addr =
		    new InetSocketAddress( args[1], Integer.parseInt(args[2]));
		DatagramPacket p = new DatagramPacket(buff, buff.length, addr );
		long t0 = System.nanoTime(); //ref time for real-time stream
		long q0 = 0;

		while ( g.available() > 0 ) { //while I have segments to read
			size = g.readShort();
			time = g.readLong();
			if ( count == 0 ) q0 = time; //real time stream control
			count += 1;
			g.readFully(buff, 0, size ); //read a segment
			p.setData(buff, 0, size );   //prepare segment to send
			p.setSocketAddress( addr );  //build the dgram packet
			long t = System.nanoTime(); //take current time
			// and sync. the wait tome to dispatch the segment
			// correctly with the required real-time control
			// (as encoded in segment timestamps)
			Thread.sleep( Math.max(0, ((time-q0)-(t-t0))/1000000));
		        // send packet (with a frame payload)		   
			s.send( p ); // Send UDP datagrams (not protected)
			
			System.out.print( "." ); // just for debug
			// tahe this last line off or any I/O or debug for
			// final observations in TP1

			System.out.println("DONE! all frames sent: "+count);

			// Note:
			// For TP1
			// YOU MUST IMPLEMENT THE REQUIRED SECURITY
			// SPECIFICATIONS and you MUST PROCESS THE
			// INSTRUMENTATION VARIABLES
			// REQUIRED TO USE FOR PrintStsts (see below)
			// to obtain the related
			// experimental anlysis and observations, as observed
			// in the StreamingServer side

                        //to do this the idea is to support this in a
			//method you must implement, inspired in the
			// following PrintStats() calling it with the
			// obtained instrumentation variabes during the
			// stream
			
		}
	}

    // Print statistics and metrics as required
    
    public void PrintStats(String m, String csuite, String k, int ks,
			   String ihcheck,
			   int nf, int afs, int ms, int etm, int frate,
			   int tput)
    {
        System.out.println("---------------------------------------------");
	System.out.println("Sreaming Server");
        System.out.println("Statistics / Metrics");
        System.out.println("---------------------------------------------");
	System.out.println();
	System.out.println("---------------------------------------------");
	System.out.println("Streamed media-movie and security configs");
	System.out.println("---------------------------------------------");
	System.out.println("Received/Streamed Movie:" + m);
	System.out.println("Used Ciphersuite /ALG/MODE/PADDING:" + csuite);
	System.out.println("Used key (hexadecimal rep):" + k);
        System.out.println("Key size used:" + ks);	
	System.out.println("Used secure Hash for integrity check:" + ihcheck);
        System.out.println("---------------------------------------------");
        System.out.println("Performance indicators of processed stream");
        System.out.println("---------------------------------------------");
        System.out.println("Nr of sent frames:" + nf );
        System.out.println("Average frame size:" +  afs);
        System.out.println("Movie size (all streamed frames):" + ms );  
        System.out.println("Total elapsed time of movie:" + etm);
        System.out.println("Observed average frame rate (frames/sec)" + frate);
        System.out.println("Observed troughput (KBytes/sec)" + tput);
        System.out.println("---------------------------------------------");
    }
}






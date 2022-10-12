/*
 * hjStreamServer.java 
 * This is a Streaing server inspired (very similar) to the
 * Streaing Server presented, used and analyzied in Lab (Lab 2, Part I)
 * You will use it as a starting point for the implementation of the
 * Streaming server for the TP1 Requirements and for the implementation
 * of the RTSSP protocol
*/

import java.io.*;
import java.net.*;

class hjStreamServer {

    static public void main( String []args ) throws Exception {
        if (args.length != 3)
        {
           System.out.println("Use: hjStreamServer <movie> <ip-multicast-address> <port>");
           System.out.println("or: hjStreamServer <movie> <ip-unicast-address> <port>");
           System.exit(-1);
         }
      
	int size;
	int count = 0;
	long time;

	// Need these variables for instrumentation metrics 
	// observed by your new implementation of the Strraming Server
	// when sending media supported by the RTSSP protocol

	String movie; // name of sent movie
	String csuite; // used cyphersuite for streaming
	String k;   // The key used, in Hexadecimal representation
	int ksize;  // The key size
	String hic; // Hash function used for integrity checks
	int nf;     // number of sent frames in a mmvie transmission
	int afs;    // average frame size in transmited frames
	int ms;     // total size of the movie (all segments) in Kbytes
	int etm;    // total elapsed time of the streamed movie
	int frate;  // observed frame rate in segments/sec)
	int tput;   // observed throughput (in Kbytes/sec)
		
	DataInputStream g =
	    new DataInputStream( new FileInputStream(args[0]) );
	byte[] buff = new byte[4096]; // can change if required

	DatagramSocket s = new DatagramSocket();
	InetSocketAddress addr =
	    new InetSocketAddress( args[1], Integer.parseInt(args[2]));
	DatagramPacket p = new DatagramPacket(buff, buff.length, addr );
	long t0 = System.nanoTime(); // current time 
	long q0 = 0;

	while ( g.available() > 0 ) {
		size = g.readShort();
		time = g.readLong();
		if ( count == 0 ) q0 = time; // ref time encoded
		        count += 1;
			g.readFully(buff, 0, size );
			p.setData(buff, 0, size );
			p.setSocketAddress( addr );
			long t = System.nanoTime();
			Thread.sleep( Math.max(0, ((time-q0)-(t-t0))/1000000) );
		        // send packet (with a frame payload)
			s.send( p );
			System.out.print( "." ); // only for debug
			// comment this for final experiment al observations
		}

	// you must inlude now the call for PrintStats to print the
	// experimental observation of instrumentation variables

	System.out.println
	    ("DONE! all frames sent in this streaming transmission: "+count);

    }

}


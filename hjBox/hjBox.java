/* hjBox, 22/23
 *
 * This is the implementation of a Box to receive streamed UDP packets
 * (with media segments as payloads encoding MPEG4 frames)
 * The code is inspired (in fact very similar) to the code presented,
 * available, used and discussed in Labs (Lab 2, Part I)
 *
 * You ca use this material as a starting point for your Box implementation
 * in TP1, according to the TP1 requirements
 */

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.MulticastSocket;
import java.net.InetSocketAddress;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

class hjBox {
    
    private static InetSocketAddress parseSocketAddress(String socketAddress) 
    {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }    
    
    public static void main(String[] args) throws Exception {

	// Need these variables for instrumentation metrics on
	// received and processed streams delivered to the
	// media player
	String movie; // name of received movie
	String csuite; // used cyphersuite to process the received stream
	String k;   // The key used, in Hexadecimal representation
        int ksize;  // The key size
        String hic; // Hash function used for integrity checks
	int ascsegments;    // average size of encrypted segments received
	int decsegments;    // average size of decrypted segments received	
        int nf;     // number of received frames in a mmvie transmission
	int afs;    // average frame size in a movie transmission
	int ms;     // total size of the receved movie (all segments) in Kbytes
	int etm;    // total elapsed time of the received movie
	int frate;  // observed frame rate in segments/sec)
        int tput;   // observed throughput in the channel (in Kbytes/sec)
        int corruptedframes;   // Nr of corrupted frames discarded (not sent to the media player
	// can add more instrumentation variables considered as interesting
	
        InputStream inputStream = new FileInputStream("configs/config.properties");
        if (inputStream == null) {
            System.err.println("Configuration file not found!");
            System.exit(1);
        }
        Properties properties = new Properties();
        properties.load(inputStream);
	String remote = properties.getProperty("remote");
        String destinations = properties.getProperty("localdelivery");

        SocketAddress inSocketAddress = parseSocketAddress(remote);
        Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(",")).map(s -> parseSocketAddress(s)).collect(Collectors.toSet());

	DatagramSocket inSocket = new DatagramSocket(inSocketAddress); 
        DatagramSocket outSocket = new DatagramSocket();
        byte[] buffer = new byte[4096];
	// probably you ned to use a larger buffer for the requirements of
	// TP1 - remember that you will receive datagrams with encrtypted
	// contents, so depending on the crypti configurations, the datagrams
	// will be bigger than the plaintext data in the initial example.

	// Not that this Box is always tryying to receive streams
	// You must modify this to contrl teh end of one received
	// movie) to obtain the relqted statistics (see PrintStats)
	
        while (buffer.length > 0 ) {
          DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
 	  inSocket.receive(inPacket);  

          System.out.print("*"); // Just for debug. Comment for final
	                         // observations and statistics
	  
          for (SocketAddress outSocketAddress : outSocketAddressSet) 
            {
              outSocket.send(new DatagramPacket(buffer, inPacket.getLength(), outSocketAddress));
	    }


	  // TODO: You must control/detect the end of a streamed movie to
	  // call PrintStats to print the obtained statistics from
	  // required instrumentation variables for experimental observations

	  // PrintStats (......)
	}
    }
}

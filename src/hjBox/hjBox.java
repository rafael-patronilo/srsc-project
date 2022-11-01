package hjBox;
/* hjBox, 22/23
 *
 * This is the implementation of a Box to receive streamed UDP packets
 * (with media segments as payloads encoding MPEG4 frames)
 * The code is inspired (in fact very similar) to the code presented,
 * available, used and discussed in Labs (Lab 2, Part I)
 *
 *
 * You ca use this material as a starting point for your Box implementation
 * in TP1, according to the TP1 requirements
 *
 */

import crypto.CryptoStuff;
import crypto.IntegrityException;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

public class hjBox {

    private static InetSocketAddress parseSocketAddress(String socketAddress) {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }

    public static void main(String[] args) throws Exception {

        InputStream inputStream = new FileInputStream("hjBox/configs/config.properties");
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
        CryptoStuff boxCrypto = CryptoStuff.loadFromFile("hjBox/configs/box-cryptoconfig", "127.0.0.1:6666");
        boxCrypto.printProperties();
        DatagramSocket inSocket = new DatagramSocket(inSocketAddress);
        DatagramSocket outSocket = new DatagramSocket();
        byte[] buffer = new byte[4096];
        // probably you ned to use a larger buffer for the requirements of
        // TP1 - remember that you will receive datagrams with encrypted
        // contents, so depending on the crypto configurations, the datagrams
        // will be bigger than the plaintext data in the initial example.

        // Not that this Box is always trying to receive streams
        // You must modify this to control teh end of one received
        // movie) to obtain the related statistics (see PrintStats)
        while (true){
            DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
            inSocket.receive(inPacket);
            String movie = new String(buffer, 0, buffer.length);
            streamMovie(movie, buffer, inSocket, outSocket, outSocketAddressSet, boxCrypto);
        }

    }

    private static void streamMovie(String movie, byte[] buffer, DatagramSocket inSocket,
                                    DatagramSocket outSocket, Set<SocketAddress> outSocketAddressSet,
                                    CryptoStuff boxCrypto)
            throws Exception{
        // Need these variables for instrumentation metrics on
        // received and processed streams delivered to the
        // media player
        String csuite; // used cyphersuite to process the received stream
        String k;   // The key used, in Hexadecimal representation
        int ksize;  // The key size
        String hic; // Hash function used for integrity checks
        int ascsegments = 0;    // average size of encrypted segments received
        int decsegments = 0;    // average size of decrypted segments received
        int nf;     // number of received frames in a movie transmission
        int afs;    // average frame size in a movie transmission
        int ms = 0;     // total size of the received movie (all segments) in Kbytes
        int etm;    // total elapsed time of the received movie
        int frate;  // observed frame rate in segments/sec)
        int tput;   // observed throughput in the channel (in Kbytes/sec)
        int corruptedframes = 0;   // Nr of corrupted frames discarded (not sent to the media player
        // can add more instrumentation variables considered as interesting
        int count = 0;
        long t, t0 = 0;

        System.out.println("Now playing: " + movie);
        int packetSize;
        boxCrypto.startDecryption();
        while (true) {
            if(count == 0) t0 = System.nanoTime();
            count++;
            DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
            inSocket.receive(inPacket);
            ascsegments += inPacket.getLength();
            try {
                packetSize = boxCrypto.handlePacket(buffer, inPacket.getLength());
                decsegments += packetSize;
                ms += packetSize;
                System.out.println(inPacket.getLength() + " "  + packetSize);
                System.out.println(CryptoStuff.bytesToHex(buffer, 0, 16));
                for (SocketAddress outSocketAddress : outSocketAddressSet) {
                    outSocket.send(new DatagramPacket(buffer, packetSize, outSocketAddress));
                }
                if (packetSize == 0)
                    break;
            } catch (IntegrityException e){
                System.out.println("Corrupted " + e.getMessage());
                corruptedframes++;
            }
        }
        t = System.nanoTime();
        // call PrintStats to print the obtained statistics from
        // required instrumentation variables for experimental observations

        // PrintStats (......)
        csuite = boxCrypto.getCiphersuite();
        k = boxCrypto.getKey();
        ksize = k.length()*8;
        hic = boxCrypto.getIntegrity();
        nf = count - 1; // last packet isn't a frame
        etm = (int)((t - t0) / 1_000_000_000L); // seconds
        afs = ms / nf;
        frate = nf / etm;
        tput = (ms / 1000) / etm;
        ascsegments /= nf;
        decsegments /= nf;

        PrintStats(movie, csuite, hic, k, ksize,  nf,
                afs, ms, etm, frate, tput, ascsegments, decsegments, corruptedframes);
        System.out.println();
    }

    private static void PrintStats(String movie, String csuite, String hic,
                            String ks, int ksize,
                            int nf, int afs, int ms, int etm,
                            int frate, int tput,
                            int asesegments, int asdecsegments, int csegments) {

        System.out.println("---------------------------------------------");
        System.out.println("BOX Indicators and Statistics");
        System.out.println("---------------------------------------------");
        System.out.println();
        System.out.println("---------------------------------------------");
        System.out.println("Receved Movie and used Cryptographic Configs");
        System.out.println("---------------------------------------------");
        System.out.println("Received movie (receoved streamed):" + movie);
        System.out.println("Used ciphersuite ALG/MODE/PADDING: " + csuite);
        System.out.println("Used Key (hexadecimal rep.): " + ks);
        System.out.println("Used Keysize: " + ksize);
        System.out.println("Used Hash for integrty checks: " + hic);

        System.out.println();
        System.out.println("---------------------------------------------");
        System.out.println("Performance indicators of received stream");
        System.out.println("processed delivered to the media player");
        System.out.println("---------------------------------------------");
        System.out.println("avg size of the received encrypted segments: " + asesegments);
        System.out.println("avg size of the decrypted segments: " + asdecsegments);
        System.out.println("Nr of received frames: " + nf);
        System.out.println("Processed average frame size: " + afs);
        System.out.println("Received movie size (all frames): " + ms);
        System.out.println("Total elapsed time of received movie (sec): " + etm);
        System.out.println("Average frame rate (frames/sec): " + frate);
        System.out.println("Box observed troughput (KBytes/sec): " + tput);
        System.out.println("Nr of segments w/ integrity invalidation \n(filtered and not sent to the media player) " +
                csegments);
        System.out.println("---------------------------------------------");
    }
}

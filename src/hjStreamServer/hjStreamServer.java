package hjStreamServer;
/*
 * hjStreamServer.java
 * This is a Streaing server inspired (very similar) to the
 * Streaing Server presented, used and analyzied in Lab (Lab 2, Part I)
 * You will use it as a starting point for the implementation of the
 * Streaming server for the TP1 Requirements and for the implementation
 * of the RTSSP protocol
 */

import crypto.CryptoStuff;
import crypto.Handshake;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.PortUnreachableException;

public class hjStreamServer {
    private static final String PASSWORD = "c4b0fbc4820e2e904b944f58ce4d90b4";
    static public void main(String[] args) throws Exception {

        if (args.length != 2) {
            System.out.println("Use: hjStreamServer <ip-multicast-address> <port>");
            System.out.println("or: hjStreamServer <ip-unicast-address> <port>");
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
        int ms = 0;     // total size of the movie (all segments) in Kbytes
        int etm;    // total elapsed time of the streamed movie
        int frate;  // observed frame rate in segments/sec)
        int tput;   // observed throughput (in Kbytes/sec)

        byte[] buffer = new byte[10096]; // can change if required
        InetSocketAddress addr =
                new InetSocketAddress(args[0], Integer.parseInt(args[1]));
        Handshake handshake = Handshake.load("hjStreamServer/configs/supported",
                "hjStreamServer/server.jks", PASSWORD);
        DatagramSocket s = new DatagramSocket(addr);
        int movieLength =  handshake.listenForHandshake(buffer, s);
        System.out.println("Handshake completed");
        CryptoStuff boxCrypto = handshake.getGeneratedCrypto();
        boxCrypto.printProperties();
        byte[] movieBytes = new byte[movieLength];
        System.arraycopy(buffer, 0, movieBytes, 0, movieLength);
        movie = new String(movieBytes);
        String movieFilename = movie + ".dat.encrypted";
        String moviePath = "hjStreamServer/movies/" + movieFilename;
        System.out.println("Movie: " + movie);
        System.out.println("Movie file: " + movieFilename);
        System.out.println("Movie path: " + moviePath);


        //CryptoStuff boxCrypto = CryptoStuff.loadFromFile("hjStreamServer/configs/box-cryptoconfig", box);
        //boxCrypto.printProperties();
        CryptoStuff movieCrypto = CryptoStuff.loadFromFile("hjStreamServer/configs/movies-cryptoconfig", movieFilename);
        movieCrypto.printProperties();

        byte[] movieData = movieCrypto.decryptFile(moviePath);

        DataInputStream g =
                new DataInputStream(new ByteArrayInputStream(movieData));

        DatagramPacket p = new DatagramPacket(buffer, buffer.length);
        long t0 = System.nanoTime(); // current time
        long t = t0;
        long q0 = 0;
        boxCrypto.startEncryption();
        int packetSize;

        // send movie name
        byte[] movieB = movie.getBytes();
        p.setData(movieB);
        s.send(p);
        boolean boxDisconnected = false;

        while (g.available() > 0) {
            size = g.readShort();
            ms += size;
            time = g.readLong();
            if (count == 0) q0 = time; // ref time encoded
            count += 1;
            g.readFully(buffer, 0, size);
            System.out.print(".");
            packetSize = boxCrypto.handlePacket(buffer, size);
            p.setData(buffer, 0, packetSize);
            //p.setSocketAddress(addr);
            t = System.nanoTime();
            Thread.sleep(Math.max(0, ((time - q0) - (t - t0)) / 1000000)/*10000*/);
            // send packet (with a frame payload)
            try {
                s.send(p);
            } catch (PortUnreachableException e) {
                System.out.println("Box disconnected");
                boxDisconnected = true;
                break;
            }
            //System.out.print("."); // only for debug
            // comment this for final experiment al observations
        }
        System.out.println();

        if (!boxDisconnected) {
            //Send empty packet to signal end of stream
            System.out.println("Sending end packet");
            p.setData(new byte[]{ (byte)0xFF }, 0, 1);
            s.send(p);
        }

        // you must inlude now the call for PrintStats to print the
        // experimental observation of instrumentation variables

        System.out.println
                ("DONE! all frames sent in this streaming transmission: " + count);
        csuite = boxCrypto.getCiphersuite();
        k = boxCrypto.getKey();
        ksize = k.length()*8;
        hic = boxCrypto.getIntegrity();
        nf = count;
        etm = (int)((t - t0) / 1_000_000_000L); // seconds
        afs = ms / nf;
        frate = nf / etm;
        tput = (ms / 1000) / etm;
        PrintStats(movie, csuite, k, ksize, hic, nf, afs, ms, etm, frate, tput);
    }


    private static void PrintStats(String movie, String csuite, String ks,
                            int ksize, String hic,
                            int nf, int afs, int ms, int etm,
                            int frate, int tput) {

        System.out.println("---------------------------------------------");
        System.out.println("Streaming Server observed Indicators and Statistics");
        System.out.println("---------------------------------------------");
        System.out.println("Streamed Movie and used Cryptographic Configs");
        System.out.println("---------------------------------------------");
        System.out.println("Movie (streamed):" + movie);
        System.out.println("Used ciphersuite ALG/MODE/PADDING: " + csuite);
        System.out.println("Used Key (hexadecimal rep.): " + ks);
        System.out.println("Used Keysize: " + ksize);
        System.out.println("Used Hash or Mac for integrty checks: " + hic);
        System.out.println();
        System.out.println("---------------------------------------------");
        System.out.println("Performance indicators of streaming");
        System.out.println("delivered to receiver Box(es)");
        System.out.println("---------------------------------------------");
        System.out.println("Nr of sent frames: " + nf);
        System.out.println("Average frame size: " + afs);
        System.out.println("Movie size sent (all frames): " + ms);
        System.out.println("Total elapsed time of streamed movie: " + etm);
        System.out.println("Average sent frame rate (frames/sec): " + frate);
        System.out.println("Observed troughput (KBytes/sec): " + tput);

    }
}


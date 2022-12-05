package crypto;

import javax.crypto.KeyAgreement;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.security.KeyStore;

import static crypto.CryptoStuff.hexToBytes;

public class Handshake {
    public static final int NONCE_LENGTH = 8;
    public static final int DH_KEY_SIZE = 2048;

    private static final String CLIENT_HELLO = "CLIENT HELLO";
    private static final String SERVER_HELLO = "SERVER HELLO";
    private static final String NEGOTIATION_HEADER = "NEGOTIATION";
    private static final String NEGOTIATION_TAIL = "END " + NEGOTIATION_HEADER;

    private static final String CERTIFICATE_HEADER = "CERTIFICATE";
    private static final String CERTIFICATE_TAIL = "END " + CERTIFICATE_HEADER;

    private static final String TIMESTAMP_FIELD = "Timestamp";
    private static final String NONCE_FIELD = "Nonce";

    private static final String RETURN_TIMESTAMP_FIELD = "Your-Timestamp";
    private static final String RETURN_NONCE_FIELD = "Your-Nonce";

    private static final String PICKED_HEAD = "PICKED";

    private static final String PICKED_TAIL = "END " + PICKED_HEAD;

    private static final String EXCHANGE_FIELD = "Exchange";

    private final CiphersuiteList supported;

    private final X509Certificate myCertificate;

    private final String myCertificateEncoded;
    private X509Certificate peerCertificate = null;

    private String myTimestamp = null, myNonce = null;

    private PrivateKey dhPrivate = null;
    private PublicKey dhPublic = null;

    private Ciphersuite sessionCS = null;
    private Ciphersuite hanshakeCS = null;

    private byte[] dhSecret = null;

    private KeyStore keyStore;

    public static Handshake load(String certificatePath, String supportedPath,
                                 String keystorePath, String password) throws CryptoException {
        CiphersuiteList supported;
        X509Certificate certificate;
        InputStream certificateFile;
        try {
            List<String> supportedLines = Files.readAllLines(Paths.get(supportedPath));
            supported = CiphersuiteList.parse(supportedLines);

            certificateFile = new BufferedInputStream(new FileInputStream(certificatePath));
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            certificate = (X509Certificate) factory.generateCertificate(certificateFile);

            FileInputStream stream = new FileInputStream(certificatePath);
            String certificateEncoded = new String(stream.readAllBytes());
            stream.close();

            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream(keystorePath), password.toCharArray());
            return new Handshake(supported, certificate, certificateEncoded, keyStore);
        } catch (IOException | CertificateException |
                 KeyStoreException | NoSuchAlgorithmException e) {
            throw new CryptoException("Error initializing handshake", e);
        }
    }

    public Handshake(CiphersuiteList supported, X509Certificate certificate,
                     String myCertificateEncoded, KeyStore keyStore) {
        this.supported = supported;
        this.myCertificate = certificate;
        this.myCertificateEncoded = myCertificateEncoded;
        this.keyStore = keyStore;
    }

    private void verifySignature(List<String> lines,
                                 String signatureHex, String signatureAlgorithm, String publicKey)
            throws CryptoException, IntegrityException {
        try{
            Signature signature = Signature.getInstance(signatureAlgorithm);
            KeyFactory keyFactory = KeyFactory.getInstance(signatureAlgorithm);
            EncodedKeySpec verifyKeySpec = new X509EncodedKeySpec(hexToBytes(publicKey));
            PublicKey verifyKey = keyFactory.generatePublic(verifyKeySpec);
            signature.initVerify(verifyKey);
            byte[] signatureBytes = hexToBytes(signatureHex);
            for (String line : lines) {
                signature.update(line.getBytes());
            }
            signature.verify(signatureBytes);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException e) {
            throw new CryptoException("Handshake failed", e);
        } catch (SignatureException e){
            throw new IntegrityException("Invalid signature");
        }
    }

    private void generateDH(){
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("DH", "BC");
            generator.initialize(DH_KEY_SIZE);
            KeyPair pair = generator.generateKeyPair();
            this.dhPrivate = pair.getPrivate();
            this.dhPublic = pair.getPublic();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    private void finishDH(String peerPublic) throws CryptoException{
        try{
            KeyAgreement agreement = KeyAgreement.getInstance("DH", "BC");
            agreement.init(dhPrivate);
            KeyFactory kf = KeyFactory.getInstance("DH");
            PublicKey peerKey = kf.generatePublic(new X509EncodedKeySpec(CryptoStuff.hexToBytes(peerPublic)));
            agreement.doPhase(peerKey, true);
            dhSecret = agreement.generateSecret();
        } catch (NoSuchAlgorithmException | NoSuchProviderException |
                 InvalidKeyException | InvalidKeySpecException e) {
            throw new CryptoException("Error completing Diffie Hellman", e);
        }
    }

    private void appendMyChallenge(StringBuilder builder){
        SecureRandom random = new SecureRandom();
        byte[] nonce = new byte[NONCE_LENGTH];
        random.nextBytes(nonce);
        myNonce = CryptoStuff.bytesToHex(nonce).toLowerCase();
        myTimestamp = Long.toHexString(System.currentTimeMillis()).toLowerCase();
        builder.append(TIMESTAMP_FIELD)
                .append(":").append(myTimestamp).append("\n");
        builder.append(NONCE_FIELD)
                .append(":").append(myNonce).append("\n");
    }

    private void pickSuites(CiphersuiteList clientSupported) throws CryptoException {
        this.sessionCS = supported.findFirstSession(clientSupported);
        this.hanshakeCS = supported.findFirstHandshake(clientSupported);
        if(this.sessionCS == null || this.hanshakeCS == null){
            throw new CryptoException("Negotiation failed");
        }
    }

    public byte[] generateClientHello(){
        StringBuilder builder = new StringBuilder();
        builder.append(CLIENT_HELLO).append("\n");
        builder.append(NEGOTIATION_HEADER).append("\n");
        builder.append(supported.stringBuilder());
        builder.append(NEGOTIATION_TAIL).append("\n");
        appendMyChallenge(builder);

        generateDH();
        builder.append(EXCHANGE_FIELD)
                .append(":").append(CryptoStuff.bytesToHex(dhPublic.getEncoded())).append("\n");

        builder.append(CERTIFICATE_HEADER).append("\n");
        builder.append(myCertificateEncoded).append("\n");
        builder.append(CERTIFICATE_TAIL).append("\n");
        return builder.toString().getBytes();
    }

    public byte[] respondClientHello(byte[] clientHello) throws CryptoException{
        Scanner scanner = new Scanner(new ByteArrayInputStream(clientHello));
        if(!scanner.nextLine().trim().equalsIgnoreCase(CLIENT_HELLO)){
            throw new CryptoException("Not a client hello");
        }
        if(!scanner.nextLine().trim().equalsIgnoreCase(NEGOTIATION_HEADER)){
            throw new CryptoException("Expected protocol negotiation");
        }
        List<String> lines = new ArrayList<>();
        String line = scanner.nextLine();
        while (!line.trim().equalsIgnoreCase(NEGOTIATION_TAIL)){
            lines.add(line);
            line = scanner.nextLine();
        }
        CiphersuiteList clientSupported = CiphersuiteList.parse(lines);
        String[] parts;

        line = scanner.nextLine();
        parts = line.split(":");
        if(!parts[0].trim().equalsIgnoreCase(TIMESTAMP_FIELD)){
            throw new CryptoException("Expected client timestamp");
        }
        String clientTimestamp = parts[1].trim();

        line = scanner.nextLine();
        parts = line.split(":");
        if(!parts[0].trim().equalsIgnoreCase(NONCE_FIELD)) {
            throw new CryptoException("Expected client nonce");
        }
        String clientNonce = parts[1].trim();

        generateDH();

        line = scanner.nextLine();
        parts = line.split(":");
        if(!parts[0].trim().equalsIgnoreCase(EXCHANGE_FIELD)) {
            throw new CryptoException("Expected key exchange parameters");
        }
        finishDH(parts[1].trim());
        if(!scanner.nextLine().trim().equalsIgnoreCase(CERTIFICATE_HEADER)){
            throw new CryptoException("Expected certificate");
        }
        StringBuilder cert = new StringBuilder();
        System.out.println("Cert");
        line = scanner.nextLine();
        System.out.println(line);
        while(!line.trim().equalsIgnoreCase(CERTIFICATE_TAIL)){
            cert.append(line).append("\n");
            line = scanner.nextLine();
            System.out.println(line);
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            byte[] b = cert.toString().getBytes();
            System.out.println(b.length);
            InputStream stream = new ByteArrayInputStream(b);
            this.peerCertificate = (X509Certificate) cf.generateCertificate(stream);
        } catch (CertificateException e) {
            throw new CryptoException("Invalid certificate", e);
        }
        pickSuites(clientSupported);
        return generateServerHello(clientTimestamp, clientNonce);
    }

    private byte[] generateServerHello(String clientTimestamp, String clientNonce){
        StringBuilder builder = new StringBuilder();
        builder.append(SERVER_HELLO).append("\n");
        CiphersuiteList picked = new CiphersuiteList();
        picked.addSession(sessionCS);
        picked.addHandshake(hanshakeCS);
        builder.append(PICKED_HEAD).append("\n");
        builder.append(picked.stringBuilder());
        builder.append(PICKED_TAIL).append("\n");

        appendMyChallenge(builder);

        builder.append(RETURN_TIMESTAMP_FIELD)
                .append(":").append(clientTimestamp).append("\n");
        builder.append(RETURN_NONCE_FIELD)
                .append(":").append(clientNonce).append("\n");

        builder.append(EXCHANGE_FIELD)
                .append(":").append(CryptoStuff.bytesToHex(dhPublic.getEncoded())).append("\n");

        builder.append(CERTIFICATE_HEADER).append("\n");
        builder.append(myCertificateEncoded).append("\n");
        builder.append(CERTIFICATE_TAIL).append("\n");

        byte[] packet = builder.toString().getBytes();
        //TODO sign
        return packet;
    }
}

package crypto;

import javax.crypto.*;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.*;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.*;
import java.util.*;
import java.security.KeyStore;

import static crypto.CryptoStuff.bytesToHex;
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

    private static final String RETURN_TIMESTAMP_FIELD = "Your-" + TIMESTAMP_FIELD;
    private static final String RETURN_NONCE_FIELD = "Your-" + NONCE_FIELD;

    private static final String PICKED_HEAD = "PICKED";

    private static final String PICKED_TAIL = "END " + PICKED_HEAD;

    private static final String EXCHANGE_FIELD = "Exchange";

    private static final String SIGNATURE_FIELD = "Signature";

    private static final String DELAYED_SIGNATURE_FIELD = "Delayed-" + SIGNATURE_FIELD;

    private static final String ERROR = "ERROR";
    public static final String PIGGYBACK = "Piggyback";

    public static final String CHAIN_BEGIN = "-----BEGIN CERTIFICATE-----";
    public static final String CHAIN_END = "-----END CERTIFICATE-----";
    private final CiphersuiteList supported;

    private final Map<String, X509Certificate[]> myCertificates;
    private X509Certificate[] peerCertificate = null;

    private String myTimestamp = null, myNonce = null;

    private PrivateKey dhPrivate = null;
    private PublicKey dhPublic = null;

    private Ciphersuite sessionCS = null;
    private Ciphersuite handshakeCS = null;

    private byte[] dhSecret = null;

    private byte[] clientHello;

    private CryptoStuff generatedCrypto = null;

    private KeyStore keyStore;

    private String password;

    public static Handshake load(String supportedPath,
                                 String keystorePath, String password) throws CryptoException {
        CiphersuiteList supported;
        try {
            List<String> supportedLines = Files.readAllLines(Paths.get(supportedPath));
            supported = CiphersuiteList.parse(supportedLines);

            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream(keystorePath), password.toCharArray());
            Map<String, X509Certificate[]> certificates = new HashMap<>();
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if(keyStore.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)){
                    Certificate[] chain = keyStore.getCertificateChain(alias);
                    X509Certificate[] x509Chain = new X509Certificate[chain.length];
                    for (int i = 0; i < x509Chain.length; i++) {
                        x509Chain[i] = (X509Certificate) chain[i];
                    }
                    certificates.put(alias, x509Chain);
                }

            }

            return new Handshake(supported, certificates, keyStore, password);
        } catch (IOException | CertificateException |
                 KeyStoreException | NoSuchAlgorithmException e) {
            throw new CryptoException("Error initializing handshake", e);
        }
    }

    public Handshake(CiphersuiteList supported, Map<String, X509Certificate[]> certificates,
                     KeyStore keyStore, String password) {
        this.supported = supported;
        this.myCertificates = certificates;
        this.keyStore = keyStore;
        this.password = password;
    }

    public int listenForHandshake(byte[] buffer, SocketAddress inAddress)
            throws CryptoException, IntegrityException{
        boolean externalError = false;
        DatagramSocket outgoing = null;
        try {
            DatagramSocket incoming = new DatagramSocket(inAddress);

            DatagramPacket clientHelloPacket = new DatagramPacket(buffer, buffer.length);
            incoming.receive(clientHelloPacket);
            String error = isError(buffer, clientHelloPacket.getLength());
            if(error != null){
                externalError = true;
                throw new CryptoException(error);
            }
            byte[] serverHello = respondClientHello(buffer, clientHelloPacket.getLength());

            outgoing = new DatagramSocket(clientHelloPacket.getSocketAddress());
            DatagramPacket serverHelloPacket = new DatagramPacket(serverHello, serverHello.length);
            outgoing.send(serverHelloPacket);

            DatagramPacket clientConfirmationPacket = new DatagramPacket(buffer, buffer.length);
            incoming.receive(clientConfirmationPacket);
            error = isError(buffer, clientHelloPacket.getLength());
            if(error != null){
                externalError = true;
                throw new CryptoException(error);
            }
            int read = receiveClientConfirmation(buffer, clientConfirmationPacket.getLength(), buffer);

            incoming.close();
            outgoing.close();
            return read;
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (IntegrityException | CryptoException e){
            if(outgoing != null && !externalError){
                byte[] errorPacket = generateErrorPacket(e);
                DatagramPacket error = new DatagramPacket(errorPacket, errorPacket.length);
                try {
                    outgoing.send(error);
                } catch (IOException e2){
                    throw new RuntimeException(e2);
                }
            }
            throw e;
        }
    }

    public void sendHandshake(byte[] buffer, SocketAddress inAddress, SocketAddress outAddress,
                                     byte[] piggyback, int piggybackLength)
            throws CryptoException, IntegrityException{
        boolean externalError = false;
        DatagramSocket outgoing = null;
        try {
            DatagramSocket incoming = new DatagramSocket(inAddress);
            outgoing = new DatagramSocket(outAddress);

            byte[] clientHello = generateClientHello();
            DatagramPacket clientHelloPacket = new DatagramPacket(clientHello, clientHello.length);
            outgoing.send(clientHelloPacket);

            DatagramPacket serverHelloPacket = new DatagramPacket(buffer, buffer.length);
            incoming.receive(serverHelloPacket);
            String error = isError(buffer, serverHelloPacket.getLength());
            if(error != null){
                externalError = true;
                throw new CryptoException(error);
            }

            byte[] clientConfirmation = respondServerHello(buffer, serverHelloPacket.getLength(),
                    piggyback, piggybackLength);
            DatagramPacket clientConfirmationPacket = new DatagramPacket(clientConfirmation,
                    clientConfirmation.length);
            outgoing.send(clientConfirmationPacket);

            incoming.close();
            outgoing.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (IntegrityException | CryptoException e){
            if(!externalError){
                byte[] errorPacket = generateErrorPacket(e);
                DatagramPacket error = new DatagramPacket(errorPacket, errorPacket.length);
                try {
                    outgoing.send(error);
                } catch (IOException e2){
                    throw new RuntimeException(e2);
                }
            }
            throw e;
        }
    }

    private void produceCrypto() throws CryptoException {
        boolean isMac;
        try {
            Mac.getInstance(sessionCS.getIntegrityCheck());
            isMac = true;
        } catch (NoSuchAlgorithmException e) {
            isMac = false;
        }
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.setSeed(dhSecret);
        try{
            KeyGenerator keyGenerator = KeyGenerator.getInstance(sessionCS.getScheme());
            keyGenerator.init(secureRandom);
            String key = bytesToHex(keyGenerator.generateKey().getEncoded());
            String macKey = null;
            if(isMac){
                KeyGenerator macGenerator = KeyGenerator.getInstance(sessionCS.getIntegrityCheck());
                macGenerator.init(secureRandom);
                macKey = bytesToHex(macGenerator.generateKey().getEncoded());
            }
            String algorithm = sessionCS.getScheme().split("/")[0];
            byte[] ivBytes = new byte[Cipher.getInstance(sessionCS.getScheme()).getBlockSize()];
            secureRandom.nextBytes(ivBytes);
            generatedCrypto = new CryptoStuff(key, algorithm, sessionCS.getScheme(), bytesToHex(ivBytes),
                    null, macKey, sessionCS.getIntegrityCheck());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new CryptoException("Key generation failed", e);
        }
    }

    public CryptoStuff getGeneratedCrypto(){
        return generatedCrypto;
    }

    private String isError(byte[] packet, int length){
        Scanner scanner = new Scanner(new ByteArrayInputStream(packet, 0, length));
        if(!scanner.nextLine().equalsIgnoreCase(ERROR)){
            return null;
        } else{
            return scanner.nextLine();
        }
    }

    private byte[] generateErrorPacket(Exception exception){
        String builder = ERROR + "\n" +
                exception.getMessage();
        return builder.getBytes();
    }

    private void verifySignature(byte[] data, String signatureHex)
            throws CryptoException, IntegrityException {
        String signatureAlgorithm = handshakeCS.getScheme();
        try{
            Signature signature = Signature.getInstance(signatureAlgorithm);
            signature.initVerify(peerCertificate[0]);
            byte[] signatureBytes = hexToBytes(signatureHex);
            signature.update(data);
            if(!signature.verify(signatureBytes)){
                throw new IntegrityException("Invalid signature");
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new CryptoException("Signature verification failed", e);
        }
    }

    private String generateSignature(byte[] data, String algorithm) throws CryptoException{
        try {
            Signature signature = Signature.getInstance(algorithm);
            String pkAlg = algorithm.split("with")[1];
            signature.initSign((PrivateKey) keyStore.getKey(pkAlg, password.toCharArray()));
            signature.update(data);
            return bytesToHex(signature.sign());
        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException |
                 InvalidKeyException | SignatureException e) {
            throw new CryptoException("Failed to sign packet", e);
        }
    }

    private void sign(StringBuilder builder, String algorithm) throws CryptoException {
        String signature = generateSignature(builder.toString().getBytes(), algorithm);
        builder.append(SIGNATURE_FIELD).append(":")
                .append(signature).append("\n");
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

    private void appendField(StringBuilder builder, String name, String value){
        builder.append(name)
                .append(":").append(value).append("\n");
    }

    private String expectField(Scanner scanner, String name) throws CryptoException{
        String line = scanner.nextLine();
        String[] parts = line.split(":");
        if(!parts[0].trim().equalsIgnoreCase(name)){
            throw new CryptoException("Expected " + name);
        }
        return parts[1].trim();
    }

    private void appendMyChallenge(StringBuilder builder){
        SecureRandom random = new SecureRandom();
        byte[] nonce = new byte[NONCE_LENGTH];
        random.nextBytes(nonce);
        myNonce = CryptoStuff.bytesToHex(nonce).toLowerCase();
        myTimestamp = Long.toHexString(System.currentTimeMillis()).toLowerCase();
        appendField(builder, TIMESTAMP_FIELD, myTimestamp);
        appendField(builder, NONCE_FIELD, myNonce);
    }

    private void pickSuites(CiphersuiteList clientSupported) throws CryptoException {
        this.sessionCS = supported.findFirstSession(clientSupported);
        this.handshakeCS = supported.findFirstHandshake(clientSupported);
        if(this.sessionCS == null || this.handshakeCS == null){
            throw new CryptoException("Negotiation failed");
        }
    }

    private void readPeerCertificate(Scanner scanner) throws CryptoException, IntegrityException{
        StringBuilder cert = new StringBuilder();
        String alias = "";
        String line;
        do {
            String lineStart = scanner.next();
            if (!lineStart.trim().equalsIgnoreCase(CERTIFICATE_HEADER)) {
                throw new CryptoException("Expected certificate");
            }
            alias = scanner.next();
            scanner.nextLine();
            line = scanner.nextLine();
            while (!line.trim().equalsIgnoreCase(CERTIFICATE_TAIL)) {
                line = scanner.nextLine();
            }
        } while (!alias.equalsIgnoreCase(handshakeCS.getScheme().split("with")[0]));

        line = scanner.nextLine();
        while(!line.trim().equalsIgnoreCase(CERTIFICATE_TAIL)){
            cert.append(line).append("\n");
            line = scanner.nextLine();
        }
        while (scanner.hasNext(CERTIFICATE_HEADER)){
            scanner.nextLine();
            line = scanner.nextLine();
            while(!line.trim().equalsIgnoreCase(CERTIFICATE_TAIL)){
                line = scanner.nextLine();
            }
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            byte[] b = cert.toString().getBytes();
            InputStream stream = new ByteArrayInputStream(b);
            Collection<?> collection = cf.generateCertificates(stream);
            X509Certificate[] chain = new X509Certificate[collection.size()];
            Iterator<?> iterator = collection.iterator();
            for (int i = 0; i < chain.length; i++) {
                chain[i] = (X509Certificate)iterator.next();
            }
            this.peerCertificate = chain;
            checkCertificate();
        } catch (CertificateExpiredException | CertificateNotYetValidException e){
            throw new IntegrityException("Untrusted certificate", e);
        } catch (CertificateException e) {
            throw new CryptoException("Invalid certificate", e);
        }
    }

    private void checkCertificate() throws  IntegrityException{
        try {
            for (X509Certificate cert : peerCertificate) {
                cert.checkValidity();
            }
            TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init(keyStore);
            for (TrustManager manager : factory.getTrustManagers()){
                if(manager instanceof X509TrustManager){
                    ((X509TrustManager) manager).checkServerTrusted(this.peerCertificate, "RSA");
                }
            }
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new IntegrityException("Untrusted certificate", e);
        }
    }

    private void appendCertificates(StringBuilder builder, X509Certificate[] certificates) throws CryptoException{
        try {
            Base64.Encoder encoder = Base64.getEncoder();
            for(X509Certificate certificate : certificates){
                String encoded = encoder.encodeToString(certificate.getEncoded());
                builder.append(CHAIN_BEGIN).append("\n");
                builder.append(encoded).append("\n");
                builder.append(CHAIN_END).append("\n");
            }
        } catch (CertificateException e) {
            throw new CryptoException("Failed to append certificate", e);
        }
    }

    public byte[] generateClientHello() throws CryptoException {
        StringBuilder builder = new StringBuilder();
        builder.append(CLIENT_HELLO).append("\n");
        builder.append(NEGOTIATION_HEADER).append("\n");
        builder.append(supported.stringBuilder());
        builder.append(NEGOTIATION_TAIL).append("\n");
        appendMyChallenge(builder);

        generateDH();
        appendField(builder, EXCHANGE_FIELD, CryptoStuff.bytesToHex(dhPublic.getEncoded()));

        for (Map.Entry<String, X509Certificate[]> entry : myCertificates.entrySet()){
            builder.append(CERTIFICATE_HEADER).append(" ").append(entry.getKey()).append("\n");
            appendCertificates(builder, entry.getValue());
            builder.append(CERTIFICATE_TAIL).append("\n");
        }

        this.clientHello = builder.toString().getBytes();
        return this.clientHello;
    }

    public byte[] respondClientHello(byte[] clientHello) throws CryptoException, IntegrityException {
        return respondClientHello(clientHello, clientHello.length);
    }

    public byte[] respondClientHello(byte[] clientHello, int length) throws CryptoException, IntegrityException{
        this.clientHello = clientHello;
        Scanner scanner = new Scanner(new ByteArrayInputStream(clientHello, 0, length));
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

        String clientTimestamp = expectField(scanner, TIMESTAMP_FIELD);
        String clientNonce = expectField(scanner, NONCE_FIELD);

        generateDH();
        pickSuites(clientSupported);
        finishDH(expectField(scanner, EXCHANGE_FIELD));
        readPeerCertificate(scanner);

        return generateServerHello(clientTimestamp, clientNonce);
    }

    private byte[] generateServerHello(String clientTimestamp, String clientNonce) throws CryptoException {
        StringBuilder builder = new StringBuilder();
        builder.append(SERVER_HELLO).append("\n");
        CiphersuiteList picked = new CiphersuiteList();
        picked.addSession(sessionCS);
        picked.addHandshake(handshakeCS);
        builder.append(PICKED_HEAD).append("\n");
        builder.append(picked.stringBuilder());
        builder.append(PICKED_TAIL).append("\n");

        appendMyChallenge(builder);

        appendField(builder, RETURN_TIMESTAMP_FIELD, clientTimestamp);
        appendField(builder, RETURN_NONCE_FIELD, clientNonce);

        appendField(builder, EXCHANGE_FIELD, CryptoStuff.bytesToHex(dhPublic.getEncoded()));


        builder.append(CERTIFICATE_HEADER).append(" ").append(handshakeCS.getScheme()).append("\n");
        appendCertificates(builder, myCertificates.get(handshakeCS.getScheme()));
        builder.append(CERTIFICATE_TAIL).append("\n");

        sign(builder, handshakeCS.getScheme());
        return builder.toString().getBytes();
    }

    public byte[] respondServerHello(byte[] serverHello, byte[] piggyback, int piggybackLength) throws CryptoException, IntegrityException{
        return respondServerHello(serverHello, serverHello.length, piggyback, piggybackLength);
    }

    public byte[] respondServerHello(byte[] serverHello, int length, byte[] piggyback, int piggybackLength) throws CryptoException, IntegrityException{
        Scanner scanner = new Scanner(new ByteArrayInputStream(serverHello, 0, length));

        if(!scanner.nextLine().trim().equalsIgnoreCase(SERVER_HELLO)){
            throw new CryptoException("Not a client hello");
        }
        if(!scanner.nextLine().trim().equalsIgnoreCase(PICKED_HEAD)){
            throw new CryptoException("Expected picked ciphers");
        }
        List<String> lines = new ArrayList<>();
        String line = scanner.nextLine();
        while (!line.trim().equalsIgnoreCase(PICKED_TAIL)){
            lines.add(line);
            line = scanner.nextLine();
        }
        CiphersuiteList picked = CiphersuiteList.parse(lines);
        this.sessionCS = picked.getSession(0);
        this.handshakeCS = picked.getHandshake(0);

        String serverTimestamp = expectField(scanner, TIMESTAMP_FIELD);
        String serverNonce = expectField(scanner, NONCE_FIELD);

        checkChallenge(scanner);
        finishDH(expectField(scanner, EXCHANGE_FIELD));
        readPeerCertificate(scanner);

        String signature = expectField(scanner, SIGNATURE_FIELD);
        verifySignature(readUpToSignature(serverHello), signature);

        return generateClientConfirmation(serverTimestamp, serverNonce, piggyback, piggybackLength);
    }

    private void checkChallenge(Scanner scanner) throws CryptoException {
        String checkingTimestamp = expectField(scanner, RETURN_TIMESTAMP_FIELD);
        if(!checkingTimestamp.equalsIgnoreCase(myTimestamp)){
            throw new CryptoException("Invalid returning timestamp: was expecting" + myTimestamp +
                    "but got" + checkingTimestamp);
        }

        String checkingNonce = expectField(scanner, RETURN_NONCE_FIELD);
        if(!checkingNonce.equalsIgnoreCase(myNonce)){
            throw new CryptoException("Invalid returning timestamp: was expecting" + myNonce +
                    "but got" + checkingNonce);
        }
    }

    private byte[] readUpToSignature(byte[] packet){
        Scanner scanner = new Scanner(new ByteArrayInputStream(packet));
        String line = scanner.nextLine();
        StringBuilder toVerify = new StringBuilder();
        while (!line.startsWith(SIGNATURE_FIELD)){
            toVerify.append(line).append("\n");
            line = scanner.nextLine();
        }
        return toVerify.toString().getBytes();
    }

    private byte[] generateClientConfirmation(String serverTimestamp, String serverNonce, byte[] piggyback,
                                              int piggybackLength) throws CryptoException{
        StringBuilder builder = new StringBuilder();
        produceCrypto();

        String delayedSignature = generateSignature(clientHello, handshakeCS.getScheme());
        appendField(builder, DELAYED_SIGNATURE_FIELD, delayedSignature);

        appendField(builder, RETURN_TIMESTAMP_FIELD, serverTimestamp);
        appendField(builder, RETURN_NONCE_FIELD, serverNonce);
        generatedCrypto.startEncryption();
        try {
            piggybackLength = generatedCrypto.handlePacket(piggyback, piggybackLength);
        } catch (IntegrityException e){
            throw new CryptoException("Unexpected integrity failure while encrypting");
        }
        appendField(builder, PIGGYBACK, bytesToHex(piggyback, 0, piggybackLength));
        sign(builder, handshakeCS.getScheme());
        return builder.toString().getBytes();
    }

    public void receiveClientConfirmation(byte[] clientConfirmation, byte[] buffer) throws CryptoException, IntegrityException{
        receiveClientConfirmation(clientConfirmation, clientConfirmation.length, buffer);
    }

    public int receiveClientConfirmation(byte[] clientConfirmation, int length, byte[] buffer) throws CryptoException, IntegrityException{
        Scanner scanner = new Scanner(new ByteArrayInputStream(clientConfirmation, 0, length));
        String delayedSignature = expectField(scanner, DELAYED_SIGNATURE_FIELD);
        verifySignature(clientHello, delayedSignature);
        checkChallenge(scanner);
        String piggyback = expectField(scanner, PIGGYBACK);
        String signature = expectField(scanner, SIGNATURE_FIELD);
        verifySignature(readUpToSignature(clientConfirmation), signature);
        produceCrypto();

        generatedCrypto.startDecryption();
        byte[] piggybackedBytes = hexToBytes(piggyback);
        System.arraycopy(piggybackedBytes, 0, buffer, 0, piggybackedBytes.length);
        return generatedCrypto.handlePacket(buffer, piggybackedBytes.length);
    }
}

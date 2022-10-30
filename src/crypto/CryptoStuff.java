package crypto;
/**
 * * A utility class that encrypts or decrypts a file.
 * * Version 2
 **/


// This is version 2 of CryptoStuff class (ex 3, Lab 1)
// In this version we separate the definition of ALGORITHM
// and the definition of CIPHERSUITE parameterization to be
// more clear and correct the utilization and generalization of
// use ...

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Arrays;
import java.util.List;
import java.security.MessageDigest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CryptoStuff {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    private final String key;
    private final String algorithm;
    private final String ciphersuite;
    private final String iv;
    private final String integrity;
    private final String mackey;

    private final String integrityCheck;

    private Cipher cipher;
    private int cipherMode = -1;
    private MessageDigest digest;
    private Mac mac;

    private boolean firstUpdate = true;

    private byte[] leftoverBytes = new byte[0];

    //For use in your TP1 implementation you must have the crytoconfigs
    //according to the StreamingServer crypto configs
    //because thsi is just an illustrative example with specific
    // defifined configurations.... Reember that for TP1 you
    // must have your own tool to encrypt the movie files that can
    // be used by your StreamingServer implementation

    // See this according to the configuration of StreamingServer
    // Initializaton vector ... See this according to the cryptoconfig
    // of Streaming Server

    public CryptoStuff(String key, String algorithm, String ciphersuite, String iv,
                       String integrity, String mackey, String integrityCheck) {
        this.key = key;
        this.algorithm = algorithm;
        this.ciphersuite = ciphersuite;
        this.iv = iv;
        this.integrity = integrity;
        this.mackey = mackey;
        this.integrityCheck = integrityCheck;
    }

    public static CryptoStuff loadFromFile(String path, String entry) throws IOException {
        List<String> lines = Files.readAllLines(Paths.get(path));
        String blockHeader = String.format("<%s>", entry);
        String blockFooter = String.format("</%s>", entry);
        String ciphersuite = null, key = null, iv = null, integrity = null, mackey = null, integrityCheck = null;
        int i = 0;
        // skip until start of block
        while (!lines.get(i).trim().equals(blockHeader)) i++;
        i++;
        while (!lines.get(i).trim().equals(blockFooter)) {
            if (lines.get(i).isBlank())
                continue;
            String[] parts = lines.get(i).split(":");
            parts[0] = parts[0].trim().toLowerCase();
            parts[1] = parts[1].trim();
            switch (parts[0]) {
                case "ciphersuite" -> {
                    if (ciphersuite != null)
                        throw new RuntimeException("Invalid configuration: Repeated property " + parts[0]);
                    ciphersuite = parts[1];
                }
                case "key" -> {
                    if (key != null)
                        throw new RuntimeException("Invalid configuration: Repeated property " + parts[0]);
                    key = parts[1];
                }
                case "iv" -> {
                    if (iv != null)
                        throw new RuntimeException("Invalid configuration: Repeated property " + parts[0]);
                    iv = parts[1];
                }
                case "integrity" -> {
                    if (integrity != null)
                        throw new RuntimeException("Invalid configuration: Repeated property " + parts[0]);
                    integrity = parts[1];
                }
                case "integrity-check" -> {
                    if (integrityCheck != null)
                        throw new RuntimeException("Invalid configuration: Repeated property " + parts[0]);
                    integrityCheck = parts[1];
                }
                case "mackey" -> {
                    if (mackey != null)
                        throw new RuntimeException("Invalid configuration: Repeated property " + parts[0]);
                    mackey = parts[1];
                }
                default -> {
                    throw new RuntimeException("Invalid configuration: Unknown property " + parts[0]);
                }
            }
            i++;
        }
        if (ciphersuite == null || key == null || iv == null || integrity == null || mackey == null) {
            throw new RuntimeException("Invalid configuration: Missing properties");
        }
        if (integrity.equalsIgnoreCase("null"))
            integrity = null;
        if (mackey.equalsIgnoreCase("null"))
            mackey = null;
        if(mackey != null && integrityCheck == null)
            throw new RuntimeException("Mac Key provided but no integrity method specified.");
        if (integrityCheck != null && integrityCheck.equalsIgnoreCase("null"))
            integrityCheck = null;
        String algorithm = ciphersuite.split("/")[0];
        return new CryptoStuff(key, algorithm, ciphersuite, iv, integrity, mackey, integrityCheck);
    }


    public String getKey() {
        return key;
    }

    public String getCiphersuite() {
        return ciphersuite;
    }

    private static byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2 + hex.length() % 2];
        for (int i = 0; i < hex.length() / 2; i++) {
            char c0 = hex.charAt(i * 2);
            int v0 = Character.digit(c0, 16);
            char c1 = hex.charAt(i * 2 + 1);
            int v1 = Character.digit(c1, 16);
            bytes[i] = (byte) (v1 + v0 * 16);
        }
        if (hex.length() % 2 != 0) {
            bytes[bytes.length - 1] = (byte) Character.digit(hex.charAt(hex.length() - 1), 16);
        }
        return bytes;
    }

    public static String bytesToHex(byte[] bytes){
        return bytesToHex(bytes, 0, bytes.length);
    }

    public static String bytesToHex(byte[] bytes, int offset, int length){
        StringBuilder builder = new StringBuilder(length*2);
        for (int i = offset; i < offset + length; i++) {
            builder.append(String.format("%02x", bytes[i]));
        }
        return builder.toString();
    }

    public void printProperties() {
        // TODO remove this
        System.out.println("key = " + this.key);
        System.out.println("algorithm = " + this.algorithm);
        System.out.println("ciphersuite = " + this.ciphersuite);
        System.out.println("iv = " + this.iv);
        System.out.println("integrity = " + this.integrity);
        if(integrityCheck!=null)
            System.out.println("integrity-check = " + this.integrityCheck);
        System.out.println("mackey = " + this.mackey);
    }

    public void startEncryption() throws CryptoException {
        initCipher(Cipher.ENCRYPT_MODE);
    }

    public void startDecryption() throws CryptoException {
        initCipher(Cipher.DECRYPT_MODE);
    }

    public int update(byte[] data, int length) throws CryptoException, IntegrityException {
        if(cipherMode == Cipher.DECRYPT_MODE) {
            return decryptionUpdate(data, length);
        } else {
            return encryptionUpdate(data, length);
        }
    }

    private int decryptionUpdate(byte[] data, int length) throws CryptoException, IntegrityException{
        int packetLength = length - integrityLength();
        byte[] code = Arrays.copyOfRange(data, packetLength, length);
        try {
            updateHmac(data, packetLength);
            int postLength = cipher.update(data, 0, packetLength, data);
            updateHash(data, postLength);
            checkIntegrity(code);
            return postLength;
        } catch (ShortBufferException ex){
            throw new CryptoException("Error encrypting/decrypting data", ex);
        }
    }

    private int encryptionUpdate(byte[] data, int length) throws CryptoException{
        int packetSize = ((length+leftoverBytes.length) / cipher.getBlockSize()) * cipher.getBlockSize();
        int consumedNow = packetSize - leftoverBytes.length;
        byte[] newLeftoverBytes = Arrays.copyOfRange(data, consumedNow, length);

        // shift the bytes to fit the leftover
        shiftBytes(data, 0, length, leftoverBytes.length);
        copyTo(this.leftoverBytes, 0, data, 0, this.leftoverBytes.length);
        this.leftoverBytes = newLeftoverBytes;
        System.out.println(bytesToHex(leftoverBytes));
        try {
            updateHash(data, packetSize);
            int postLength = cipher.update(data, 0, packetSize, data);
            updateHmac(data, postLength);
            postLength += putIntegrityCode(data, postLength);
            return postLength;
        } catch (ShortBufferException ex){
            throw new CryptoException("Error encrypting/decrypting data", ex);
        }
    }

    private void clearCipher(){
        this.cipher = null;
        this.cipherMode = -1;
        this.digest = null;
        this.leftoverBytes = new byte[0];
    }

    public byte[] endCrypto() throws CryptoException {
        try {
            Cipher tmp = this.cipher;
            clearCipher();
            return tmp.doFinal();
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            throw new CryptoException("Error encrypting/decrypting data", ex);
        }
    }

    public byte[] decryptFile(String filepath) throws CryptoException, IntegrityException {
        initCipher(Cipher.DECRYPT_MODE);
        byte[] data = doFile(new File(filepath));
        updateHash(data, data.length);
        updateHmac(data, data.length);
        checkIntegrity(hexToBytes(integrityCheck));
        clearCipher();
        return data;
    }

    public void encryptFile(String filepath, String outpath) throws CryptoException{
        File inFile = new File(filepath);
        File outFile = new File(outpath);
        try {
            initCipher(Cipher.ENCRYPT_MODE);
            byte[] outputBytes = doFile(inFile);
            FileOutputStream outputStream = new FileOutputStream(outFile);
            outputStream.write(outputBytes);
            outputStream.close();
            clearCipher();

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void initCipher(int cipherMode) throws CryptoException {
        try{
            IvParameterSpec ivSpec = new IvParameterSpec(hexToBytes(iv));
            Key secretKey = new SecretKeySpec(hexToBytes(key), algorithm);
            this.cipher = Cipher.getInstance(this.ciphersuite);
            this.cipher.init(cipherMode, secretKey, ivSpec);
            this.cipherMode = cipherMode;
            if(this.mackey != null){
                this.mac = Mac.getInstance(this.integrity);
                Key macSpec = new SecretKeySpec(hexToBytes(this.mackey), this.integrity);
                this.mac.init(macSpec);
            }
            else if (this.integrity != null) {
                this.digest = MessageDigest.getInstance(this.integrity);
            }
        } catch (NoSuchPaddingException | NoSuchAlgorithmException
                     | InvalidKeyException
                     | InvalidAlgorithmParameterException ex) {
            throw new CryptoException("Error encrypting/decrypting data", ex);
        }
    }

    private void updateHash(byte[] buffer, int dataLength){
        if(digest != null){
            digest.update(buffer, 0, dataLength);
        }
    }

    private void updateHmac(byte[] buffer, int dataLength){
        if(mac != null){
            mac.update(buffer, 0, dataLength);
        }
    }

    private int putIntegrityCode(byte[] buffer, int offset) throws CryptoException{
        try {
            int length = 0;
            if (mac != null) {
                mac.doFinal(buffer, offset);
                length = mac.getMacLength();
                System.out.println("HMAC = " + bytesToHex(buffer, offset, length));
            } else if (digest != null) {
                length = digest.digest(buffer, offset, digest.getDigestLength());
                System.out.println("HASH = " + bytesToHex(buffer, offset, length));
            }
            return length;
        }
        catch (ShortBufferException | DigestException e){
            throw new CryptoException("Error encrypting/decrypting data", e);
        }
    }

    /**
     * Size of the integrity code at the end of an incoming packet
     * Always 0 in EncryptMode
     * @return the size
     */
    private int integrityLength(){
        if(mac!=null){
            return mac.getMacLength();
        } else if (digest != null) {
            return digest.getDigestLength();
        }
        return 0;
    }

    private void checkIntegrity(byte[] code) throws IntegrityException{
        byte[] resultIntegrity = null;
        if(mac!=null){
            resultIntegrity = mac.doFinal();
            mac.reset();
        } else if (digest != null) {
            resultIntegrity = digest.digest();
            digest.reset();
        }
        if(resultIntegrity == null)
            return;
        if(code.length != resultIntegrity.length){
            throw new IntegrityException("Different Sizes: Correct = " + bytesToHex(code) +
                    "; Computed = " + bytesToHex(resultIntegrity));
        }
        for (int i = 0; i < code.length; i++) {
            if(code[i] != resultIntegrity[i]) {
                throw new IntegrityException("Different Bytes: Correct = " + bytesToHex(code) +
                        "; Computed = " + bytesToHex(resultIntegrity));
            }
        }
    }

    private byte[] doFile(File inputFile) throws CryptoException
    {
        try {
            FileInputStream inputStream = new FileInputStream(inputFile);
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);
            byte[] outputBytes = cipher.doFinal(inputBytes);

            inputStream.close();

            return outputBytes;
        }
        catch (BadPaddingException
               | IllegalBlockSizeException ex)
        {
            throw new CryptoException("Error encrypting/decrypting file", ex);
        } catch (IOException ex){
            throw new RuntimeException(ex);
        }
    }

    private static void copyTo(byte[] from, int fromOffset, byte[] to, int toOffset, int length){
        for (int i = 0; i < length; i++) {
            to[i + toOffset] = from[i + fromOffset];
        }
    }

    private static void shiftBytes(byte[] data, int offset, int length, int shift){
        for (int i = length - 1; i >= offset; i--) {
            int newI = i + shift;
            data[newI] = data[i];
        }
    }
}

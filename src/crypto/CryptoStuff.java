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
import java.util.List;
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
            bytes[i] = (byte) (v1 + v0 << 4);
        }
        if (hex.length() % 2 != 0) {
            bytes[bytes.length - 1] = (byte) Character.digit(hex.charAt(hex.length() - 1), 16);
        }
        return bytes;
    }

    public void printProperties() {
        // TODO remove this
        System.out.println("key = " + this.key);
        System.out.println("algorithm = " + this.algorithm);
        System.out.println("ciphersuite = " + this.ciphersuite);
        System.out.println("iv = " + this.iv);
        System.out.println("integrity = " + this.integrity);
        System.out.println("mackey = " + this.mackey);
    }

    public void startEncryption() throws CryptoException {
        initCipher(Cipher.ENCRYPT_MODE);
    }

    public void startDecryption() throws CryptoException {
        initCipher(Cipher.DECRYPT_MODE);
    }


    public int update(byte[] data) throws CryptoException {return update(data, data.length);}

    public int update(byte[] data, int length) throws CryptoException {
        try {
            int len = cipher.update(data, 0, length, data);
            return len;
        } catch (ShortBufferException ex){
            throw new CryptoException("Error encrypting/decrypting data", ex);
        }
    }

    public byte[] endCrypto() throws CryptoException {
        try {
            Cipher tmp = this.cipher; //
            this.cipher = null; //
            return tmp.doFinal();
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            throw new CryptoException("Error encrypting/decrypting file", ex);
        }
    }

    public byte[] decryptFile(String filepath) throws CryptoException {
        //TODO check integrity
        return doFile(Cipher.DECRYPT_MODE, new File(filepath));
    }

    public void encryptFile(String filepath, String outpath) throws CryptoException{
        File inFile = new File(filepath);
        File outFile = new File(outpath);
        try {
            byte[] outputBytes = doFile(Cipher.ENCRYPT_MODE, inFile);
            FileOutputStream outputStream = new FileOutputStream(outFile);
            outputStream.write(outputBytes);
            outputStream.close();
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
        } catch (NoSuchPaddingException | NoSuchAlgorithmException
                     | InvalidKeyException
                     | InvalidAlgorithmParameterException ex) {
            throw new CryptoException("Error encrypting/decrypting data", ex);
        }
    }

    private byte[] doFile(int cipherMode, File inputFile) throws CryptoException
    {
        try {
            initCipher(cipherMode);
            FileInputStream inputStream = new FileInputStream(inputFile);
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);
            byte[] outputBytes = cipher.doFinal(inputBytes);

            inputStream.close();
            this.cipher = null;

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
}

package crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.List;

public class Handshake {
    //Used to wrap secrets on payloads
    private String keyAlgorithm = "RSA";
    private String privateKey;
    private String publicKey;

    //Used to verify authenticity of handshake
    private String signatureAlgorithm = "SHA256withRSA";
    private String signKey;
    private String verifyKey;

    private static String unwrap(Cipher cipher, Key wrappingKey, String wrappedKey)
            throws BadPaddingException, IllegalBlockSizeException {
        byte[] key = cipher.doFinal(CryptoStuff.hexToBytes(wrappedKey));
        return CryptoStuff.bytesToHex(key);
    }

    private void verifySignature(List<String> lines, String signatureHex)
            throws CryptoException, IntegrityException {
        try{
            Signature signature = Signature.getInstance(signatureAlgorithm);
            KeyFactory keyFactory = KeyFactory.getInstance(signatureAlgorithm);
            EncodedKeySpec verifyKeySpec = new X509EncodedKeySpec(CryptoStuff.hexToBytes(verifyKey));
            PublicKey verifyKey = keyFactory.generatePublic(verifyKeySpec);
            signature.initVerify(verifyKey);
            byte[] signatureBytes = CryptoStuff.hexToBytes(signatureHex);
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

    private void unwrapKeys(CryptoStuff crypto) throws CryptoException {
        try{
            KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
            Cipher cipher = Cipher.getInstance(keyAlgorithm);
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(CryptoStuff.hexToBytes(publicKey));
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            crypto.setKey(unwrap(cipher, publicKey, crypto.getKey()));
            if (crypto.getMackey() != null) {
                crypto.setMackey(unwrap(cipher, publicKey, crypto.getMackey()));
            }
        } catch (NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException |
                 InvalidKeySpecException | BadPaddingException | InvalidKeyException e) {
            throw new CryptoException("Handshake failed", e);
        }
    }

    public CryptoStuff receiveHandshake(byte[] payload) throws CryptoException, IntegrityException {
            List<String> lines = Arrays.asList(new String(payload).split("\n"));
            String signature = lines.get(lines.size() - 1);
            lines.remove(lines.size() - 1);
            verifySignature(lines, signature);
            CryptoStuff crypto = CryptoStuff.parseConfig(lines);
            unwrapKeys(crypto);
            return crypto;
    }

}

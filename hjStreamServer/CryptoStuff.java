/**
 ** A utility class that encrypts or decrypts a file.
 ** Version 2
**/


// This is version 2 of CryptoStuff class (ex 3, Lab 1)
// In this version we separate the definition of ALGORITHM
// and the definition of CIPHERSUITE parameterization to be
// more clear and correct the utilization and generalization of
// use ...

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import java.security.Key;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;


public class CryptoStuff
{

    //For use in your TP1 implementation you must have the crytoconfigs
    //according to the StreamingServer crypto configs
    //because thsi is just an illustrative example with specific
    // defifined configurations.... Reember that for TP1 you
    // must have your own tool to encrypt the movie files that can
    // be used by your StreamingServer implementation
	 
     //private static final String ALGORITHM = "AES";
     //private static final String TRANSFORMATION = "AES/CTR/PKCS5Padding";
     // See this according to the configuration of StreamingServer
     // Initializaton vector ... See this according to the cryptoconfig
     // of Streaming Server
     private static final byte[] ivBytes  = new byte[]
     {
	0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 ,
        0x0f, 0x0d, 0x0e, 0x0c, 0x0b, 0x0a, 0x09, 0x08 
     };

    
    public byte[] encrypt(byte[] input)
                 throws CryptoException 
     {
        return doCrypto(Cipher.ENCRYPT_MODE, key, algorithm, transformation, iv, input);
     }

    public byte[] decrypt(byte[] input)
            throws CryptoException
    {
        return doCrypto(Cipher.DECRYPT_MODE, key, algorithm, transformation, iv, input);
    }

    private static byte[] hexToBytes(String hex){
         byte[] bytes = new byte[hex.length() / 2 + hex.length() % 2];
         //TODO odd numbers??
        for (int i = 0; i < hex.length(); i+=2) {
            char c0 = hex.charAt(i);
            int v0 = Character.digit(c0, 16);
            char c1 = hex.charAt(i+1);
            int v1 = (byte)Character.digit(c1, 16);
            bytes[i/2] = (byte) (v1 + v0 << 4);
        }
        return bytes;
    }

     private static byte[] doCrypto(int cipherMode, String algorithm, String transformation, String key, String iv, byte[] input) throws CryptoException
     {
        try 
          {
                  IvParameterSpec ivSpec = new IvParameterSpec(hexToBytes(iv));
                  Key secretKey = new SecretKeySpec(hexToBytes(key), algorithm);
                  Cipher cipher = Cipher.getInstance(transformation);
                  cipher.init(cipherMode, secretKey, ivSpec);
                  return cipher.doFinal(input);
          }
          catch (NoSuchPaddingException | NoSuchAlgorithmException
                  | InvalidKeyException | BadPaddingException
                  | IllegalBlockSizeException
                      | InvalidAlgorithmParameterException ex)
          {
            throw new CryptoException("Error encrypting/decrypting file", ex);
          }
     }
}

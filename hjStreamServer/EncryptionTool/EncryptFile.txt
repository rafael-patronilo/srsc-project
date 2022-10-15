import java.io.File;
 
/*
 *  Main class for encryption/decryption
 *  using CryptoStuff Class
 */
public class EncryptFile
{
   
   public static void main(String[] args)
   {
      if (args.length != 3)
	{
	System.out.println("Ex., If you want to use AES");	    
	System.out.println("Use: EncryptFile <AES key> <file> <encryptd-file>");
        System.exit(-1);
        }
   
        String key = args[0]; // For AES you need a key w/ 128, 192 or
	// 256 bits ...  Here we use the key passed as argument (as example)
	// However, for TP1 you must modify this according to the expected
	// crypto configurations
	// that wil be used by the Streaming Server to decrypt the
	// movies when these movies will be streamed
 
        File inputFile = new File(args[1]);
        File encryptedFile = new File(args[2]);

        try 
	  {
             CryptoStuff.encrypt(key, inputFile, encryptedFile);
	  }
          catch (CryptoException ex) 
	  {
	     
             System.out.println(ex.getMessage());
             ex.printStackTrace();
	  }
	
   }
   
}

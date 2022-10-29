package crypto;

public class EncryptFile {
    public static void main(String[] params) throws Exception{
        if (params.length < 3){
            System.out.println("Encrypts a file in place");
            System.out.println("Usage: EncryptFile filename cryptoconfig cryptoentry");
            System.exit(-1);
        }
        CryptoStuff crypto = CryptoStuff.loadFromFile(params[1], params[2]);
        crypto.encryptFile(params[0], params[0] + ".encrypted");
    }
}

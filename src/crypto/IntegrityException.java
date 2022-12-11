package crypto;

public class IntegrityException extends Exception {
    public IntegrityException(){

    }

    public IntegrityException(String message){
        super(message);
    }
    public IntegrityException(String message, Exception e){
        super(message, e);
    }
}

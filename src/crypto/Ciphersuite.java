package crypto;

import java.util.List;
import java.util.Objects;

public class Ciphersuite {
    private final String scheme;
    private final String integrityCheck;

    public Ciphersuite(String algorithm, String scheme, String integrityCheck) {
        this.scheme = scheme;
        this.integrityCheck = integrityCheck;
    }

    public String getScheme() {
        return scheme;
    }

    public String getIntegrityCheck() {
        return integrityCheck;
    }

    static Ciphersuite parseConfig(List<String> lines, int start) throws CryptoException{
        String scheme = null, integrityCheck = null;

        for (int i = start; i < start + 2; i++){
            if(i >= lines.size() || lines.get(i).isBlank())
                break;
            String line = lines.get(i);
            //System.out.println(line);
            String[] parts = line.split(":");
            parts[0] = parts[0].trim().toLowerCase();
            parts[1] = parts[1].trim();
            switch (parts[0]) {
                case "scheme" -> {
                    if (scheme != null)
                        throw new CryptoException("Invalid configuration: Repeated property " + parts[0]);
                    scheme = parts[1];
                }
                case "integrity-check" -> {
                    if (integrityCheck != null)
                        throw new CryptoException("Invalid configuration: Repeated property " + parts[0]);
                    integrityCheck = parts[1];
                }
                default -> throw new CryptoException("Invalid configuration: Unknown property " + parts[0]);

            }
        }
        if (scheme == null) {
            throw new CryptoException("Invalid configuration: Missing properties");
        }
        if (integrityCheck != null && integrityCheck.equalsIgnoreCase("null"))
            integrityCheck = null;
        String algorithm = scheme.split("/")[0];
        return new Ciphersuite(algorithm, scheme, integrityCheck);
    }

    @Override
    public String toString(){
        return String.format("scheme:%s\nintegrity-check:%s\n",
                scheme, integrityCheck == null ? "NULL" : integrityCheck);
    }

    @Override
    public boolean equals(Object other){
        if(other instanceof Ciphersuite otherS){
            return Objects.equals(otherS.integrityCheck, this.integrityCheck) &&
                    Objects.equals(otherS.scheme, this.scheme);
        } else return false;
    }

    @Override
    public int hashCode(){
        return Objects.hash(this.integrityCheck, this.scheme);
    }
}

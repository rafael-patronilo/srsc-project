package crypto;

import java.util.ArrayList;
import java.util.List;

public class CiphersuiteList {
    public static final String HANDSHAKE_HEADER = "HANDSHAKE";
    public static final String SESSION_HEADER = "SESSION";
    private List<Ciphersuite> handshake = new ArrayList<>();
    private List<Ciphersuite> session = new ArrayList<>();

    private static int skipBlankLines(List<String> lines, int i){
        int x = 0;
        while (i < lines.size() && lines.get(i + x).isBlank()) x++;
        return x;
    }

    private static int skipNonBlankLines(List<String> lines, int i){
        int x = 0;
        while (i < lines.size() && !lines.get(i + x).isBlank()) x++;
        return x;
    }

    public static CiphersuiteList parse(List<String> lines) throws CryptoException {
        CiphersuiteList list = new CiphersuiteList();
        int i = 0;
        i += skipBlankLines(lines, i);
        if(i >= lines.size() || !lines.get(i).trim().equals(HANDSHAKE_HEADER)){
            throw new CryptoException("Invalid Ciphersuite list: Couldn't find Handshake header");
        }
        i++;
        i += skipBlankLines(lines, i);
        while (i < lines.size() && !lines.get(i).trim().equals(SESSION_HEADER)) {
            list.handshake.add(Ciphersuite.parseConfig(lines, i));
            i += skipNonBlankLines(lines, i);
            i += skipBlankLines(lines, i);
        }
        if(i >= lines.size()){
            throw new CryptoException("Invalid Ciphersuite list: Couldn't find Session header");
        }
        while (i < lines.size()) {
            list.session.add(Ciphersuite.parseConfig(lines, i));
            i += skipNonBlankLines(lines, i);
            i += skipBlankLines(lines, i);
        }
        return list;
    }

    @Override
    public String toString(){
        StringBuilder builder = new StringBuilder();
        builder.append(HANDSHAKE_HEADER);
        for (Ciphersuite suite : handshake){
            builder.append(suite.toString());
        }
        builder.append(SESSION_HEADER);
        for (Ciphersuite suite : session){
            builder.append(suite.toString());
        }
        return builder.toString();
    }
}

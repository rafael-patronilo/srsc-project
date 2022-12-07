package crypto;

import java.util.ArrayList;
import java.util.List;

public class CiphersuiteList {
    public static final String HANDSHAKE_HEADER = "HANDSHAKE";
    public static final String SESSION_HEADER = "SESSION";
    private List<Ciphersuite> handshake = new ArrayList<>();
    private List<Ciphersuite> session = new ArrayList<>();

    public void addSession(Ciphersuite suite){
        session.add(suite);
    }

    public void addHandshake(Ciphersuite suite){
        handshake.add(suite);
    }

    private static int skipBlankLines(List<String> lines, int i){
        int x = 0;
        while (i + x < lines.size() && lines.get(i + x).isBlank()) x++;
        return x;
    }

    private static int skipNonBlankLines(List<String> lines, int i){
        int x = 0;
        while (i + x < lines.size() && !lines.get(i + x).isBlank()) x++;
        return x;
    }

    public Ciphersuite getSession(int index){
        return session.get(index);
    }

    public Ciphersuite getHandshake(int index){
        return handshake.get(index);
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
        i++;
        i += skipBlankLines(lines, i);
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

    public Ciphersuite findFirstSession(CiphersuiteList other){
        for (Ciphersuite suite : this.session){
            if(other.session.contains(suite)){
                return suite;
            }
        }
        return null;
    }

    public Ciphersuite findFirstHandshake(CiphersuiteList other){
        for (Ciphersuite suite : this.handshake){
            if(other.handshake.contains(suite)){
                return suite;
            }
        }
        return null;
    }

    @Override
    public String toString() {
        return this.stringBuilder().toString();
    }

    public StringBuilder stringBuilder(){
        StringBuilder builder = new StringBuilder();
        builder.append(HANDSHAKE_HEADER).append("\n");
        for (Ciphersuite suite : handshake) {
            builder.append(suite.toString()).append("\n");
        }
        builder.append(SESSION_HEADER).append("\n");
        for (Ciphersuite suite : session) {
            builder.append(suite.toString()).append("\n");
        }
        return builder;
    }
}

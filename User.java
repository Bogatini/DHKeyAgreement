import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class User {
    private String name;
    private KeyPairGenerator KpairGen;
    private KeyPair keyPair;
    public KeyAgreement KeyAgree;
    public Key pubKey;

    public User(String username) throws Exception {
        name = username;

        // user generates their DH key pair
        System.out.println(name + ": Generate DH keypair ...");
        KpairGen = KeyPairGenerator.getInstance("DH");
        KpairGen.initialize(1024); // this is where the global paramaters should be put
        keyPair = KpairGen.generateKeyPair();
        
        // user initializes
        System.out.println(name + ": Initialize ...");
        KeyAgree = KeyAgreement.getInstance("DH");
        KeyAgree.init(keyPair.getPrivate());

        pubKey = keyPair.getPublic();
    }

    public User(String username, DHParameterSpec dhParamSpec) throws Exception {
        name = username;

        // user generates their DH key pair using provided specs
        System.out.println(name + ": Generate DH keypair ...");
        KpairGen = KeyPairGenerator.getInstance("DH");
        KpairGen.initialize(dhParamSpec);
        keyPair = KpairGen.generateKeyPair();

        // user initializes
        System.out.println(name + ": Initialize ...");
        KeyAgree = KeyAgreement.getInstance("DH");
        KeyAgree.init(keyPair.getPrivate());

        pubKey = keyPair.getPublic();
    }
    
    // simulates sending user's public key
    public Key send() {
        return pubKey;
    }
    // simulates sending user's public key after putting the key to the power of user's private key and MODing it
    public Key send(Key input) throws Exception {
        return KeyAgree.doPhase(input, false);
    }
}
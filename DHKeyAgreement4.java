import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class DHKeyAgreement4 {
    public static void main(String[] args) throws Exception {
        // initialise a with hard coded keysize/parameters
        User alice = new User("Alice");
        DHPublicKey DHPubKey = (DHPublicKey) alice.pubKey;
        DHParameterSpec dhParamSpec = DHPubKey.getParams();

        // create b,c,d using the same parameters as a
        User bob = new User("Bob", dhParamSpec);
        User  carol = new User("Carol", dhParamSpec);
        User david = new User("David", dhParamSpec);

        /* 
        share keys between users
        
        alice used as example
        bob starts with g^b which is sent to carol
        carol sends g^bc to david
        david sends g^bcd to alice
        alice calculates the final shared key g^bcda - aliceSharedSecret
        this repeats for all members 
        */
        alice.KeyAgree.doPhase(david.send(carol.send(bob.send())), true);  //bcd   // true indicates this is the last phase in the agreement
        byte[] aliceSharedSecret = alice.KeyAgree.generateSecret();

        bob.KeyAgree.doPhase(alice.send(david.send(carol.send())), true);  //cda
        byte[] bobSharedSecret = bob.KeyAgree.generateSecret();

        carol.KeyAgree.doPhase(bob.send(alice.send(david.send())), true);  //dab
        byte[] carolSharedSecret = carol.KeyAgree.generateSecret();

        david.KeyAgree.doPhase(carol.send(bob.send(alice.send())), true); // abc
        byte[] davidSharedSecret = david.KeyAgree.generateSecret();

        // checks if all keys are equal
        if (!java.util.Arrays.equals(aliceSharedSecret, bobSharedSecret))
            throw new Exception("Alice and Bob differ");
        System.out.println("Alice and Bob are the same");

        if (!java.util.Arrays.equals(bobSharedSecret, carolSharedSecret))
            throw new Exception("Bob and Carol differ");
        System.out.println("Bob and Carol are the same");

        if (!java.util.Arrays.equals(carolSharedSecret, davidSharedSecret))
            throw new Exception("Carol and David differ");
        System.out.println("Carol and David are the same");
    }
}

import java.security.PrivateKey;
import java.security.Signature;

public class Signer {

    public byte[] sign(PrivateKey privateKey, byte[] data, String algorithm) {

        Signature signature;
        byte[] sig = null;
        try {
            signature = Signature.getInstance(algorithm);
            signature.initSign(privateKey);
            // Update and sign the data
            signature.update(data);
            sig = signature.sign();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return sig;
    }
}
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;

import javax.crypto.spec.IvParameterSpec;

/**
 * In charge of encrypting a file using the Cipher Class
 */
public class Encrypter {

    private KeyGenerator kg;

    public byte[] encrypt(byte[] content, String encryptAlgo, String algoMode, String cryptoProvider, String padding) {
        byte[] res = null;
        try {
            String ciphInit = encryptAlgo + '/' + algoMode + '/' + padding;
            Cipher ciph = Cipher.getInstance(ciphInit);

            // generate a key for the encryption
            kg = KeyGenerator.getInstance(encryptAlgo);
            SecretKey sk = kg.generateKey();

            // generate random IV for encryption
            SecureRandom sr = SecureRandom.getInstance(encryptAlgo, cryptoProvider);
            byte ivArr[] = new byte[16];
            sr.nextBytes(ivArr);
            IvParameterSpec iv = new IvParameterSpec(ivArr);

            ciph.init(Cipher.ENCRYPT_MODE, sk, iv);
            res = ciph.doFinal(content);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return res;
    }

    private static void getKey(String cryptoProvider) {

    }
}

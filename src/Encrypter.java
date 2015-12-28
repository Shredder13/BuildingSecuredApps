import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;


/**
 * In charge of encrypting a file using the Cipher Class
 */
public class Encrypter {

    private KeyGenerator kg;

    public void Encrypt(byte[] content, String encryptAlgo, String algoMode, String cryptoProvider) {
        try {
            String ciphInit = encryptAlgo + '/' + algoMode + '/' + "";
            Cipher ciph = Cipher.getInstance(ciphInit);
            kg = KeyGenerator.getInstance(encryptAlgo);
            SecretKey sk = kg.generateKey();
            try {
                ciph.init(Cipher.ENCRYPT_MODE, sk);
            } catch (InvalidKeyException e) {

            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }

        //ciph.init(Cipher.EN)
    }

    private static void getKey(String cryptoProvider) {

    }
}

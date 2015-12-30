import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Properties;

/**
 * In charge of the configuration, and starts the encryption and the signing of the file
 */
public class EncryptAndSign {

    private byte[] plaintext;
    private String encryptAlgo;
    private String algoMode;
    private String cryptoProvider;
    private String padding;
    private String signatureAlgo;
    private KeyStore keystore;
    private String keystorePass;

    public EncryptAndSign() {
        plaintext = null;
        // default values in case we would not be able to read from the config
        encryptAlgo = "AES";
        algoMode = "CBC";
        cryptoProvider = "SunJCE";
        padding = "PKCS5Padding";
        signatureAlgo = "SHA1withDSA";
        try {
            keystore = KeyStore.getInstance("JCEKS", cryptoProvider);
        } catch (Exception e) {
            //TODO: treat the exception
            e.getMessage();
        }

    }

    public void setKeystore(String keystoreName) {
        try {
            this.keystore.load(new FileInputStream(keystoreName), keystorePass.toCharArray());
        } catch (Exception e) {
            //TODO: treat the exception
            e.getMessage();
        }

    }

    public void setKeystorePass(String password) {
        keystorePass = password;
    }

    public void ecryptAndSign(Path path) {
        if (path.toFile() != null) {
            setConfigurations();
            readFile(path);
            Encrypter encrypter = new Encrypter();
            byte[] data = encrypter.encrypt(plaintext, encryptAlgo, algoMode, cryptoProvider, padding);
            Signer signer = new Signer();
            byte[] signedData = signer.sign(null, data, signatureAlgo);
        }
    }

    private void setConfigurations() {
        File file = new File("config.ini");
        try {
            FileReader reader = new FileReader(file);
            Properties properties = new Properties();
            properties.load(reader);
            encryptAlgo = properties.getProperty("encrypt_algorithm");
            algoMode = properties.getProperty("encrypt_algorithm_mode");
            cryptoProvider = properties.getProperty("crypto_provider");
            padding = properties.getProperty("padding");
            signatureAlgo = properties.getProperty("signature_algorithm");
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }

    private void readFile(Path path) {
        try {
            plaintext = Files.readAllBytes(path);
            //TODO: remove after tests
            System.out.println(plaintext.toString());
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }
}

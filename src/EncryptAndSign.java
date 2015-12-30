import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

/**
 * In charge of the configuration, and starts the encryption and the signing of the file
 */
public class EncryptAndSign {

    //private byte[] plaintext;
    private String encryptAlgo;
    private String algoMode;
    private String cryptoProvider;
    private String padding;
    private String signatureAlgo;
    private String keyEncryptAlgo;

    public EncryptAndSign(Path path, String keystoreName, String keystorePass, String keyAlias, String keyAliasPass, String certAlias) {
        //plaintext = null;
        // default values in case we would not be able to read from the config
        encryptAlgo = "AES";
        algoMode = "CBC";
        cryptoProvider = "SunJCE";
        padding = "PKCS5Padding";
        signatureAlgo = "SHA1withDSA";

        if (path.toFile() != null) {
            setConfigurations();
            Encrypter encrypter = new Encrypter(cryptoProvider, keystoreName, keystorePass, keyAlias, certAlias);
            byte[] data = encrypter.encrypt(path, encryptAlgo, algoMode, cryptoProvider, padding, keystoreName, keystorePass, keyAlias, keyAliasPass, keyEncryptAlgo);
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
            keyEncryptAlgo = properties.getProperty("key_encrypt_algorithm");
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }
}

package bsapps;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

/**
 * In charge of the configuration, and starts the encryption and the signing of the file
 */
public class EncryptAndSign {

    private byte[] plaintext;
    private String encryptAlgo;
    private String algoMode;
    private String cryptoProvider;

    public EncryptAndSign() {
        plaintext = null;
        // default values in case we would not be able to read from the config
        encryptAlgo = "RSA";
        algoMode = "CBC";
        cryptoProvider = "SunJCE";
    }

    public void handleFile(Path path) {
        if (path.toFile() != null) {
            readFile(path);
            getConfigurations();
            encrypter.encrypt(plaintext, encryptAlgo, algoMode, cryptoProvider);
            Signer signer = new Signer();
            signer.sign();
        }
    }

    private void getConfigurations() {
        File file = new File("config.ini");
        try {
            FileReader reader = new FileReader(file);
            Properties properties = new Properties();
            properties.load(reader);
            encryptAlgo = properties.getProperty("encrypt_algorithm");
            algoMode = properties.getProperty("algorithm_mode");
            cryptoProvider = properties.getProperty("crypto_provider");
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }

    private void readFile(Path path) {
        try {
            plaintext = Files.readAllBytes(path);
            //TODO: remove after tests
            System.out.println(plaintext);
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }
}

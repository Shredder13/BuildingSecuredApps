

//import javax.crypto.CipherOutputStream;
import java.nio.file.Path;
import java.nio.file.Paths;


public class Main {

    public static void main(String[] args) {
        if (args.length != 6) {
            System.out.println("Usage: EnryptAndSign.jar <File Path> <Keystore name> <Keystore Password> <Key Alias> <Key Password> <Certificate Alias>");
            return;
        } else {
            Path path = Paths.get(args[0]);
            String keyStorePass = args[2];
            String keyStoreName = args[1];
            String keyAlias = args[3];
            String keyAliasPass = args[4];
            String certAlias = args[5];
            EncryptAndSign eas = new EncryptAndSign(path, keyStoreName, keyStorePass, keyAlias, keyAliasPass, certAlias);

            // AES with CBC and random IV
            // the key for the AES we randomly select using a function from the API

            //eas.sign();
        }
        // 1. get plaintext
        // 2. encode and write cypher
        // 3. calculate digital signature (a-symetric) of the file's content and save to config file
        // the config file can contain the encrypted key

        // IMPORTANT:

        // have to be able to switch the algorithm and crypto providers easily -> config file!
    }
}

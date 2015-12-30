import java.nio.file.Path;
import java.nio.file.Paths;


public class Main {

    public static void main(String[] args) {
        if (args.length != 6) {
            System.out.println("Usage: EncryptAndSign.jar <File Path> <Keystore name> <Keystore Password> <Key Alias> <Key Password> <Certificate Alias>");
            return;
        } else {
            Path path = Paths.get(args[0]);
            String keyStorePass = args[2];
            String keyStoreName = args[1];
            String keyAlias = args[3];
            String keyAliasPass = args[4];
            String certAlias = args[5];
            Encrypter encrypter = new Encrypter();
            encrypter.encrypt(path, keyStoreName, keyStorePass, certAlias, keyAlias, keyAliasPass);
        }
    }
}

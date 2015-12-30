import java.nio.file.Path;
import java.nio.file.Paths;


public class Main {

    public static void main(String[] args) {
        String usage = "Usage: \n 1: EncryptAndSign.jar <Mode: Encrypt> <File to Encrypt Path> <Keystore name> " +
                "<Keystore Password> <Key Alias> <Key Password> <Certificate Alias>" + "\n OR 2: EncryptAndSign.jar " +
                "<Mode: Encrypt> <File to Decrypt Path> <Config File Path> <Keystore name> + \n" +
                "<Keystore Password> <Key Alias> <Key Password> <Certificate Alias>";
        if (args[0] == "Encrypt") {
            if (args.length != 7) {
                System.out.println(usage);
                return;
            } else {
                Path path = Paths.get(args[1]);
                String keyStoreName = args[2];
                String keyStorePass = args[3];
                String keyAlias = args[4];
                String keyAliasPass = args[5];
                String certAlias = args[6];
                Encryptor encrypter = new Encryptor();
                encrypter.encrypt(path, keyStoreName, keyStorePass, certAlias, keyAlias, keyAliasPass);
            }
        } else if (args[0] != "Decrypt") {
            System.out.println(usage);
        } else {
            if (args.length != 8) {
                System.out.println(usage);
                return;
            } else {
                Path toDecrypt = Paths.get(args[1]);
                Path config = Paths.get(args[2]);
                String keyStoreName = args[3];
                String keyStorePass = args[4];
                String keyAlias = args[5];
                String keyAliasPass = args[6];
                String certAlias = args[7];
                Decryptor decrypter = new Decryptor();
                decrypter.decrypt(toDecrypt, config, keyStoreName, keyStorePass, certAlias, keyAlias, keyAliasPass);
            }

        }
    }
}

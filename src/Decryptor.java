import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Properties;

public class Decryptor {

    private final String KEYSTORE_TYPE = "JCEKS";

    private KeyStore keystore;
    private String encryptAlgo;
    private String signatureAlgo;
    private String keyEncryptAlgo;
    private String cipherAlgoMode;
    private String signature;
    private String iv;
    private String encryptedKey;
    private Certificate certificate;
    private byte[] signatureBytes;
    private byte[] ivBytes;

    public Decryptor() {

        try {
            keystore = KeyStore.getInstance(KEYSTORE_TYPE);
        } catch (KeyStoreException e) {
            // TODO
            e.printStackTrace();
        }
    }

    public void decrypt(Path encrypted, Path config, String keystoreName, String keystorePass, String certAlias,
                        String keyAlias, String keyAliasPass) {
        try {
            keystore.load(new FileInputStream(keystoreName), keystorePass.toCharArray());
            Key key = keystore.getKey(keyAlias, keyAliasPass.toCharArray());
            PrivateKey priKey = null;
            if (key != null) {
                if (key instanceof PrivateKey) {
                    priKey = (PrivateKey) key;
                } else {
                    //TODO
                }
            } else {
                //TODO
            }

            certificate = keystore.getCertificate(certAlias);
            PublicKey pubKey = null;
            if (certificate != null) {
                pubKey = certificate.getPublicKey();
            } else {
                //TODO
            }

            // read configurations from file
            getConfigurations(config);

            // get symmetric key using the private key we've got
            Cipher ciph = Cipher.getInstance(keyEncryptAlgo);
            ciph.init(Cipher.DECRYPT_MODE, priKey);
            byte[] decKey = ciph.doFinal(encryptedKey.getBytes());
            Key secret = new SecretKeySpec(decKey, encryptAlgo);

            Signature signa = Signature.getInstance(signatureAlgo);
            signa.initVerify(pubKey);

            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

            ciph = Cipher.getInstance(cipherAlgoMode);
            ciph.init(Cipher.DECRYPT_MODE, secret, ivSpec);

            CipherInputStream cis = new CipherInputStream(new FileInputStream(encrypted.toFile()), ciph);
            readAndDecrypt(cis);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void getConfigurations(Path config) {
        try {
            FileReader reader = new FileReader(config.toFile());
            Properties prop = new Properties();
            prop.load(reader);
            encryptAlgo = prop.getProperty("encrypt_algorithm");
            signatureAlgo = prop.getProperty("signature_algorithm");
            keyEncryptAlgo = prop.getProperty("key_encription_algorithm");
            cipherAlgoMode = prop.getProperty("cipher_algorithm_mode");
            encryptedKey = prop.getProperty("encripted_key");
            signature = prop.getProperty("file_signature");
            signatureBytes = signature.getBytes();
            iv = prop.getProperty("iv");
            ivBytes = iv.getBytes();
        } catch (IOException e) {
            //TODO
            e.printStackTrace();
        }
    }

    private void readAndDecrypt(CipherInputStream cis) {
        try {
            byte[] buff = new byte[1024];
            FileOutputStream fos = new FileOutputStream("decrypted");
            int num = cis.read(buff);
            while (num != -1) {
                //signatureBytes.(buff, 0, num);
                fos.write(buff, 0 ,num);
                num = cis.read(buff);
            }
            cis.close();
            fos.close();
        } catch (Exception e) {
            // TODO
            e.printStackTrace();
        }
    }

}
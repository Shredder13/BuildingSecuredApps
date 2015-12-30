import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;

import javax.crypto.spec.IvParameterSpec;

/**
 * In charge of encrypting a file using the Cipher Class
 */
public class Encrypter {

    private KeyGenerator kg;
    private KeyStore keystore;
    private String keystorePass;
    private Certificate certificate;


    public Encrypter(String cryptoProvider, String keystoreName, String keystorePass, String keyAlias, String certAlias) {
        try {
            keystore = KeyStore.getInstance("JCEKS", cryptoProvider);
            //TODO: get certificate from keystore
            certificate = keystore.getCertificate(certAlias);
        } catch (Exception e) {
            //TODO: treat the exception
            e.getMessage();
        }
    }
    public byte[] encrypt(Path path, String encryptAlgo, String algoMode, String cryptoProvider, String padding, String keystoreName, String keystorePass,
                          String keyAlias, String keyAliasPass, String keyEncryptAlgo, String signAlgo) {
        byte[] res = null;
        try {
            String ciphInit = encryptAlgo + '/' + algoMode + '/' + padding;
            Cipher ciph = Cipher.getInstance(ciphInit);

            // generate a key for the encryption
            kg = KeyGenerator.getInstance(encryptAlgo, cryptoProvider);
            SecretKey sk = kg.generateKey();

            // generate random IV for encryption
            SecureRandom sr = SecureRandom.getInstance(encryptAlgo, cryptoProvider);
            byte ivArr[] = new byte[16];
            sr.nextBytes(ivArr);
            IvParameterSpec iv = new IvParameterSpec(ivArr);

            keystore.load(new FileInputStream(keystoreName), keystorePass.toCharArray());
            Key ek = keystore.getKey(keyAlias, keyAliasPass.toCharArray());
            PrivateKey priKey = null;
            if (ek != null) {
                if (ek instanceof PrivateKey) {
                    priKey = (PrivateKey)ek;
                } else {
                    //TODO
                }
            }
            PublicKey pubKey = null;
            if (certificate != null) {
                pubKey = certificate.getPublicKey();
            } else {
                //TODO
            }

            // initialize cipher for plaintext encryption
            ciph.init(Cipher.ENCRYPT_MODE, sk, iv);

            FileInputStream fis = new FileInputStream(path.toString());
            CipherOutputStream cos = new CipherOutputStream(new FileOutputStream("encripted"), ciph);
            Signature signature = sign(signAlgo, cryptoProvider, priKey);
            readAndEncrypt(fis, cos, signature);
            ciph = Cipher.getInstance(keyEncryptAlgo, cryptoProvider);
            byte[] encKey = ciph.doFinal(sk.getEncoded());

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return res;
    }

    private void readAndEncrypt(FileInputStream fis, CipherOutputStream cos, Signature signature) {
        byte[] buff = new byte[1024];
        try {
            int num = fis.read(buff);
            while (num != -1) {
                signature.update(buff, 0, num);
                cos.write(buff, 0 ,num);
                num = fis.read(buff);
            }
            fis.close();
            cos.close();

        } catch (Exception e) {

        }
    }

    private Signature sign(String signatureAlgo, String cryptoProv, PrivateKey key) {
        Signature signa = null;
        try {
            signa = Signature.getInstance(signatureAlgo, cryptoProv);
            signa.initSign(key);
        } catch (Exception e) {
            // TODO: handle
        }
        return signa;
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
}

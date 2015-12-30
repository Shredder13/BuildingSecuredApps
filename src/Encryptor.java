import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Properties;

import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;

/**
 * In charge of encrypting a file using the Cipher Class
 */
public class Encryptor {

    private final String KEYSTORE_TYPE = "JCEKS";
    private final String SIGN_PROVIDER = "SunRsaSign";

    private String encryptAlgo = "AES";
    private String algoMode = "CBC";
    private String cryptoProvider = "SunJCE";
    private String padding = "PKCS5Padding";
    private String signatureAlgo = "SHA1withRSA";
    private String keyEncryptAlgo = "RSA";
    private String cipherAlgoMode = "AES/CBC/PKCS5Padding";
    private String ivAlgo = "SHA1PRNG";
    private String ivProvider = "SUN";

    private KeyStore keystore;
    private Certificate certificate;
    private Signature signature;



    public Encryptor() {

        setConfigurations();
        try {
            keystore = KeyStore.getInstance(KEYSTORE_TYPE, cryptoProvider);
        } catch (Exception e) {
            //TODO: treat the exception
            e.getMessage();
        }
    }
    public void encrypt(Path path, String keystoreName, String keystorePass, String certAlias,
                          String keyAlias, String keyAliasPass) {
        try {
            // generate a key for the encryption
            KeyGenerator kg = KeyGenerator.getInstance(encryptAlgo, cryptoProvider);
            SecretKey sk = kg.generateKey();

            // generate random IV for encryption
            SecureRandom sr = SecureRandom.getInstance(ivAlgo, ivProvider);
            byte[] ivArr = new byte[16];
            sr.nextBytes(ivArr);
            IvParameterSpec iv = new IvParameterSpec(ivArr);

            // load private key and public key from keystore using the given name and password
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
            // get public key from certificate
            PublicKey pubKey = null;
            certificate = keystore.getCertificate(certAlias);
            if (certificate != null) {
                pubKey = certificate.getPublicKey();
            } else {
                //TODO
            }

            // encryption to the encription algorithm key
            Cipher ciphKey = Cipher.getInstance(keyEncryptAlgo, cryptoProvider);
            ciphKey.init(Cipher.ENCRYPT_MODE, pubKey);
            byte[] encKey = ciphKey.doFinal(sk.getEncoded());

            signature = initSignature(signatureAlgo, SIGN_PROVIDER, priKey);

            // initialize cipher for plaintext encryption
            String ciphInit = encryptAlgo + '/' + algoMode + '/' + padding;
            Cipher ciph = Cipher.getInstance(ciphInit);
            ciph.init(Cipher.ENCRYPT_MODE, sk, iv);


            FileInputStream fis = new FileInputStream(path.toString());
            CipherOutputStream cos = new CipherOutputStream(new FileOutputStream("encrypted"), ciph);
            readAndEncrypt(fis, cos);

            byte[] signedSig = signature.sign();

            writeToConfig(encKey, signedSig, ivArr);

        } catch (Exception e) {
            //TODO
            System.out.println(e.getMessage());
        }
    }

    private void readAndEncrypt(FileInputStream fis, CipherOutputStream cos) {
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
            //TODO
        }
    }

    private Signature initSignature(String signatureAlgo, String cryptoProv, PrivateKey key) {
        Signature signa = null;
        try {
            signa = Signature.getInstance(signatureAlgo, cryptoProv);
            signa.initSign(key);
        } catch (Exception e) {
            // TODO: handle
            e.getMessage();
        }
        return signa;
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

    private void writeToConfig(byte[] encriptedKey, byte[] signature, byte[] iv) {
        try {
            FileOutputStream fos = new FileOutputStream(new File("encrypted_output"));
            String line = "encryption_algorithm=" + encryptAlgo + "\n";
            fos.write(line.getBytes());
            line = "signature_algorithm=" + signatureAlgo + "\n";
            fos.write(line.getBytes());
            line = "key_encryption_algorithm=" + keyEncryptAlgo + "\n";
            fos.write(line.getBytes());
            line = "cipher_algorithm_mode=" + cipherAlgoMode + "\n";
            fos.write(line.getBytes());
            line = "encrypted_key=";
            fos.write(line.getBytes());
            fos.write(DatatypeConverter.printBase64Binary(encriptedKey).getBytes());
            fos.write("\n".getBytes());
            line = "file_signature=";
            fos.write(line.getBytes());
            fos.write(DatatypeConverter.printBase64Binary(signature).getBytes());
            fos.write("\n".getBytes());
            line = "iv=";
            fos.write(line.getBytes());
            fos.write(DatatypeConverter.printBase64Binary(iv).getBytes());
            fos.flush();
            fos.close();
        } catch (Exception e) {
            // TODO
        }
    }

//    private void writeToConfig2(byte[] encriptedKey, byte[] signature, byte[] iv) {
//        try{
//            Writer conf = new PrintWriter(new FileOutputStream("encrypted_output"));
//            conf.write(DatatypeConverter.parseBase64Binary(encriptedKey) + "\n");
//            conf.write(DatatypeConverter.parseBase64Binary(encryptAlgo) + "\n");
//            conf.write(DatatypeConverter.parseBase64Binary(encryptAlgo) + "\n");
//            conf.write(DatatypeConverter.parseBase64Binary(encryptAlgo) + "\n");
//            conf.write(DatatypeConverter.parseBase64Binary(encryptAlgo) + "\n");
//            conf.write(DatatypeConverter.parseBase64Binary(encryptAlgo) + "\n");
//            conf.write(DatatypeConverter.parseBase64Binary(encryptAlgo) + "\n");
//            conf.write(DatatypeConverter.parseBase64Binary(encryptAlgo) + "\n");
//
//        } catch (Exception e) {
//
//        }
//    }
}

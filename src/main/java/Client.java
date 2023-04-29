import org.bouncycastle.jce.provider.BouncyCastleProvider;
import utils.RandomChallengeGenerator;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;

public class Client {
    private static final int SERVER_PORT = 5000;
    private static final String SERVER_IP = "127.0.0.1";
    private static final String CERT_PASSWD = "dalgov";

    public static void main(String[] args) {
        EIDKeystoreManager keyStore = new EIDKeystoreManager();
        X509Certificate cert = keyStore.getCertificate();
        PublicKey publicKey = keyStore.getPublicKey();
        PrivateKey privateKey = keyStore.getPrivateKey();
        Certificate[] certificateChain = keyStore.getCertificateChain();

        getBankAuthorization(publicKey, privateKey);
    }

    private static void getBankAuthorization(PublicKey publicKey, PrivateKey privateKey) {
        try {
            //TODO Fetch bank's certificate from Certificate Server
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            FileInputStream fis = new FileInputStream("src/main/certs/keystore.jks");
            keyStore.load(fis, CERT_PASSWD.toCharArray());
            Certificate bankCert = keyStore.getCertificate("beid");
            PublicKey bankPubKey = bankCert.getPublicKey();
            PrivateKey privateKey1 = (PrivateKey) keyStore.getKey("beid", CERT_PASSWD.toCharArray());

            Security.addProvider(new BouncyCastleProvider());

            byte[] sessionKey = RandomChallengeGenerator.generateRandomChallenge(32);

            // Connect to the server
            try (Socket socket = new Socket(SERVER_IP, SERVER_PORT)) {
                var signature = signSessionKey(sessionKey, privateKey);

                String sessionKeyAndSignature =
                        Base64.getEncoder().encodeToString(signature)
                        + "#"
                        + Base64.getEncoder().encodeToString(sessionKey)
                        + "#"
                        + Base64.getEncoder().encodeToString(publicKey.getEncoded())
                        + "clientNumber";

                Cipher cipher = Cipher.getInstance("ECIES", "BC");
                cipher.init(Cipher.ENCRYPT_MODE, bankPubKey);
                byte[] ciphertextBytes = cipher.doFinal(sessionKeyAndSignature.getBytes(StandardCharsets.UTF_8));
                String ciphertext = Base64.getEncoder().encodeToString(ciphertextBytes);

                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                out.writeObject(ciphertext);
                out.flush();

                // Decrypt
                /**Cipher cipher2 = Cipher.getInstance("ECIES", "BC");
                cipher2.init(Cipher.DECRYPT_MODE, privateKey1);
                byte[] decoded = Base64.getDecoder().decode(ciphertext);
                byte[] messageBytes = cipher2.doFinal(decoded);
                String message = new String(messageBytes);
                System.out.println(message);**/

            } catch (NoSuchPaddingException e) {
                throw new RuntimeException(e);
            } catch (IllegalBlockSizeException e) {
                throw new RuntimeException(e);
            } catch (BadPaddingException e) {
                throw new RuntimeException(e);
            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            } catch (NoSuchProviderException e) {
                throw new RuntimeException(e);
            }

            //Exchanging data with the bank

            // Clean up


        } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        } catch (UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] signSessionKey(byte[] message, PrivateKey privateKey) {
        try {
            Signature signature = Signature.getInstance("SHA384withECDSA");
            signature.initSign(privateKey);
            signature.update(message);
            byte[] signatureBytes = signature.sign();
            return signatureBytes;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}

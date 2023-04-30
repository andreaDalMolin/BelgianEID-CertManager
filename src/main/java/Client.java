import org.bouncycastle.jce.provider.BouncyCastleProvider;
import utils.RandomChallengeGenerator;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;

import static utils.CryptoUtil.decryptStringWithAES;
import static utils.CryptoUtil.encryptStringWithAES;

public class Client {
    private static final int SERVER_PORT = 5000;
    private static final String SERVER_IP = "127.0.0.1";
    private static final String CERT_PASSWD = "dalgov";
    private static final String USER_PIN = "1111";
    private static final String CLIENT_NUMBER = "1111";

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
            Security.addProvider(new BouncyCastleProvider());
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            FileInputStream fis = new FileInputStream("src/main/certs/keystore.jks");
            keyStore.load(fis, CERT_PASSWD.toCharArray());
            Certificate bankCert = keyStore.getCertificate("beid");
            PublicKey bankPubKey = bankCert.getPublicKey();
//            PrivateKey bankPrivKey = (PrivateKey) keyStore.getKey("beid", CERT_PASSWD.toCharArray());

            // Connect to the server
            try (Socket socket = new Socket(SERVER_IP, SERVER_PORT)) {
                InputStream in = socket.getInputStream();
                ObjectInputStream inputStream = new ObjectInputStream(in);
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                
                // 1. Generate a session key and sign it 
                byte[] sessionKey = RandomChallengeGenerator.generateRandomChallenge(32);
                var signature = signMessage(sessionKey, privateKey);

                // 2. Send Session key + Signature + EID Public Key to the bank
                String sessionKeyAndSignature =
                        Base64.getEncoder().encodeToString(signature)
                        + "#"
                        + Base64.getEncoder().encodeToString(sessionKey)
                        + "#"
                        + Base64.getEncoder().encodeToString(publicKey.getEncoded());

                Cipher cipher = Cipher.getInstance("ECIES", "BC");
                cipher.init(Cipher.ENCRYPT_MODE, bankPubKey);
                byte[] ciphertextBytes = cipher.doFinal(sessionKeyAndSignature.getBytes(StandardCharsets.UTF_8));
                String ciphertext = Base64.getEncoder().encodeToString(ciphertextBytes);

                out.writeObject(ciphertext);
                out.flush();

                Object inObj = decryptStringWithAES((byte[]) inputStream.readObject(), sessionKey);

                assert inObj != null;
                if ((inObj.equals("CLIENT_NUMBER_REQUEST"))) {
                    out.writeObject(encryptStringWithAES(CLIENT_NUMBER, sessionKey));
                    out.flush();
                }

                // Retrieve bank's challenge
                String challenge = decryptStringWithAES((byte[]) inputStream.readObject(), sessionKey);
                byte[] decodedChallenge = Base64.getDecoder().decode(challenge);

                //TODO grab user's PIN

                assert challenge != null;
                byte[] signedChallenge = signMessage(decodedChallenge, privateKey);
                String signedChallengeAndPin =
                        Base64.getEncoder().encodeToString(signedChallenge)
                        + "#"
                        + USER_PIN;

                out.writeObject(encryptStringWithAES(signedChallengeAndPin, sessionKey));
                out.flush();

                inObj = decryptStringWithAES((byte[]) inputStream.readObject(), sessionKey);

                assert inObj != null;
                if (inObj.equals("OK")) {
                    System.out.println("we cool");
                } else {
                    System.out.println("we fucked");
                }

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
            } catch (ClassNotFoundException e) {
                throw new RuntimeException(e);
            }

            //Exchanging data with the bank

            // Clean up


        } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
    }

    private static byte[] signMessage(byte[] message, PrivateKey privateKey) {
        try {
            Signature signature = Signature.getInstance("SHA384withECDSA");
            signature.initSign(privateKey);
            signature.update(message);
            return signature.sign();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}

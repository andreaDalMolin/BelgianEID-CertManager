import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import utils.RandomChallengeGenerator;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import static utils.CryptoUtil.decryptStringWithAES;
import static utils.CryptoUtil.encryptStringWithAES;

public class Bank {
    private static final int PORT = 5000;
    private static final String CERT_PASSWD = "dalgov";
    private static final String KEY_STORE_PATH = "src/main/certs/keystore.jks";
    private static final String PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "EC";
    private static final String CIPHER_ALGORITHM = "ECIES";
    private static final String SIGNATURE_ALGORITHM = "SHA384withECDSA";
    private static final Logger LOGGER = LoggerFactory.getLogger(Bank.class);

    public static void main(String[] args) throws SignatureException {

        try (ServerSocket serverSocket = new ServerSocket(PORT);
             FileInputStream keyStoreStream = new FileInputStream(KEY_STORE_PATH)) {
            LOGGER.info("Server started on port {}", PORT);

            Security.addProvider(new BouncyCastleProvider());
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(keyStoreStream, CERT_PASSWD.toCharArray());
            PrivateKey privateKey = (PrivateKey) keyStore.getKey("beid", CERT_PASSWD.toCharArray());


            while (true) {
                Socket clientSocket = serverSocket.accept();
                LOGGER.info("Client connected from " + clientSocket.getInetAddress());

                ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
                InputStream in = clientSocket.getInputStream();
                ObjectInputStream objIn = new ObjectInputStream(in);
                Object inputStream = objIn.readObject();

                if (inputStream instanceof String) {
                    // 1. Decrypt and extract Signature, Session Key and Client's EID Public Key
                    Cipher cipher = Cipher.getInstance("ECIES", "BC");
                    cipher.init(Cipher.DECRYPT_MODE, privateKey);
                    byte[] decoded = Base64.getDecoder().decode(((String) inputStream).getBytes(StandardCharsets.UTF_8));
                    byte[] messageBytes = cipher.doFinal(decoded);
                    String message = new String(messageBytes);
                    byte[] signature = Base64.getDecoder().decode(message.split("#")[0]);
                    byte[] sessionKey = Base64.getDecoder().decode(message.split("#")[1]);
                    byte[] clientPubKeyBytes = Base64.getDecoder().decode(message.split("#")[2]);
                    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(clientPubKeyBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance("EC");
                    ECPublicKey clientPubKey = (ECPublicKey) keyFactory.generatePublic(keySpec);

                    // 2. Verify if the signature is valid
                    if (!checkSignatureValid(clientPubKey, signature, sessionKey)) {
                        LOGGER.error("Invalid signature, closing connection with client");
                        clientSocket.close();
                        continue;
                    }

                    out.writeObject(encryptStringWithAES("CLIENT_NUMBER_REQUEST", sessionKey));
                    out.flush();

                    // 3. Ask client's number
                    inputStream = objIn.readObject();

                    //Here you do all the stuff involved with fecthing the user in the DB, checking if he exists, if the number is valid etc...
                    // ...

                    // 4. Generate random challenge and send it to client
                    byte[] challenge = RandomChallengeGenerator.generateRandomChallenge(32);
                    String encodedChallenge = Base64.getEncoder().encodeToString(challenge);
                    out.writeObject(encryptStringWithAES(encodedChallenge, sessionKey));
                    out.flush();

                    // 5. Verify challenge's signature and PIN
                    inputStream = decryptStringWithAES((byte[]) objIn.readObject(), sessionKey);

                    byte[] signedChallenge = Base64.getDecoder().decode((String) ((String) inputStream).split("#")[0]);
                    String userPin = (String) ((String) inputStream).split("#")[1];

                    //TODO verify user's PIN

                    if (checkSignatureValid(clientPubKey, signedChallenge, challenge)) {
                        out.writeObject(encryptStringWithAES("OK", sessionKey));
                        out.flush();
                    } else {
                        out.writeObject(encryptStringWithAES("NOK", sessionKey));
                        out.flush();
                    }
                }

                objIn.close();
                in.close();
                clientSocket.close();
            }
        } catch (IOException | ClassNotFoundException | UnrecoverableKeyException | NoSuchPaddingException |
                 IllegalBlockSizeException | CertificateException | KeyStoreException | NoSuchAlgorithmException |
                 BadPaddingException | NoSuchProviderException | InvalidKeyException | InvalidKeySpecException e) {
            LOGGER.error(e.getMessage());
        }

    }

    private static boolean checkSignatureValid(ECPublicKey ecPublicKey, byte[] signature, byte[] originalMessage) throws  NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sVerif = Signature.getInstance("SHA384withECDSA");
        sVerif.initVerify(ecPublicKey);
        sVerif.update(originalMessage);
        return sVerif.verify(signature);
    }
}

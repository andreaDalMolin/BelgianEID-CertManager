import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
    private static int port = 5000;
    private static final String CERT_PASSWD = "dalgov";

    public static void main(String[] args) throws SignatureException {

        try {
            ServerSocket serverSocket = new ServerSocket(port);
            System.out.println("Server started on port " + port);
            Security.addProvider(new BouncyCastleProvider());

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            FileInputStream fis = new FileInputStream("src/main/certs/keystore.jks");
            keyStore.load(fis, CERT_PASSWD.toCharArray());
            Certificate bankCert = keyStore.getCertificate("beid");
            PublicKey bankPubKey = bankCert.getPublicKey();
            PrivateKey privateKey1 = (PrivateKey) keyStore.getKey("beid", CERT_PASSWD.toCharArray());

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected from " + clientSocket.getInetAddress());

                ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
                InputStream in = clientSocket.getInputStream();
                ObjectInputStream objIn = new ObjectInputStream(in);
                Object inputStream = objIn.readObject();

                if (inputStream instanceof String) {
                    // Decrypt and extract Signature, Session Key and Client's EID Public Key
                    Cipher cipher2 = Cipher.getInstance("ECIES", "BC");
                    cipher2.init(Cipher.DECRYPT_MODE, privateKey1);
                    byte[] decoded = Base64.getDecoder().decode(((String) inputStream).getBytes(StandardCharsets.UTF_8));
                    byte[] messageBytes = cipher2.doFinal(decoded);
                    String message = new String(messageBytes);
                    byte[] signature = Base64.getDecoder().decode(message.split("#")[0]);
                    byte[] sessionKey = Base64.getDecoder().decode(message.split("#")[1]);
                    byte[] clientPubKeyBytes = Base64.getDecoder().decode(message.split("#")[2]);
                    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(clientPubKeyBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance("EC");
                    ECPublicKey ecPublicKey = (ECPublicKey) keyFactory.generatePublic(keySpec);

                    // Verify if the signature is valid
                    if (!checkSignatureValid(ecPublicKey, signature, sessionKey)) {
                        //TODO
                        //Stop the process, signature invalid
                    }

                    out.writeObject(encryptStringWithAES("CLIENT_NUMBER_REQUEST", sessionKey));
                    out.flush();

                    // Retrieve client number
                    inputStream = objIn.readObject();

                    //Here you do all the stuff involved with fecthing the user in the DB, checking if he exists, if the number is valid etc...
                    // ...

                    // Generate random challenge and send it to client
                    byte[] challenge = RandomChallengeGenerator.generateRandomChallenge(32);
                    String encodedChallenge = Base64.getEncoder().encodeToString(challenge);
                    out.writeObject(encryptStringWithAES(encodedChallenge, sessionKey));
                    out.flush();

                    inputStream = decryptStringWithAES((byte[]) objIn.readObject(), sessionKey);

                    byte[] signedChallenge = Base64.getDecoder().decode((String) ((String) inputStream).split("#")[0]);
                    String userPin = (String) ((String) inputStream).split("#")[1];

                    //TODO verify user's PIN

                    if (checkSignatureValid(ecPublicKey, signedChallenge, challenge)) {
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
        } catch (IOException | ClassNotFoundException e) {
            System.out.println(e.getMessage());
        } catch (UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }

    }

    private static boolean checkSignatureValid(ECPublicKey ecPublicKey, byte[] signature, byte[] originalMessage) throws  NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sVerif = Signature.getInstance("SHA384withECDSA");
        sVerif.initVerify(ecPublicKey);
        sVerif.update(originalMessage);
        return sVerif.verify(signature);
    }
}

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import utils.RandomChallengeGenerator;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
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

public class Bank {
    private static int port = 5000;
    private static final String CERT_PASSWD = "dalgov";

    public static void main(String[] args) {

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

                InputStream in = clientSocket.getInputStream();
                ObjectInputStream objIn = new ObjectInputStream(in);
                ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());

                Object obj = objIn.readObject();

                if (obj instanceof String str) {
                    // Decrypt
                    Cipher cipher2 = Cipher.getInstance("ECIES", "BC");
                    cipher2.init(Cipher.DECRYPT_MODE, privateKey1);
                    byte[] decoded = Base64.getDecoder().decode(((String) obj).getBytes(StandardCharsets.UTF_8));
                    byte[] messageBytes = cipher2.doFinal(decoded);
                    String message = new String(messageBytes);
                    byte[] signature = Base64.getDecoder().decode(message.split("#")[0]);
                    byte[] sessionKey = Base64.getDecoder().decode(message.split("#")[1]);
                    byte[] clientPubKey = Base64.getDecoder().decode(message.split("#")[2]);


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
        }

    }
}

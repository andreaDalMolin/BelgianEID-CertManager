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
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class Server {
    public static void main(String[] args) {
        int port = 5000;

        try {
            ServerSocket serverSocket = new ServerSocket(port);
            System.out.println("Server started on port " + port);
            Security.addProvider(new BouncyCastleProvider());

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected from " + clientSocket.getInetAddress());

                InputStream in = clientSocket.getInputStream();
                ObjectInputStream objIn = new ObjectInputStream(in);
                ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());

                Object obj = objIn.readObject();

                if (obj instanceof String str) {
                    String userAccountNumber = new String(Base64.getDecoder().decode(str.split("#")[1]), StandardCharsets.UTF_8);

                    //Here you do all the shit involved with fecthing the user in the DB, checking if he exists, if the number is valid etc...
                    // ...

                    // Recode public key from bytes
                    byte[] publicKeyBytes = Base64.getDecoder().decode(str.split("#")[0]);
                    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance("EC");
                    ECPublicKey ecPublicKey = (ECPublicKey) keyFactory.generatePublic(keySpec);
                    String publicKey = convertPublicKeyToString(ecPublicKey);

                    // Generate random challenge
                    byte[] challenge = RandomChallengeGenerator.generateRandomChallenge(32);

                    // Create a MessageDigest object for the SHA-256 algorithm
                    sendChallengeToClient(publicKey, challenge, out);

                    // Receive challenge response
                    String response = (String) objIn.readObject();
                    boolean signatureValid = checkSignatureValid(ecPublicKey, response);

                    if (signatureValid) {
                        // send OK
                        out.writeObject("OK");
                        out.flush();
                    } else {
                        // send NOK
                        out.writeObject("NOK");
                        out.flush();
                    }

                } else {
                    System.out.println("Unknown data type received");
                }

                objIn.close();
                in.close();
                clientSocket.close();
            }
        } catch (NoSuchPaddingException | IllegalBlockSizeException | IOException | NoSuchAlgorithmException |
                 InvalidKeySpecException | BadPaddingException | SignatureException | InvalidKeyException |
                 ClassNotFoundException e) {
            System.out.println(e.getMessage());
        }

    }

    private static boolean checkSignatureValid(ECPublicKey ecPublicKey, String response) throws  NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] signedMessage = Base64.getDecoder().decode(response.split("#")[0]);
        byte[] signature = Base64.getDecoder().decode(response.split("#")[1]);

        Signature sVerif = Signature.getInstance("SHA384withECDSA");
        sVerif.initVerify(ecPublicKey);
        sVerif.update(signedMessage);
        return sVerif.verify(signature);
    }

    private static void sendChallengeToClient(String publicKey, byte[] challenge, ObjectOutputStream out) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        // Compute the hash value of the string as a byte array
        byte[] hashBytes = digest.digest(publicKey.getBytes(StandardCharsets.UTF_8));
        // Use the first 16 bytes of the hash as the key for AES encryption
        byte[] keyBytes = Arrays.copyOf(hashBytes, 16);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        // Create a cipher object for AES encryption
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        // Encrypt the plaintext message with AES
        byte[] ciphertextBytes = cipher.doFinal(challenge);

        // Convert the ciphertext to a base64-encoded string for printing or transmission
        String ciphertext = Base64.getEncoder().encodeToString(ciphertextBytes);

        // Print the ciphertext and the key in hexadecimal format
        System.out.println("Ciphertext: " + ciphertext);
        System.out.println("Key: " + bytesToHex(keyBytes));

        out.writeObject(ciphertext);
        out.flush();
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static String convertPublicKeyToString(PublicKey clePublique) {
        byte[] pubKey = clePublique.getEncoded();
        StringBuilder sb = new StringBuilder();

        for (byte b : pubKey) {
            String hexString = String.format("%02x", b);
            sb.append(hexString);
        }

        return sb.toString();
    }
}

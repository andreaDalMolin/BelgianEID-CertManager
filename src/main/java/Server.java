import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class Server {
    public static void main(String[] args) throws IOException, InterruptedException, ClassNotFoundException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, ShortBufferException, InvalidAlgorithmParameterException {
        int port = 5000;
        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("Server started on port " + port);
        Security.addProvider(new BouncyCastleProvider());

        while (true) {
            Socket clientSocket = serverSocket.accept();
            System.out.println("Client connected from " + clientSocket.getInetAddress());

            InputStream in = clientSocket.getInputStream();
            ObjectInputStream objIn = new ObjectInputStream(in);

            Object obj = objIn.readObject();

            if (obj instanceof ECPublicKey clientPubKey) {

//                try {
//                    ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
//                    out.writeObject(bankPubKey);
//                    out.flush();
//
//                    out.writeObject(cipherText);
//                    out.flush();
//                } catch (Exception e) {
//                    e.printStackTrace();
//                }





            } else if (obj instanceof String str) {
                System.out.println("Received pubKey: " + str);

                String plaintext = "This is a secret message!";

                // Create a MessageDigest object for the SHA-256 algorithm
                MessageDigest digest = MessageDigest.getInstance("SHA-256");

                // Compute the hash value of the string as a byte array
                byte[] hashBytes = digest.digest(str.getBytes(StandardCharsets.UTF_8));

                // Use the first 16 bytes of the hash as the key for AES encryption
                byte[] keyBytes = Arrays.copyOf(hashBytes, 16);
                SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

                // Create a cipher object for AES encryption
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, key);

                // Encrypt the plaintext message with AES
                byte[] ciphertextBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

                // Convert the ciphertext to a base64-encoded string for printing or transmission
                String ciphertext = Base64.getEncoder().encodeToString(ciphertextBytes);

                // Print the ciphertext and the key in hexadecimal format
                System.out.println("Ciphertext: " + ciphertext);
                System.out.println("Key: " + bytesToHex(keyBytes));

                ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
                out.writeObject(ciphertext);
                out.flush();
            } else {
                System.out.println("Unknown data type received");
            }

            objIn.close();
            in.close();
            clientSocket.close();
        }
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}

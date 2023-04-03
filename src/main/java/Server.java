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
                System.out.println("Received public key: " + clientPubKey);
                byte[] challenge = RandomChallengeGenerator.generateRandomChallenge(32);

                ECGenParameterSpec spec = new ECGenParameterSpec("secp384r1");
                KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
                gen.initialize(spec, new SecureRandom());
                KeyPair pair = gen.generateKeyPair();
                ECPublicKey bankPubKey = (ECPublicKey) pair.getPublic();
                ECPrivateKey bankPrivKey = (ECPrivateKey) pair.getPrivate();

                String cipherText = encrypt(clientPubKey, bankPubKey, bankPrivKey);

                try {
                    ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
                    out.writeObject(bankPubKey);
                    out.flush();

                    out.writeObject(cipherText);
                    out.flush();
                } catch (Exception e) {
                    e.printStackTrace();
                }


            } else if (obj instanceof String str) {
                System.out.println("Received string: " + str);
            } else {
                System.out.println("Unknown data type received");
            }

            objIn.close();
            in.close();
            clientSocket.close();
        }
    }

    private static String encrypt(ECPublicKey publicKey, ECPublicKey bankPubKey, ECPrivateKey bankPrivKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        // 1. Generate the pre-master shared secret
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
        ka.init(bankPrivKey);
        ka.doPhase(bankPubKey, true);
        byte[] sharedSecret = ka.generateSecret();

        // 2. (Optional) Hash the shared secret.
        // 		Alternatively, you don't need to hash it.
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(sharedSecret);
        byte[] digest = messageDigest.digest();

        // 3. (Optional) Split up hashed shared secret into an initialization vector and a session key
        // 		Alternatively, you can just use the shared secret as the session key and not use an iv.
        int digestLength = digest.length;
        byte[] iv = Arrays.copyOfRange(digest, 0, (digestLength + 1)/2);
        byte[] sessionKey = Arrays.copyOfRange(digest, (digestLength + 1)/2, digestLength);

        // 4. Create a secret key from the session key and initialize a cipher with the secret key
        SecretKey secretKey = new SecretKeySpec(sessionKey, 0, sessionKey.length, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        // 5. Encrypt whatever message you want to send
        String encryptMe = "Hello world!";
        byte[] encryptMeBytes = encryptMe.getBytes(StandardCharsets.UTF_8);
        byte[] cipherText = cipher.doFinal(encryptMeBytes);
        String cipherString = Base64.getEncoder().encodeToString(cipherText);
        return cipherString;
    }
}

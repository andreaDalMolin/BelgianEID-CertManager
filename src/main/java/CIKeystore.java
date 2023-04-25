import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;

public class CIKeystore
{
    // Choose your certificate here !
    private static final String aliasClesAuthKeystore = "Authentication";
    private static final String aliasClesSignKeystore = "Signature";
    private static final int SERVER_PORT = 5000;
    private static final String SERVER_IP = "127.0.0.1";
    public static void main(String[] args) {
        Security.setProperty("crypto.policy", "unlimited");
        Security.addProvider(new BouncyCastleProvider());

        // PKCS11 config path
        String configPath = "C:\\tmp\\pkcs11.cfg";
        Provider pkcs11Provider = Security.getProvider("SunPKCS11");
        pkcs11Provider = pkcs11Provider.configure(configPath);
        Security.addProvider(pkcs11Provider);
        KeyStore CartIdKeystore;
        try {
            // 1. Keystore creation
            CartIdKeystore = KeyStore.getInstance("PKCS11");
            CartIdKeystore.load(null, null);
            System.out.println("*** KeyStore PKCS11 created ***");

            // 2. Private key
            PrivateKey privateKey;
            privateKey = (PrivateKey) CartIdKeystore.getKey(aliasClesSignKeystore, null);

            // 3. Certificate
            X509Certificate cert = (X509Certificate)CartIdKeystore.getCertificate(aliasClesAuthKeystore);
//            System.out.println(cert);

            var chain = CartIdKeystore.getCertificateChain(aliasClesAuthKeystore);

            PublicKey publicKey = cert.getPublicKey();

            getBankAuthorization(publicKey, privateKey);
        }
        catch (KeyStoreException | UnrecoverableKeyException | IOException |
               NoSuchAlgorithmException | CertificateException ex) {
            System.out.println(ex.getMessage());
        }
    }

    private static void getBankAuthorization(PublicKey clePublique, PrivateKey clePrivee) {
        try {
            // Connect to the server
            Socket socket = new Socket(SERVER_IP, SERVER_PORT);

            // Get user account number and pincode. These will be user input later
            String number = "1111";
            String pincode = "1111";

            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            String stringPubKey = convertPublicKeyToString(clePublique);

            // Send the client's public key to the server
            String pubKeyAndAccNum = Base64.getEncoder().encodeToString(clePublique.getEncoded())
                    + "#"
                    + Base64.getEncoder().encodeToString(number.getBytes(StandardCharsets.UTF_8));
            out.writeObject(pubKeyAndAccNum);
            out.flush();

            // Receive bank's challenge response
            InputStream in = socket.getInputStream();
            ObjectInputStream objIn = new ObjectInputStream(in);
            Object obj = objIn.readObject();
            String encryptedChallenge = (String) obj;

            // Decrypting the challenge
            decryptChallengeAndSign(clePrivee, pincode, out, stringPubKey, encryptedChallenge);

            // Receive bank's authorization
            obj = objIn.readObject();
            if (obj.equals("OK")) {
                System.out.println("Great ! You're authenticated !");
            } else {
                System.out.println("Oh no ! Anyway...");
            }

            // Clean up
            in.close();
            out.close();
            socket.close();

        } catch (ClassNotFoundException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException
                 | InvalidKeyException | SignatureException
                 | IOException | NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        }

    }

    private static void decryptChallengeAndSign(PrivateKey clePrivee, String pincode, ObjectOutputStream out, String stringPubKey, String encrypted) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, SignatureException, NoSuchProviderException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(stringPubKey.getBytes(StandardCharsets.UTF_8));
        byte[] keyBytes = Arrays.copyOf(hashBytes, 16);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plaintextBytes = cipher.doFinal(Base64.getDecoder().decode(encrypted));

        Cipher cipher2 = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
        cipher2.init(Cipher.DECRYPT_MODE, clePrivee);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        outputStream.write(plaintextBytes);
        outputStream.write(("#"+ pincode).getBytes(StandardCharsets.UTF_8));
        byte[] preSignedMessage = outputStream.toByteArray();

        Signature s = Signature.getInstance("SHA384withECDSA");
        s.initSign(clePrivee);
        s.update(preSignedMessage);
        byte[] signatureBytes = s.sign();
        String signature = Base64.getEncoder().encodeToString(signatureBytes);
        String signedChallenge = Base64.getEncoder().encodeToString(preSignedMessage);

        out.writeObject(signedChallenge+"#"+signature);
        out.flush();
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
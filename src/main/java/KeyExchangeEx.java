import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;

public class KeyExchangeEx {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        Security.addProvider(new BouncyCastleProvider());
        ECGenParameterSpec specA = new ECGenParameterSpec("secp384r1");
        KeyPairGenerator genA = KeyPairGenerator.getInstance("ECDH", "BC");
        genA.initialize(specA, new SecureRandom());
        KeyPair pairA = genA.generateKeyPair();
        ECPublicKey partyAPubKey = (ECPublicKey) pairA.getPublic();
        ECPrivateKey partyAPrivKey = (ECPrivateKey) pairA.getPrivate();

        ECGenParameterSpec specB = new ECGenParameterSpec("secp384r1");
        KeyPairGenerator genB = KeyPairGenerator.getInstance("ECDH", "BC");
        genB.initialize(specB, new SecureRandom());
        KeyPair pairB = genB.generateKeyPair();
        ECPublicKey partyBPubKey = (ECPublicKey) pairB.getPublic();
        ECPrivateKey partyBPrivKey = (ECPrivateKey) pairB.getPrivate();

        // 1. Generate the pre-master shared secret
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
        ka.init(partyAPrivKey);
        ka.doPhase(partyBPubKey, true);
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

        // Same stuff as before...
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        // 5. Encrypt whatever message you want to send
        String decryptMe = cipherString; // Message received from Party A
        byte[] decryptMeBytes = Base64.getDecoder().decode(decryptMe);
        byte[] textBytes = cipher.doFinal(decryptMeBytes);
        String originalText = new String(textBytes);
        System.out.println(originalText);
    }
}

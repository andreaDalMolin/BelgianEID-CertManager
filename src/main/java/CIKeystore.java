import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import static java.util.Arrays.copyOfRange;

public class CIKeystore
{
    private static ByteArrayInputStream bais = new ByteArrayInputStream
            ("name = beid\nlibrary = c:\\WINDOWS\\system32\\beidpkcs11.dll".getBytes());
    private static final String aliasClesSignatureKeystore = "Signature";
    // L'alias s'appelle obligatoirement ainsi !
    public static void main(String[] args)
    {

        Security.setProperty("crypto.policy", "unlimited");

        //Le chemin de configuration du PKCS11
        String configName = "C:\\tmp\\pkcs11.cfg";
        Provider pkcs11Provider = Security.getProvider("SunPKCS11");
        pkcs11Provider = pkcs11Provider.configure(configName);
        Security.addProvider(pkcs11Provider);
        KeyStore CartIdKeystore = null;
        try
        {
            // 1. Création du Keystore
            CartIdKeystore = KeyStore.getInstance("PKCS11");
            CartIdKeystore.load(null, null); // pas de fichier keystore à lire
            System.out.println("*** KeyStore PKCS11 créé ***");
            // 2. Signature
            PrivateKey clePrivee;
            clePrivee = (PrivateKey) CartIdKeystore.getKey(
                    aliasClesSignatureKeystore, null); // pas de password
            Signature s = Signature.getInstance("SHA384withECDSA");
            s.initSign(clePrivee);
            System.out.println("here");
            String message = "Mot de passe du jour : KlixPataclix";
            s.update(message.getBytes());
            byte[] signature = s.sign();
            // 3. Certificat associé
            X509Certificate cert = (X509Certificate)CartIdKeystore.getCertificate(
                    aliasClesSignatureKeystore);
            System.out.println(cert);  // OU : affiche(cert);
            PublicKey clePublique = cert.getPublicKey();
            // 4. Vérification de la signature
            Signature sVerif = Signature.getInstance("SHA384withECDSA");
            sVerif.initVerify(clePublique);
            sVerif.update(message.getBytes());
            boolean signatureValide = sVerif.verify(signature);
            /**System.out.println("*** Signature générée pour '" + message + "' = "+
                    new String(signature)+" ***");
            if(signatureValide)System.out.println("*** La signature est valide ***");
            else System.out.println("*** La signature n'est pas valide ***");
            //
            System.out.println("-------------------------------------------------\n\n");

            byte[] myKey = clePublique.getEncoded();
            StringBuilder sb = new StringBuilder();

            for (byte b : myKey) {
                String hexString = String.format("%02x", b);
                sb.append(hexString);
            }

            String result = sb.toString();
            System.out.println("FULL KEY : " + result);
            System.out.println("SHORT KEY : " + result.substring(46));
**/

            // Connect to the server
            Socket socket = new Socket("localhost", 5000);

            // Generate the client's key pair
            /**KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp384r1");
            keyGen.initialize(ecSpec);
            KeyPair keyPair = keyGen.generateKeyPair();
            ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
            ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();**/

            // Send the client's public key to the server
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            out.writeObject(clePublique);
            out.flush();

            // Receive the server's public key
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            byte[] serverPublicKeyBytes = (byte[]) in.readObject();
            X509EncodedKeySpec ks = new X509EncodedKeySpec(serverPublicKeyBytes);
            KeyFactory kf = KeyFactory.getInstance("EC");
            ECPublicKey serverPublicKey = (ECPublicKey) kf.generatePublic(ks);

            // Generate the shared secret using the client's private key and the server's public key
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(clePrivee);
            ka.doPhase(serverPublicKey, true);
            byte[] sharedSecret = ka.generateSecret();

            // Hash the shared secret using SHA-256
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(sharedSecret);

            // Split the hash into an initialization vector and a session key
            byte[] iv = Arrays.copyOfRange(hash, 0, 16);
            byte[] sessionKey = Arrays.copyOfRange(hash, 16, 32);

            // Create a secret key from the session key and initialize a cipher with the secret key
            SecretKey secretKey = new SecretKeySpec(sessionKey, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            // Send an encrypted message to the server
            String myMessage = "Hello, server!";
            byte[] encryptedMessage = cipher.doFinal(myMessage.getBytes(StandardCharsets.UTF_8));
            out.writeObject(encryptedMessage);
            out.flush();

            // Receive and decrypt a message from the server
            byte[] encryptedResponse = (byte[]) in.readObject();
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            byte[] decryptedResponse = cipher.doFinal(encryptedResponse);
            String response = new String(decryptedResponse, StandardCharsets.UTF_8);
            System.out.println("Server said: " + response);

            // Clean up
            in.close();
            out.close();
            socket.close();

        }
        catch (KeyStoreException ex) {
            System.out.println("err KeyStoreException");
            System.out.println(ex.getMessage());
        }
        catch (UnrecoverableKeyException ex) {
            System.out.println("err UnrecoverableKeyException");
            System.out.println(ex.getMessage());
        }
        catch (InvalidKeyException ex) {
            System.out.println("err InvalidKeyException");
            System.out.println(ex.getMessage());
        }
        catch (SignatureException ex) {
            System.out.println("err SignatureException");
            System.out.println(ex.getMessage());
        }
        catch (IOException ex) {
            System.out.println("err IOException");
            System.out.println(ex.getMessage());
        }
        catch (NoSuchAlgorithmException ex) {
            System.out.println("err NoSuchAlgorithmException");
            System.out.println(ex.getMessage());
        }
        catch (CertificateException ex) {
            System.out.println("err CertificateException");
            System.out.println(ex.getMessage());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}


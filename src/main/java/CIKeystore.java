import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
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
    private static final String aliasClesSignatureKeystore = "Authentication";
    // L'alias s'appelle obligatoirement ainsi !
    public static void main(String[] args)
    {

        Security.setProperty("crypto.policy", "unlimited");
        Security.addProvider(new BouncyCastleProvider());

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

            extracted(clePrivee, clePublique);

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

    private static void extracted(PrivateKey clePrivee, PublicKey clePublique) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
        // Connect to the server
        Socket socket = new Socket("localhost", 5000);

        byte[] myKey = clePublique.getEncoded();
        StringBuilder sb = new StringBuilder();

        for (byte b : myKey) {
            String hexString = String.format("%02x", b);
            sb.append(hexString);
        }

        String result = sb.toString();
        System.out.println("FULL KEY : " + result);
        System.out.println("SHORT KEY : " + result.substring(46));

        // Send the client's public key to the server
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        out.writeObject(result);
        out.flush();

        InputStream in = socket.getInputStream();
        ObjectInputStream objIn = new ObjectInputStream(in);

        Object obj = objIn.readObject();
        String encrypted = (String) obj;

        String stringToHash = "Hello, World!";

        // Create a MessageDigest object for the SHA-256 algorithm
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        // Compute the hash value of the string as a byte array
        byte[] hashBytes = digest.digest(result.getBytes(StandardCharsets.UTF_8));

        // Use the first 16 bytes of the hash as the key for AES decryption
        byte[] keyBytes = Arrays.copyOf(hashBytes, 16);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        // Create a cipher object for AES decryption
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);

        // Decrypt the ciphertext message with AES
        byte[] plaintextBytes = cipher.doFinal(Base64.getDecoder().decode(encrypted));
        String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);

        // Print the plaintext message
        System.out.println("Plaintext: " + plaintext);

        // Print the plaintext message
        System.out.println("Plaintext: " + plaintext);

        // Clean up
        in.close();
        out.close();
        socket.close();
    }


}


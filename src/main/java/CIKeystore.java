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

        // Send the client's public key to the server
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        out.writeObject(clePublique);
        out.flush();

        InputStream in = socket.getInputStream();
        ObjectInputStream objIn = new ObjectInputStream(in);

        Object obj = objIn.readObject();

        // Receive the server's public key

        if (obj instanceof ECPublicKey bankPubKey) {
            System.out.println("Received bank's public key: " + bankPubKey);

            // 1. Generate the pre-master shared secret
            KeyAgreement ka = KeyAgreement.getInstance("EC", "BC");
            ka.init(clePrivee);
            ka.doPhase(clePublique, true);
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
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);



            // 5. Encrypt whatever message you want to send
//            String decryptMe = cipherString; // Message received from Party A
//            byte[] decryptMeBytes = Base64.getDecoder().decode(decryptMe);
//            byte[] textBytes = cipher.doFinal(decryptMeBytes);
//            String originalText = new String(textBytes);

        }  else if (obj instanceof String str) {
            System.out.println("Received string: " + str);
        }

//        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
//        byte[] serverPublicKeyBytes = (byte[]) in.readObject();
//        X509EncodedKeySpec ks = new X509EncodedKeySpec(serverPublicKeyBytes);
//        KeyFactory kf = KeyFactory.getInstance("EC");
//        ECPublicKey serverPublicKey = (ECPublicKey) kf.generatePublic(ks);



        // Clean up
        in.close();
        out.close();
        socket.close();
    }


}


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class CIKeystore
{
    private static ByteArrayInputStream bais = new ByteArrayInputStream
            ("name = beid\nlibrary = c:\\WINDOWS\\system32\\beidpkcs11.dll".getBytes());
    private static final String aliasClesSignatureKeystore = "Signature";
    // L'alias s'appelle obligatoirement ainsi !
    public static void main(String[] args)
    {
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
            Signature sVerif = Signature.getInstance("SHA1withRSA");
            sVerif.initVerify(clePublique);
            sVerif.update(message.getBytes());
            boolean signatureValide = sVerif.verify(signature);
            System.out.println("*** Signature générée pour '" + message + "' = "+
                    new String(signature)+" ***");
            if(signatureValide)System.out.println("*** La signature est valide ***");
            else System.out.println("*** La signature n'est pas valide ***");
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
        }
    }
}


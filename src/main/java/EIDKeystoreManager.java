import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class EIDKeystoreManager {
    private static final String configPath = "C:\\tmp\\pkcs11.cfg";
    private static final String aliasClesAuthKeystore = "Authentication";
    private KeyStore keystore;

    public EIDKeystoreManager() {
        Security.setProperty("crypto.policy", "unlimited");
        Security.addProvider(new BouncyCastleProvider());

        Provider pkcs11Provider = Security.getProvider("SunPKCS11");
        pkcs11Provider = pkcs11Provider.configure(configPath);
        Security.addProvider(pkcs11Provider);

        try {
            keystore = KeyStore.getInstance("PKCS11");
            keystore.load(null, null);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException ex) {
            System.out.println(ex.getMessage());
        }
    }

    public X509Certificate getCertificate() {
        try {
            return (X509Certificate)keystore.getCertificate(aliasClesAuthKeystore);
        } catch (KeyStoreException ex) {
            System.out.println(ex.getMessage());
            return null;
        }
    }

    public Certificate[] getCertificateChain() {
        try {
            return keystore.getCertificateChain(aliasClesAuthKeystore);
        } catch (KeyStoreException ex) {
            System.out.println(ex.getMessage());
            return null;
        }
    }

    public PublicKey getPublicKey() {
        try {
            return getCertificate().getPublicKey();
        } catch (NullPointerException ex) {
            System.out.println("Certificate not found");
            return null;
        }
    }

    public PrivateKey getPrivateKey() {
        try {
            return (PrivateKey) keystore.getKey(aliasClesAuthKeystore, null);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {
            System.out.println(ex.getMessage());
            return null;
        }
    }
}

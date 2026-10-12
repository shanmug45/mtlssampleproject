package dev.samplemtls.common;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public final class TlsContexts {
    private TlsContexts() {
    }

    public static SSLContext create(byte[] identityStore, char[] identityPassword,
                                    byte[] trustStore, char[] trustPassword)
            throws GeneralSecurityException, IOException {
        KeyStore identity = load(identityStore, identityPassword);
        KeyStore trust = load(trustStore, trustPassword);
        if (!hasPrivateKey(identity)) {
            throw new GeneralSecurityException("Identity store must contain a private key and certificate.");
        }
        if (!hasCertificate(trust)) {
            throw new GeneralSecurityException("Truststore must contain at least one trusted certificate.");
        }

        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(identity, identityPassword);

        TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        trustManagers.init(trust);

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagers.getKeyManagers(), trustManagers.getTrustManagers(), null);
        return context;
    }

    private static KeyStore load(byte[] data, char[] password)
            throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new ByteArrayInputStream(data), password);
        return keyStore;
    }

    private static boolean hasPrivateKey(KeyStore keyStore) throws GeneralSecurityException {
        var aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            if (keyStore.isKeyEntry(aliases.nextElement())) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasCertificate(KeyStore keyStore) throws GeneralSecurityException {
        var aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            if (keyStore.getCertificate(aliases.nextElement()) != null) {
                return true;
            }
        }
        return false;
    }
}

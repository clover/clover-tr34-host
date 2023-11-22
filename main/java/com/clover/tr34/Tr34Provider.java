package com.clover.tr34;

import org.bouncycastle.jcajce.provider.asymmetric.RSA;
import org.bouncycastle.jcajce.provider.asymmetric.X509;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.AlgorithmParametersSpi;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.DigestSignatureSpi;
import org.bouncycastle.jcajce.provider.asymmetric.x509.KeyFactory;
import org.bouncycastle.jcajce.provider.symmetric.AES;
import org.bouncycastle.jcajce.provider.symmetric.DES;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;

import java.security.Provider;

/**
 * Helper class to get a Java security provider with functionality necessary for TR-34.
 */
public final class Tr34Provider {

    static class Tr34BC extends BCJcaJceHelper {
        public Provider getProvider() {
            return provider;
        }
    }

    public static final Provider PROVIDER = new Tr34BC().getProvider();

    static {
        if (PROVIDER.getName() == null) {
            // Impossible
            proguardWorkaround();
        }
    }

    /**
     * This code isn't intended to run, instead it exists to trick proguard into keeping classes
     * that otherwise don't appear to be used. Java security providers rely heavily on reflection,
     * but proguard is unaware of classes referenced via reflection and strips them. Proguard rules
     * could be used but getting those rules to propagate from one project to another isn't easy.
     */
    private static void proguardWorkaround() {
        try {
            new X509.Mappings().configure(null);
            new RSA.Mappings().configure(null);
            new AES.Mappings().configure(null);
            new DES.Mappings().configure(null);
            new CertificateFactory().engineGenerateCertificate(null);
            new CertificateFactory().engineGenerateCertificates(null);
            new KeyFactory() {
                public void keepStuff() throws Exception {
                    engineGeneratePrivate(null);
                    engineGeneratePublic(null);
                }
            }.keepStuff();
            new AES.CBC();
            new DES.CBC();
            new RSA();
            new AlgorithmParametersSpi.PSS();
            new AlgorithmParametersSpi.OAEP();
            new DigestSignatureSpi.SHA256();
        } catch (Exception e) {
            throw new RuntimeException("Unexpected executed code that should never run", e);
        }
    }

}

package com.clover.tr34;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/**
 * Helpful cryptography related utility methods.
 */
public final class Tr34CryptoUtils {

    private Tr34CryptoUtils() { }

    public static PrivateKey parsePrivateKey(String pem) {
        if (pem.contains("BEGIN RSA PRIVATE KEY")) {
            return parsePrivateKeyFromOpenSSL(pem);
        } else if (pem.contains("BEGIN PRIVATE KEY")) {
            return parsePrivateKeyFromPKCS8(pem);
        } else {
            throw new IllegalArgumentException();
        }
    }

    private static PrivateKey parsePrivateKeyFromOpenSSL(String pem) {
        try {
            byte[] der = pemToDer(pem);
            RSAPrivateCrtKeyParameters priv = (RSAPrivateCrtKeyParameters) OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(der);
            RSAPrivateKeySpec spec = new RSAPrivateCrtKeySpec(priv.getModulus(),
                    priv.getPublicExponent(), priv.getExponent(), priv.getP(), priv.getQ(), priv.getDP(), priv.getDQ(),
                    priv.getQInv());
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePrivate(spec);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static PrivateKey parsePrivateKeyFromPKCS8(String pem) {
        try {
            byte[] der = pemToDer(pem);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(der);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static PublicKey parsePublicKey(String pem) {
        try {
            byte[] der = pemToDer(pem);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(der);
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static X509Certificate parseCert(String pem) {
        return parseCert(pem.getBytes());
    }

    public static X509Certificate parseCert(byte[] der) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", Tr34Provider.PROVIDER);
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static CertPath createCertPath(List<X509Certificate> chain) {
        try {
            return CertificateFactory.getInstance("X.509").generateCertPath(chain);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static void verifyCertificateChain(List<X509Certificate> chain, X509Certificate root) {
        // If the root is included in the chain, remove it
        int lastIndex = chain.size() - 1;
        X509Certificate highestChainCert = chain.get(lastIndex);
        if (highestChainCert.getPublicKey().equals(root.getPublicKey())) {
            chain = new LinkedList<>(chain);
            chain.remove(lastIndex);
        }

        TrustAnchor ta = new TrustAnchor(root, null);
        new Tr34CertValidator(ta)
                .withProvider(Tr34Provider.PROVIDER)
                .withoutDateValidation()
                .validate(createCertPath(chain));
    }

    public static void verifyCertificateChain(X509Certificate leafCert, List<X509Certificate> caList, X509Certificate root) {
        LinkedList<X509Certificate> chain = new LinkedList<>(caList);
        chain.addFirst(leafCert);
        verifyCertificateChain(chain, root);
    }

    public static void verifyCertificateChain(X509Certificate[] chain, X509Certificate root) {
        verifyCertificateChain(Arrays.asList(chain), root);
    }

    public static void verifyCrl(X509CRLHolder crl, X509Certificate crlSigner) {
        try {
            ContentVerifierProvider cvp = new JcaContentVerifierProviderBuilder()
                    .setProvider(Tr34Provider.PROVIDER).build(crlSigner.getPublicKey());
            if (!crl.isSignatureValid(cvp)) {
                throw new SecurityException("CRL verification failed");
            }
        } catch (SecurityException e) {
            throw e;
        } catch (Exception e) {
            throw new SecurityException("CRL verification failed", e);
        }
    }

    public static byte[] pemToDer(String pem) {
        try {
            return new PemReader(new StringReader(pem)).readPemObject().getContent();
        } catch (IOException e) {
            throw new Tr34Exception(e);
        }
    }

    public static ASN1Primitive decodeToAsn1(Object encoded) {
        try {
            if (encoded instanceof String) {
                return ASN1Primitive.fromByteArray(pemToDer((String) encoded));
            } else if (encoded instanceof byte[]) {
                return ASN1Primitive.fromByteArray((byte[]) encoded);
            } else if (encoded instanceof ASN1Primitive) {
                return (ASN1Primitive) encoded;
            }
        } catch (IOException e) {
            throw new Tr34Exception(e);
        }

        throw new Tr34Exception("Unable to decode instances of " + encoded.getClass());
    }

    public static Date createHoursFromNowDate(long hoursFromNow) {
        long secs = System.currentTimeMillis() / 1000;
        return new Date((secs + (hoursFromNow * 60 * 60)) * 1000);
    }

    public static X509CRL createCRL(PrivateKey caKey, X509Certificate caCert, List<Tr34KdhRevocation> revocationList,
                                    Date crlNextUpdate) {
        try {
            final String sigAlg = "SHA256withRSA";

            X509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(caCert.getSubjectX500Principal(),
                    createHoursFromNowDate(0)).setNextUpdate(crlNextUpdate);

            ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                    .setProvider(Tr34Provider.PROVIDER).build(caKey);

            for (Tr34KdhRevocation cr : revocationList) {
                crlGen.addCRLEntry(cr.serial, cr.revocationDate, cr.revocationReason.ordinal());
            }

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509CRL) cf.generateCRL(new ByteArrayInputStream(crlGen.build(signer).getEncoded()));
        } catch (Exception e) {
            throw new Tr34Exception(e);
        }
    }

    public static final Selector<X509CertificateHolder> ALL_CERT_SELECTOR = new Selector<X509CertificateHolder>() {
        @Override
        public boolean match(X509CertificateHolder obj) {
            return true;
        }

        @Override
        public Object clone() {
            throw new UnsupportedOperationException();
        }
    };

    public static final Selector<X509CRLHolder> ALL_CRL_SELECTOR = new Selector<X509CRLHolder>() {
        @Override
        public boolean match(X509CRLHolder obj) {
            return true;
        }

        @Override
        public Object clone() {
            throw new UnsupportedOperationException();
        }
    };

}

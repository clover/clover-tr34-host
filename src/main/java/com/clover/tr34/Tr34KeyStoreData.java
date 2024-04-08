package com.clover.tr34;

import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * Holds the identifying certificates and keys for one KDH operator and one KRD vendor. When the
 * KDH and KRD are operated by different organizations the private key material for only one
 * organization will be available, other values will be null.
 */
public abstract class Tr34KeyStoreData {

    private static void verifyCertKeyMatch(X509Certificate cert, PrivateKey privateKey) {
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
        RSAPublicKey certPublicKey = (RSAPublicKey) cert.getPublicKey();

        if (!rsaPrivateKey.getModulus().equals(certPublicKey.getModulus())) {
            throw new IllegalStateException("Cert and key mismatch");
        }

        boolean keyPairMatches;

        try {
            byte[] challenge = "HelloWorld".getBytes();

            Signature sig = Signature.getInstance("NONEwithRSA");
            sig.initSign(privateKey);
            sig.update(challenge);
            byte[] signature = sig.sign();

            sig.initVerify(cert.getPublicKey());
            sig.update(challenge);

            keyPairMatches = sig.verify(signature);
        } catch (Exception e) {
            throw new IllegalArgumentException("Bad private key", e);
        }

        if (!keyPairMatches) {
            throw new IllegalArgumentException("Cert and key mismatch");
        }
    }

    /**
     * Subclasses are encouraged to invoke this at the end of construction to ensure validity.
     */
    protected void verifyKdh() {
        List<X509Certificate> kdhChain = new LinkedList<>();
        kdhChain.add(getKdhCert());
        kdhChain.addAll(getKdhIssuerChain());
        Tr34CryptoUtils.verifyCertificateChain(kdhChain, getRootCert());

        verifyCertKeyMatch(getKdhCert(), getKdhKeyStoreData().privateKey);
    }

    /**
     * Subclasses are encouraged to invoke this at the end of construction to ensure validity.
     *
     * @param higherIntermediates Optional ordered list of certificates between the KRD CA and the root.
     */
    protected void verifyKrdCa(X509Certificate... higherIntermediates) {
        List<X509Certificate> krdCaChain = new LinkedList<>();
        krdCaChain.add(getKrdCaCert());
        if (higherIntermediates != null) {
            Collections.addAll(krdCaChain, higherIntermediates);
        }
        Tr34CryptoUtils.verifyCertificateChain(krdCaChain, getRootCert());

        verifyCertKeyMatch(getKrdCaCert(), getKrdCaKeyStoreData().privateKey);
    }

    /**
     * Per TR-34 both KRD and KDH must form a trusted relationship with the root CA.
     */
    public abstract X509Certificate getRootCert();

    public abstract X509Certificate getKdhCert();

    public abstract X509Certificate getKrdCaCert();

    public abstract Tr34ScdKeyStoreData getKdhKeyStoreData();

    public abstract Tr34ScdKeyStoreData getKdhCaKeyStoreData();

    public abstract Tr34ScdKeyStoreData getKrdCaKeyStoreData();

    public abstract List<Tr34KdhRevocation> getKdhRevocationList();

    /**
     * Return an ordered list of intermediate certificates for the KDH certificate starting with
     * the direct KDH CA and ending with the root certificate.
     */
    public abstract List<X509Certificate> getKdhIssuerChain();

    public abstract int nextCrlUpdateDays();

}

package com.clover.tr34;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;


/**
 * Generates TR-34 tokens using the provided {@link Tr34KeyStoreData}.
 * Contains internal helpers for verifying and decrypting tokens as well.
 */
public final class Tr34TokenFactory {

    private final Tr34KeyStoreData tr34KeyStoreData;

    public Tr34TokenFactory(Tr34KeyStoreData keyStoreData) {
        this.tr34KeyStoreData = keyStoreData;
    }

    /**
     * Generates a KDH Credential Token for binding a KRD to a KDH or updating the CRL for a bound KRD.
     */
    public Tr34KdhCredentialToken generateKdhCredentialToken(List<Tr34KdhRevocation> revocationList,
                                                             Date crlNextUpdate) {
        X509CRL crl = Tr34CryptoUtils.createCRL(tr34KeyStoreData.getKdhCaKeyStoreData().privateKey,
                tr34KeyStoreData.getKdhCaKeyStoreData().cert, revocationList, crlNextUpdate);
        return Tr34KdhCredentialToken.create(tr34KeyStoreData.getKdhCert(), crl);
    }

    /**
     * Generates a KDH Unbind Token.
     */
    public Tr34KdhUnbindToken generateKdhUnbindToken(Tr34RandomToken randomToken, List<X509Certificate> krdChain) {
        Tr34CryptoUtils.verifyCertificateChain(krdChain, tr34KeyStoreData.getRootCert());

        return Tr34KdhUnbindToken.create(randomToken, krdChain.get(0), tr34KeyStoreData.getKdhKeyStoreData());
    }

    /**
     * Generates a KDH Rebind Token.
     */
    public Tr34KdhRebindToken generateKdhRebindToken(Tr34RandomToken randomToken, List<X509Certificate> krdChain,
                                                     X509Certificate newKdhCert) {
        Tr34CryptoUtils.verifyCertificateChain(krdChain, tr34KeyStoreData.getRootCert());

        return Tr34KdhRebindToken.create(randomToken, krdChain.get(0), newKdhCert,
                tr34KeyStoreData.getKdhKeyStoreData());
    }

    /**
     * Generates a Higher Level Authority Unbind Token.
     */
    public Tr34CaUnbindToken generateCaUnbindToken(List<X509Certificate> krdChain, X509Certificate currentKdhCert) {
        Tr34CryptoUtils.verifyCertificateChain(krdChain, tr34KeyStoreData.getRootCert());

        return Tr34CaUnbindToken.create(krdChain.get(0), currentKdhCert, tr34KeyStoreData.getKrdCaKeyStoreData());
    }

    /**
     * Generates a Higher Level Authority Rebind Token.
     */
    public Tr34CaRebindToken generateCaRebindToken(List<X509Certificate> krdChain, X509Certificate currentKdhCert,
                                                   X509Certificate newKdhCert) {
        Tr34CryptoUtils.verifyCertificateChain(krdChain, tr34KeyStoreData.getRootCert());

        return Tr34CaRebindToken.create(krdChain.get(0), currentKdhCert, newKdhCert,
                tr34KeyStoreData.getKrdCaKeyStoreData());
    }

    /**
     * Generates a two-pass key token for the KRD corresponding to the KRD cert parameter.
     * This method currently only supports two types of keys: 128-bit AES or 192-bit TDES.
     * <p>
     * This functions operates on clear symmetric keys, it should not be used in production outside
     * an HSM.
     * <p>
     * This method does not verify the KRD certificate! The caller must verify the certificate first!
     */
    public Tr34TwoPassKeyToken generateTwoPassKeyToken(Tr34RandomToken randomToken, List<X509Certificate> krdChain,
                                                       byte[] symmetricKey) {
        Tr34CryptoUtils.verifyCertificateChain(krdChain, tr34KeyStoreData.getRootCert());

        String header;
        if (symmetricKey.length == 16) {
            header = Tr34KeyBlockHeaderFactory.createHeaderForAesTr31Kbk();
        } else if (symmetricKey.length == 24) {
            header = Tr34KeyBlockHeaderFactory.createHeaderForTdesTr31Kbk();
        } else {
            throw new Tr34Exception("Only 128 bit AES or 192 TDES keys are supported");
        }

        X509Certificate kdhCert = tr34KeyStoreData.getKdhCert();

        // Create the key block
        Tr34KeyBlock keyBlock = Tr34KeyBlock.create(header, symmetricKey, kdhCert);

        // Generate a response
        return Tr34TwoPassKeyToken.create(randomToken, krdChain.get(0), keyBlock,
                tr34KeyStoreData.getKdhKeyStoreData());
    }

}

package com.clover.tr34;

import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.SignerInformationVerifierProvider;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;

import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
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
    public Tr34KdhCredentialToken generateKdhCredentialToken(List<Tr34KdhRevocation> revocationList, Date crlNextUpdate) {
        X509CRL crl = Tr34CryptoUtils.createCRL(tr34KeyStoreData.getKdhCaKeyStoreData().privateKey,
                tr34KeyStoreData.getKdhCaKeyStoreData().cert, revocationList, crlNextUpdate);
        return Tr34KdhCredentialToken.create(tr34KeyStoreData.getKdhCert(), crl);
    }

    /**
     * Generates a KDH Unbind Token.
     */
    public Tr34KdhUnbindToken generateKdhUnbindToken(Tr34RandomToken randomToken, X509Certificate krdCert) {
        return Tr34KdhUnbindToken.create(randomToken, krdCert, tr34KeyStoreData.getKdhKeyStoreData());
    }

    /**
     * Generates a KDH Rebind Token.
     */
    public Tr34KdhRebindToken generateKdhRebindToken(Tr34RandomToken randomToken, X509Certificate krdCert, X509Certificate newKdhCert) {
        return Tr34KdhRebindToken.create(randomToken, krdCert, newKdhCert, tr34KeyStoreData.getKdhKeyStoreData());
    }

    /**
     * Generates a Higher Level Authority Unbind Token.
     */
    public Tr34CaUnbindToken generateCaUnbindToken(X509Certificate krdCert, X509Certificate currentKdhCert) {
        return Tr34CaUnbindToken.create(krdCert, currentKdhCert, tr34KeyStoreData.getKrdCaKeyStoreData());
    }

    /**
     * Generates a Higher Level Authority Rebind Token.
     */
    public Tr34CaRebindToken generateCaRebindToken(X509Certificate krdCert, X509Certificate currentKdhCert, X509Certificate newKdhCert) {
        return Tr34CaRebindToken.create(krdCert, currentKdhCert, newKdhCert, tr34KeyStoreData.getKrdCaKeyStoreData());
    }

    /**
     * Generates a two-pass key token for the KRD corresponding to the KRD cert parameter.
     * This method currently only supports two types of keys: 128-bit AES or 192-bit TDES.
     */
    public Tr34TwoPassKeyToken generateTwoPassKeyToken(Tr34RandomToken randomToken, X509Certificate krdCert, byte[] symmetricKey) {
        String header;
        if (symmetricKey.length == 16) {
            header = Tr34KeyBlockHeaderFactory.createHeaderForAesTr31Kbk();
        } else if (symmetricKey.length == 24) {
            header = Tr34KeyBlockHeaderFactory.createHeaderForTdesTr31Kbk();
        } else {
            throw new Tr34Exception("Only 128 bit AES or 192 TDES keys are supported");
        }

        X509Certificate tr34RootCert = tr34KeyStoreData.getRootCert();
        X509Certificate krdCaCert = tr34KeyStoreData.getKrdCaCert();
        X509Certificate kdhCert = tr34KeyStoreData.getKdhCert();

        // Verify KRD certificate
        Tr34CryptoUtils.verifyCertificateChain(new X509Certificate[] { krdCert, krdCaCert, tr34RootCert }, tr34RootCert);

        // Create the key block
        Tr34KeyBlock keyBlock = Tr34KeyBlock.create(header, symmetricKey, kdhCert);

        // Generate a response
        return Tr34TwoPassKeyToken.create(randomToken, krdCert, keyBlock, tr34KeyStoreData.getKdhKeyStoreData());
    }

    void verifyTwoPassKeyTokenResponse(Tr34TwoPassKeyToken twoPassKeyToken, Tr34RandomToken request) throws Exception {
        // Verify nonce
        if (!request.getRandomNumber().equals(twoPassKeyToken.getRandomNonce())) {
            throw new SecurityException("nonce mismatch");
        }

        cmsVerify(twoPassKeyToken, tr34KeyStoreData.getKdhCert());
    }

    void verifyKdhUnbindToken(Tr34KdhUnbindToken unbindToken, Tr34RandomToken request, X509Certificate krdCert)
            throws Exception {
        if (!request.getRandomNumber().equals(unbindToken.getRandomNonce())) {
            throw new Tr34Exception("Random number mismatch");
        }

        IssuerAndSerialNumber krdIssuerAndSerial = new IssuerAndSerialNumber(Certificate.getInstance(krdCert.getEncoded()));
        IssuerAndSerialNumber tokenIntendedIssuerAndSerial = unbindToken.getKrdIssuerAndSerial();

        if (!tokenIntendedIssuerAndSerial.equals(krdIssuerAndSerial)) {
            throw new Tr34Exception("Intended KRD issuer and serial mismatch");
        }

        cmsVerify(unbindToken, tr34KeyStoreData.getKdhCert());
    }

    void verifyKdhRebindToken(Tr34KdhRebindToken rebindToken, Tr34RandomToken request, X509Certificate krdCert)
            throws Exception {
        if (!request.getRandomNumber().equals(rebindToken.getRandomNonce())) {
            throw new Tr34Exception("Random number mismatch");
        }

        IssuerAndSerialNumber krdIssuerAndSerial = new IssuerAndSerialNumber(Certificate.getInstance(krdCert.getEncoded()));
        IssuerAndSerialNumber tokenIntendedKrdIssuerAndSerial = rebindToken.getKrdIssuerAndSerial();

        if (!tokenIntendedKrdIssuerAndSerial.equals(krdIssuerAndSerial)) {
            throw new Tr34Exception("Intended KRD issuer and serial mismatch");
        }

        cmsVerify(rebindToken, tr34KeyStoreData.getKdhCert());
    }

    void verifyCaUnbindToken(Tr34CaUnbindToken caUnbindToken, X509Certificate krdCert, X509Certificate kdhCert)
            throws Exception {
        IssuerAndSerialNumber krdIssuerAndSerial = new IssuerAndSerialNumber(Certificate.getInstance(krdCert.getEncoded()));
        IssuerAndSerialNumber tokenTargetKrdIssuerAndSerial = caUnbindToken.getKrdIssuerAndSerial();

        if (!tokenTargetKrdIssuerAndSerial.equals(krdIssuerAndSerial)) {
            throw new Tr34Exception("Intended KRD issuer and serial mismatch");
        }

        IssuerAndSerialNumber kdhIssuerAndSerial = new IssuerAndSerialNumber(Certificate.getInstance(kdhCert.getEncoded()));
        IssuerAndSerialNumber tokenTargetKdhIssuerAndSerial = caUnbindToken.getKdhIssuerAndSerial();

        if (!tokenTargetKdhIssuerAndSerial.equals(kdhIssuerAndSerial)) {
            throw new Tr34Exception("Intended KDH issuer and serial mismatch");
        }

        cmsVerify(caUnbindToken, tr34KeyStoreData.getKrdCaCert());
    }

    void verifyCaRebindToken(Tr34CaRebindToken rebindToken, X509Certificate krdCert, X509Certificate currentKdhCert)
            throws Exception {
        IssuerAndSerialNumber krdIssuerAndSerial = new IssuerAndSerialNumber(Certificate.getInstance(krdCert.getEncoded()));
        IssuerAndSerialNumber kdhIssuerAndSerial = new IssuerAndSerialNumber(Certificate.getInstance(currentKdhCert.getEncoded()));

        IssuerAndSerialNumber tokenIntendedKrdIssuerAndSerial = rebindToken.getKrdIssuerAndSerial();
        IssuerAndSerialNumber tokenIntendedKdhIssuerAndSerial = rebindToken.getKdhIssuerAndSerial();

        if (!tokenIntendedKrdIssuerAndSerial.equals(krdIssuerAndSerial)) {
            throw new Tr34Exception("Intended KRD issuer and serial mismatch");
        }

        if (!tokenIntendedKdhIssuerAndSerial.equals(kdhIssuerAndSerial)) {
            throw new Tr34Exception("Intended KDH issuer and serial mismatch");
        }

        cmsVerify(rebindToken, tr34KeyStoreData.getKrdCaCert());
    }

    private void cmsVerify(Tr34SignedObject signedObject, X509Certificate signerCert) throws Exception {
        if (!cmsVerify(signedObject, new PubKeyOrCert(signerCert))) {
            throw new SecurityException("Verification failed");
        } else {
            System.out.println("Verify success");
        }
    }

    private static boolean cmsVerify(Tr34SignedObject signedObject, PubKeyOrCert pubKeyOrCert) throws Exception {
        SignerInformationVerifierProvider vProv = signerId -> {
            JcaSimpleSignerInfoVerifierBuilder builder = new JcaSimpleSignerInfoVerifierBuilder()
                    .setProvider(Tr34Provider.PROVIDER);
            if (pubKeyOrCert.isCert()) {
                if (signerId.getSerialNumber().equals(pubKeyOrCert.cert.getSerialNumber())) {
                    return builder.build(pubKeyOrCert.cert);
                } else {
                    throw new IllegalArgumentException("No cert for: " + signerId);
                }
            } else {
                return builder.build(pubKeyOrCert.pubKey);
            }
        };

        return signedObject.getCMSSignedData().verifySignatures(vProv);
    }

    Tr34KeyBlock decrypt(Tr34TwoPassKeyToken response, PrivateKey recipientPrivateKey) throws CMSException {
        CMSEnvelopedData enveloped = new CMSEnvelopedData(new ContentInfo(PKCSObjectIdentifiers.envelopedData, response.getEnvelopedData()));
        Collection<RecipientInformation> recip = enveloped.getRecipientInfos().getRecipients();
        KeyTransRecipientInformation rinfo = (KeyTransRecipientInformation) recip.iterator().next();
        return Tr34KeyBlock.create(rinfo.getContent(new JceKeyTransEnvelopedRecipient(recipientPrivateKey).setProvider(Tr34Provider.PROVIDER)));
    }

}

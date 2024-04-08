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
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collection;

/**
 * This class handles some operations necessary for the receiver of various TR-34 tokens.
 */
public class Tr34TokenClient {

    private final Tr34KeyStoreData tr34KeyStoreData;

    public Tr34TokenClient(Tr34KeyStoreData keyStoreData) {
        this.tr34KeyStoreData = keyStoreData;
    }

    public void verifyTwoPassKeyTokenResponse(Tr34TwoPassKeyToken twoPassKeyToken, Tr34RandomToken request) throws Exception {
        // Verify nonce
        if (!request.getRandomNumber().equals(twoPassKeyToken.getRandomNonce())) {
            throw new SecurityException("nonce mismatch");
        }

        cmsVerify(twoPassKeyToken, tr34KeyStoreData.getKdhCert());
    }

    public void verifyKdhUnbindToken(Tr34KdhUnbindToken unbindToken, Tr34RandomToken request, X509Certificate krdCert)
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

    public void verifyKdhRebindToken(Tr34KdhRebindToken rebindToken, Tr34RandomToken request, X509Certificate krdCert)
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

    public void verifyCaUnbindToken(Tr34CaUnbindToken caUnbindToken, X509Certificate krdCert, X509Certificate kdhCert)
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

    public void verifyCaRebindToken(Tr34CaRebindToken rebindToken, X509Certificate krdCert, X509Certificate currentKdhCert)
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
        if (!cmsVerify(signedObject, new TrustAnchor(signerCert, null))) {
            throw new SecurityException("Verification failed");
        }
    }

    private static boolean cmsVerify(Tr34SignedObject signedObject, TrustAnchor trustAnchor) throws Exception {
        SignerInformationVerifierProvider vProv = signerId -> {
            JcaSimpleSignerInfoVerifierBuilder builder = new JcaSimpleSignerInfoVerifierBuilder()
                    .setProvider(Tr34Provider.PROVIDER);
            if (trustAnchor.getTrustedCert() != null) {
                if (signerId.getSerialNumber().equals(trustAnchor.getTrustedCert().getSerialNumber())) {
                    return builder.build(trustAnchor.getTrustedCert());
                } else {
                    throw new IllegalArgumentException("No cert for: " + signerId);
                }
            } else if (trustAnchor.getCAPublicKey() != null) {
                return builder.build(trustAnchor.getCAPublicKey());
            } else {
                throw new SecurityException("Unsupported trust anchor: " + trustAnchor);
            }
        };

        return signedObject.getCMSSignedData().verifySignatures(vProv);
    }

    public Tr34KeyBlock decrypt(CMSEnvelopedData enveloped, PrivateKey recipientPrivateKey) throws CMSException {
        Collection<RecipientInformation> recip = enveloped.getRecipientInfos().getRecipients();
        KeyTransRecipientInformation rinfo = (KeyTransRecipientInformation) recip.iterator().next();
        return Tr34KeyBlock.decode(rinfo.getContent(new JceKeyTransEnvelopedRecipient(recipientPrivateKey)
                .setProvider(Tr34Provider.PROVIDER)));
    }

    public Tr34KeyBlock decrypt(Tr34TwoPassKeyToken response, PrivateKey recipientPrivateKey) throws CMSException {
        CMSEnvelopedData enveloped = new CMSEnvelopedData(new ContentInfo(PKCSObjectIdentifiers.envelopedData, response.getEnvelopedData()));
        return decrypt(enveloped, recipientPrivateKey);
    }

}

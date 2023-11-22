package com.clover.tr34;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

/**
 * See B.6 CTKDH – The KDH Credential Token
 */
public class Tr34KdhCredentialToken extends Tr34SignedObject {

    private final CMSSignedData rootNode;

    private Tr34KdhCredentialToken(CMSSignedData csd) {
        this.rootNode = csd;

        if (csd.getCertificates().getMatches(Tr34CryptoUtils.ALL_CERT_SELECTOR).size() != 1) {
            throw new Tr34Exception("Unexpected number of certificates");
        }
    }

    public static Tr34KdhCredentialToken create(Object encoded) {
        try {
            CMSSignedData csd;
            if (encoded instanceof CMSSignedData) {
                csd = (CMSSignedData) encoded;
            } else {
                csd = new CMSSignedData(ContentInfo.getInstance(Tr34CryptoUtils.decodeToAsn1(encoded)));
            }
            return new Tr34KdhCredentialToken(csd);
        } catch (CMSException e) {
            throw new Tr34Exception(e);
        }
    }

    public static Tr34KdhCredentialToken create(X509Certificate kdhCert, X509CRL crl) {
        try {
            CMSSignedDataGenerator sdGen = new CMSSignedDataGenerator();
            sdGen.setDefiniteLengthEncoding(true);
            sdGen.addCertificate(new X509CertificateHolder(kdhCert.getEncoded()));
            sdGen.addCRL(new X509CRLHolder(crl.getEncoded()));
            CMSSignedData csd = sdGen.generate(new CMSAbsentContent());
            return new Tr34KdhCredentialToken(csd);
        } catch (CMSException | GeneralSecurityException | IOException e) {
            throw new Tr34Exception(e);
        }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return rootNode.toASN1Structure().toASN1Primitive();
    }

    @Override
    public SignedData getSignedData() {
        throw new UnsupportedOperationException("Unsigned type");
    }

    @Override
    public SignerInfo getSignerInfo() {
        throw new UnsupportedOperationException("Unsigned type");
    }

}

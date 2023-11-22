package com.clover.tr34;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;

import java.security.cert.X509Certificate;
import java.util.Collection;

/**
 * See B.7 CTKRD - The KRD Credential Token
 */
public class Tr34KrdCredentialToken extends Tr34SignedObject {

    private final CMSSignedData rootNode;
    private final X509Certificate krdCert;

    private Tr34KrdCredentialToken(CMSSignedData csd) throws Exception {
        this.rootNode = csd;

        Collection<X509CertificateHolder> certs = csd.getCertificates()
                .getMatches(Tr34CryptoUtils.ALL_CERT_SELECTOR);

        if (certs.size() != 1) {
            throw new Tr34Exception("Unexpected number of certificates");
        }

        krdCert = Tr34CryptoUtils.parseCert(certs.iterator().next().getEncoded());

        // Just to make sure this isn't a KDH bind token
        if (!csd.getCRLs().getMatches(Tr34CryptoUtils.ALL_CRL_SELECTOR).isEmpty()) {
            throw new Tr34Exception("CRLs not allowed");
        }
    }

    public static Tr34KrdCredentialToken create(Object encoded) {
        try {
            CMSSignedData csd;
            if (encoded instanceof CMSSignedData) {
                csd = (CMSSignedData) encoded;
            } else {
                csd = new CMSSignedData(ContentInfo.getInstance(Tr34CryptoUtils.decodeToAsn1(encoded)));
            }
            return new Tr34KrdCredentialToken(csd);
        } catch (Exception e) {
            throw new Tr34Exception(e);
        }
    }

    public static Tr34KrdCredentialToken create(X509Certificate krdCert) {
        try {
            CMSSignedDataGenerator sdGen = new CMSSignedDataGenerator();
            sdGen.setDefiniteLengthEncoding(true);
            sdGen.addCertificate(new X509CertificateHolder(krdCert.getEncoded()));
            CMSSignedData csd = sdGen.generate(new CMSAbsentContent());
            return new Tr34KrdCredentialToken(csd);
        } catch (Exception e) {
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

    public X509Certificate getKrdCertificate() {
        return krdCert;
    }

}

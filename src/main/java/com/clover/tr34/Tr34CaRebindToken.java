package com.clover.tr34;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cms.CMSSignedData;

import java.io.ByteArrayOutputStream;
import java.security.cert.X509Certificate;


/**
 * B.10 RBTCA_UNBIND – Higher Level Authority Rebind Token
 */
public class Tr34CaRebindToken extends Tr34SignedObject {

    private final CMSSignedData rootNode;
    private final SignedData signedData;
    private final SignerInfo signerInfo;

    private final IssuerAndSerialNumber krdIssuerAndSerial;
    private final IssuerAndSerialNumber kdhIssuerAndSerial;

    private final X509Certificate newKdhCert;

    private Tr34CaRebindToken(CMSSignedData csd) throws Exception {
        signedData = SignedData.getInstance(csd.toASN1Structure().getContent());

        ASN1Set signerInfos = signedData.getSignerInfos();
        if (signerInfos.size() != 1) {
            throw new Tr34Exception("Unexpected number of signers");
        }

        signerInfo = SignerInfo.getInstance(signerInfos.getObjectAt(0));

        ContentInfo ci = signedData.getEncapContentInfo();
        if (!ci.getContentType().equals(CMSObjectIdentifiers.signedData)) {
            throw new Tr34Exception("Unexpected content type");
        }

        byte[] encapContentEncoded = ((ASN1OctetString) ci.getContent()).getOctets();
        SignedData innerSignedData = SignedData.getInstance(encapContentEncoded);

        ASN1Set certs = innerSignedData.getCertificates();
        if (certs == null || certs.size() != 1) {
            throw new Tr34Exception("Missing new cert to bind");
        }

        newKdhCert = Tr34CryptoUtils.parseCert(certs.getObjectAt(0).toASN1Primitive().getEncoded());

        ASN1OctetString innerInnerContent = ASN1OctetString.getInstance(innerSignedData.getEncapContentInfo().getContent());

        // Due to an unusual design choice we need manually stream out the concatenated objects
        try (ASN1InputStream ais = new ASN1InputStream(innerInnerContent.getOctets())) {
            krdIssuerAndSerial = IssuerAndSerialNumber.getInstance(ais.readObject());
            kdhIssuerAndSerial = IssuerAndSerialNumber.getInstance(ais.readObject());
        }

        this.rootNode = csd;
    }

    public static Tr34CaRebindToken decode(Object encoded) {
        try {
            CMSSignedData csd;
            if (encoded instanceof CMSSignedData) {
                csd = (CMSSignedData) encoded;
            } else {
                csd = new CMSSignedData(ContentInfo.getInstance(Tr34CryptoUtils.decodeToAsn1(encoded)));
            }
            return new Tr34CaRebindToken(csd);
        } catch (Exception e) {
            throw new Tr34Exception(e);
        }
    }

    public static Tr34CaRebindToken create(X509Certificate krdCert,
                                           X509Certificate currentKdhCert, X509Certificate newKdhCert,
                                           Tr34ScdKeyStoreData krdKeyStore) {
        try {
            ASN1EncodableVector attributes = new ASN1EncodableVector();
            AttributeTable at = new AttributeTable(attributes);

            // Unfortunately KRD issuer and serial concatenated with KDH issuer and serial instead
            // of being contained in a SET or SEQUENCE
            IssuerAndSerialNumber krdIssuerAndSerial =
                    new IssuerAndSerialNumber(Certificate.getInstance(krdCert.getEncoded()));

            IssuerAndSerialNumber currentKdhIssuerAndSerial =
                    new IssuerAndSerialNumber(Certificate.getInstance(currentKdhCert.getEncoded()));

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(krdIssuerAndSerial.getEncoded());
            baos.write(currentKdhIssuerAndSerial.getEncoded());

            SignedData innerSignedData = createUnsignedSignedData(baos.toByteArray(), newKdhCert);

            CMSSignedData cmsSignedData = signCmsData(at, CMSObjectIdentifiers.signedData,
                    innerSignedData.getEncoded(), krdKeyStore);

            return new Tr34CaRebindToken(cmsSignedData);
        } catch (Exception e) {
            throw new Tr34Exception(e);
        }
    }

    @Override
    public SignedData getSignedData() {
        return signedData;
    }

    @Override
    public SignerInfo getSignerInfo() {
        return signerInfo;
    }

    public IssuerAndSerialNumber getKrdIssuerAndSerial() {
        return krdIssuerAndSerial;
    }

    public IssuerAndSerialNumber getKdhIssuerAndSerial() {
        return kdhIssuerAndSerial;
    }

    public X509Certificate getNewKdhCert() {
        return newKdhCert;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return rootNode.toASN1Structure().toASN1Primitive();
    }

}

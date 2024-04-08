package com.clover.tr34;

import org.bouncycastle.asn1.ASN1EncodableVector;
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

import java.security.cert.X509Certificate;

/**
 * See B.11 RBTKDH – KDH Rebind Token
 */
public class Tr34KdhRebindToken extends Tr34SignedObject {

    private final CMSSignedData rootNode;
    private final SignedData signedData;
    private final SignerInfo signerInfo;
    private final ASN1OctetString randomNonce;
    private final X509Certificate newKdhCert;
    private final IssuerAndSerialNumber krdIssuerAndSerial;

    private Tr34KdhRebindToken(CMSSignedData csd) throws Exception {
        signedData = SignedData.getInstance(csd.toASN1Structure().getContent());

        ASN1Set signerInfos = signedData.getSignerInfos();
        if (signerInfos.size() != 1) {
            throw new Tr34Exception("Unexpected number of signers");
        }

        signerInfo = SignerInfo.getInstance(signerInfos.getObjectAt(0));
        ASN1Set authenticatedAttrs = signerInfo.getAuthenticatedAttributes();

        AttributeTable attrTable = new AttributeTable(authenticatedAttrs);
        randomNonce = (ASN1OctetString) attrTable.get(Tr34ObjectIdentifiers.randomNonce).getAttributeValues()[0];
        if (randomNonce.getOctetsLength() != 8 && randomNonce.getOctetsLength() != 16) {
            throw new Tr34Exception("Random nonce must be 8 or 16 octets");
        }

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

        krdIssuerAndSerial = IssuerAndSerialNumber.getInstance(innerInnerContent.getOctets());

        this.rootNode = csd;
    }

    public static Tr34KdhRebindToken decode(Object encoded) {
        try {
            CMSSignedData csd;
            if (encoded instanceof CMSSignedData) {
                csd = (CMSSignedData) encoded;
            } else {
                csd = new CMSSignedData(ContentInfo.getInstance(Tr34CryptoUtils.decodeToAsn1(encoded)));
            }
            return new Tr34KdhRebindToken(csd);
        } catch (Exception e) {
            throw new Tr34Exception(e);
        }
    }

    public static Tr34KdhRebindToken create(Tr34RandomToken request, X509Certificate krdCert,
                                            X509Certificate newKdhCert, Tr34ScdKeyStoreData currentKdhKeyStore) {
        try {
            ASN1EncodableVector attributes = new ASN1EncodableVector();
            attributes.add(request);
            AttributeTable at = new AttributeTable(attributes);

            // There is an inner SignedData in the outer SignedData, but the inner SignedData is unsigned,
            // an overly complex choice for a container in my opinion.

            IssuerAndSerialNumber krdIssuerAndSerial =
                    new IssuerAndSerialNumber(Certificate.getInstance(krdCert.getEncoded()));

            SignedData innerSignedData = createUnsignedSignedData(krdIssuerAndSerial.getEncoded(), newKdhCert);

            CMSSignedData cmsSignedData = signCmsData(at, CMSObjectIdentifiers.signedData,
                    innerSignedData.getEncoded(), currentKdhKeyStore);

            return new Tr34KdhRebindToken(cmsSignedData);
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

    public ASN1OctetString getRandomNonce() {
        return randomNonce;
    }

    public IssuerAndSerialNumber getKrdIssuerAndSerial() {
        return krdIssuerAndSerial;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return rootNode.toASN1Structure().toASN1Primitive();
    }

}

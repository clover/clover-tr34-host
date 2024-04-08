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
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;

import java.security.cert.X509Certificate;

/**
 * See B.14 UBTKDH – KDH Unbind Token
 */
public class Tr34KdhUnbindToken extends Tr34SignedObject {

    private final CMSSignedData rootNode;
    private final SignedData signedData;
    private final SignerInfo signerInfo;
    private final ASN1OctetString randomNonce;
    private final IssuerAndSerialNumber krdInfo;

    private Tr34KdhUnbindToken(CMSSignedData csd) {
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

        byte[] encodedEncapContent = ((ASN1OctetString) signedData.getEncapContentInfo().getContent()).getOctets();
        krdInfo = IssuerAndSerialNumber.getInstance(encodedEncapContent);

        this.rootNode = csd;
    }

    public static Tr34KdhUnbindToken decode(Object encoded) {
        try {
            CMSSignedData csd;
            if (encoded instanceof CMSSignedData) {
                csd = (CMSSignedData) encoded;
            } else {
                csd = new CMSSignedData(ContentInfo.getInstance(Tr34CryptoUtils.decodeToAsn1(encoded)));
            }
            return new Tr34KdhUnbindToken(csd);
        } catch (CMSException e) {
            throw new Tr34Exception(e);
        }
    }

    public static Tr34KdhUnbindToken create(Tr34RandomToken request, X509Certificate krdCert,
                                            Tr34ScdKeyStoreData currentKdhKeyStore) {
        try {
            ASN1EncodableVector attributes = new ASN1EncodableVector();
            attributes.add(request);
            AttributeTable at = new AttributeTable(attributes);

            // Just KRD issuer and serial is the content
            IssuerAndSerialNumber krdIssuerAndSerial =
                    new IssuerAndSerialNumber(Certificate.getInstance(krdCert.getEncoded()));

            CMSSignedData cmsSignedData = signCmsData(at, CMSObjectIdentifiers.data, krdIssuerAndSerial.getEncoded(),
                    currentKdhKeyStore);

            return new Tr34KdhUnbindToken(cmsSignedData);
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
        return krdInfo;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return rootNode.toASN1Structure().toASN1Primitive();
    }

}

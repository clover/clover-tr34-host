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
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;

import java.io.ByteArrayOutputStream;
import java.security.cert.X509Certificate;

/**
 * B.13 UBTCA_UNBIND – Higher Level Authority Unbind Token
 */
public class Tr34CaUnbindToken extends Tr34SignedObject {

    private final CMSSignedData rootNode;
    private final SignedData signedData;
    private final SignerInfo signerInfo;

    private final IssuerAndSerialNumber krdIssuerAndSerial;
    private final IssuerAndSerialNumber kdhIssuerAndSerial;

    private Tr34CaUnbindToken(CMSSignedData csd) {
        signedData = SignedData.getInstance(csd.toASN1Structure().getContent());

        ASN1Set signerInfos = signedData.getSignerInfos();
        if (signerInfos.size() != 1) {
            throw new Tr34Exception("Unexpected number of signers");
        }

        signerInfo = SignerInfo.getInstance(signerInfos.getObjectAt(0));

        byte[] encodedEncapContent = ((ASN1OctetString) signedData.getEncapContentInfo().getContent()).getOctets();

        // Due to an unusual design choice we need manually stream out the concatenated objects
        try (ASN1InputStream ais = new ASN1InputStream(encodedEncapContent)) {
            krdIssuerAndSerial = IssuerAndSerialNumber.getInstance(ais.readObject());
            kdhIssuerAndSerial = IssuerAndSerialNumber.getInstance(ais.readObject());
        } catch (Exception e) {
            throw new Tr34Exception(e);
        }

        this.rootNode = csd;
    }

    public static Tr34CaUnbindToken create(Object encoded) {
        try {
            CMSSignedData csd;
            if (encoded instanceof CMSSignedData) {
                csd = (CMSSignedData) encoded;
            } else {
                csd = new CMSSignedData(ContentInfo.getInstance(Tr34CryptoUtils.decodeToAsn1(encoded)));
            }
            return new Tr34CaUnbindToken(csd);
        } catch (CMSException e) {
            throw new Tr34Exception(e);
        }
    }

    public static Tr34CaUnbindToken create(X509Certificate krdCert,
                                           X509Certificate kdhCert, Tr34ScdKeyStoreData krdKeyStore) {
        try {
            ASN1EncodableVector attributes = new ASN1EncodableVector();
            AttributeTable at = new AttributeTable(attributes);

            // KRD issuer and serial concatenated with KDH issuer and serial are signed content
            IssuerAndSerialNumber krdIssuerAndSerial =
                    new IssuerAndSerialNumber(Certificate.getInstance(krdCert.getEncoded()));

            IssuerAndSerialNumber kdhIssuerAndSerial =
                    new IssuerAndSerialNumber(Certificate.getInstance(kdhCert.getEncoded()));

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(krdIssuerAndSerial.getEncoded());
            baos.write(kdhIssuerAndSerial.getEncoded());

            byte[] encapDataBytes = baos.toByteArray();

            CMSSignedData cmsSignedData = signCmsData(at, CMSObjectIdentifiers.data, encapDataBytes, krdKeyStore);

            return new Tr34CaUnbindToken(cmsSignedData);
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

    @Override
    public ASN1Primitive toASN1Primitive() {
        return rootNode.toASN1Structure().toASN1Primitive();
    }

}

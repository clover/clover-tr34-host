package com.clover.tr34;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.security.cert.X509Certificate;

/**
 * Parent class for all TR-34 objects which are signed.
 */
public abstract class Tr34SignedObject extends Tr34Object {

    protected static SignedData createUnsignedSignedData(byte[] data, X509Certificate cert) throws Exception {
        ASN1Set innerCerts;
        if (cert == null) {
            innerCerts = new DLSet();
        } else {
            innerCerts = new DLSet(new ASN1Encodable[] { ASN1Primitive.fromByteArray(cert.getEncoded()) });
        }

        ASN1OctetString dataOctetString = new DEROctetString(data);
        ContentInfo innerCi = new ContentInfo(CMSObjectIdentifiers.data, dataOctetString);
        ASN1Set emptySet = new DLSet(new ASN1Encodable[0]);
        return new SignedData(emptySet, innerCi, innerCerts, emptySet, emptySet);
    }

    protected static CMSSignedData signCmsData(AttributeTable at, ASN1ObjectIdentifier innerDataId,
                                               byte[] innerDataBytes, Tr34ScdKeyStoreData signerKeyStore) throws Exception {
        CMSAttributeTableGenerator atg = new DefaultSignedAttributeTableGenerator(at);

        CMSSignedDataGenerator sdGen = new CMSSignedDataGenerator();
        sdGen.setDefiniteLengthEncoding(true);
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(Tr34Provider.PROVIDER).build(signerKeyStore.privateKey);

        DigestCalculatorProvider dcp = new JcaDigestCalculatorProviderBuilder().build();
        SignerInfoGenerator sig = new JcaSignerInfoGeneratorBuilder(dcp)
                .setSignedAttributeGenerator(atg)
                .build(contentSigner, signerKeyStore.cert);
        sdGen.addSignerInfoGenerator(sig);

        final boolean encapsulateData = true;
        CMSSignedData sd = sdGen.generate(new CMSProcessableByteArray(innerDataId, innerDataBytes), encapsulateData);
        CMSSignedData.addDigestAlgorithm(sd, new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));
        return sd;
    }

    public CMSSignedData getCMSSignedData() {
        try {
            return new CMSSignedData(toASN1Primitive().getEncoded());
        } catch (Exception e) {
            throw new Tr34Exception(e);
        }
    }

    public abstract SignedData getSignedData();

    public abstract SignerInfo getSignerInfo();

}

package com.clover.tr34;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;

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

    protected static byte[] encryptForRecipient(X509Certificate recipientCert, byte[] dataToDecrypt) throws Exception {
        // Generate inner EnvelopedData
        OAEPParameterSpec oaepParamSpec = new OAEPParameterSpec("SHA-256", "MGF1",
                MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        JcaAlgorithmParametersConverter paramsConv = new JcaAlgorithmParametersConverter();
        AlgorithmIdentifier algoId = paramsConv.getAlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP, oaepParamSpec);

        JceKeyTransRecipientInfoGenerator recipInfo = new JceKeyTransRecipientInfoGenerator(recipientCert, algoId);

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
        edGen.addRecipientInfoGenerator(recipInfo);

        JceCMSContentEncryptorBuilder contentEncBuilder = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC);

        CMSTypedData msg = new CMSProcessableByteArray(dataToDecrypt);
        CMSEnvelopedData cmsEd = edGen.generate(msg, contentEncBuilder.build());
        EnvelopedData ed = (EnvelopedData) cmsEd.toASN1Structure().getContent();
        return ed.getEncoded(ASN1Encoding.DL);
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

package com.clover.tr34;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;

/**
 * See B.9 KTKDH – The KDH Key Token
 * <p>
 * Currently, this implementation only encrypts with ephemeral key type AES 128, the standard allows
 * for TDEA 168 but that is not implemented here.
 */
public class Tr34TwoPassKeyToken extends Tr34SignedObject {

    private final ASN1Sequence rootNode;
    private final SignedData signedData;
    private final SignerInfo signerInfo;
    private final EnvelopedData envelopedData;
    private final ASN1OctetString randomNonce;
    private final String keyBlockHeader;

    public static Tr34TwoPassKeyToken decode(Object encoded) {
        try {
            return new Tr34TwoPassKeyToken((ASN1Sequence) Tr34CryptoUtils.decodeToAsn1(encoded));
        } catch (Exception e) {
            throw new Tr34Exception(e);
        }
    }

    private static ASN1Sequence generateKT_KDH(Tr34RandomToken request, X509Certificate krdCert,
                                               Tr34KeyBlock keyBlock, Tr34ScdKeyStoreData kdhKeyStore) throws Exception {
        // The KTKDH message includes an inner content of type EnvelopedData and an outer
        // content of type SignedData.

        // Add SignedAttributes: key block header (KBH) and random nonce
        ASN1EncodableVector attributes = new ASN1EncodableVector();
        attributes.add(keyBlock.getFullKeyHeader());
        attributes.add(request);
        AttributeTable at = new AttributeTable(attributes);

        // Encrypt the key block with recipient public key
        byte[] envelopedCryptData = encryptForRecipient(krdCert, keyBlock.getEncoded());

        // Sign the message
        CMSSignedData sd = signCmsData(at, CMSObjectIdentifiers.envelopedData, envelopedCryptData, kdhKeyStore);

        return (ASN1Sequence) ASN1Sequence.fromByteArray(sd.getEncoded());
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

    static Tr34TwoPassKeyToken create(Tr34RandomToken request,
                                      X509Certificate krdCert, Tr34KeyBlock keyBlock,
                                      Tr34ScdKeyStoreData kdhKeyStore) {
        try {
            ASN1Sequence out = generateKT_KDH(request, krdCert, keyBlock, kdhKeyStore);
            return new Tr34TwoPassKeyToken(out);
        } catch (Exception e) {
            throw new Tr34Exception(e);
        }
    }

    private Tr34TwoPassKeyToken(ASN1Sequence rootAsn1) throws Exception {
        CMSSignedData csd = new CMSSignedData(ContentInfo.getInstance(Tr34CryptoUtils.decodeToAsn1(rootAsn1)));
        signedData = SignedData.getInstance(csd.toASN1Structure().getContent());

        ASN1Set signerInfos = signedData.getSignerInfos();
        if (signerInfos.size() != 1) {
            throw new Tr34Exception("Invalid number of signer infos");
        }

        signerInfo = SignerInfo.getInstance(signerInfos.getObjectAt(0));
        ASN1Set authenticatedAttrs = signerInfo.getAuthenticatedAttributes();

        AttributeTable attrTable = new AttributeTable(authenticatedAttrs);
        randomNonce = (ASN1OctetString) attrTable.get(Tr34ObjectIdentifiers.randomNonce).getAttributeValues()[0];
        if (randomNonce.getOctetsLength() < 8 || randomNonce.getOctetsLength() > 16) {
            throw new Tr34Exception("Random nonce must be 8 to 16 octets");
        }

        ASN1OctetString kbhOctets = (ASN1OctetString) attrTable.get(PKCSObjectIdentifiers.data).getAttributeValues()[0];
        if (kbhOctets.getOctetsLength() != 16) {
            throw new Tr34Exception("Key block header must be 16 octets");
        }

        keyBlockHeader = new String(kbhOctets.getOctets(), StandardCharsets.US_ASCII);

        // Get inner EnvelopedData

        ContentInfo ci = signedData.getEncapContentInfo();
        if (!PKCSObjectIdentifiers.envelopedData.equals(ci.getContentType())) {
            throw new Tr34Exception("Invalid encapsulated content info identifier");
        }

        ASN1OctetString enveloped = (ASN1OctetString) ci.getContent();
        ASN1Sequence obj = ASN1Sequence.getInstance(enveloped.getOctets());
        envelopedData = EnvelopedData.getInstance(obj);

        this.rootNode = rootAsn1;
    }

    public ASN1OctetString getRandomNonce() {
        return randomNonce;
    }

    public EnvelopedData getEnvelopedData() {
        return envelopedData;
    }

    @Override
    public SignerInfo getSignerInfo() {
        return signerInfo;
    }

    @Override
    public SignedData getSignedData() {
        return signedData;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return rootNode;
    }
}

package com.clover.tr34;

import com.clover.tr34.samples.AscSampleTr34KeyStoreData;
import com.clover.tr34.samples.AscSampleTr34Messages;
import com.clover.tr34.samples.CloverSampleTr34KeyStoreData;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.io.IOException;
import java.lang.reflect.Field;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;


/**
 * Tests using ASC X9 TR34-2019 sample certificates, keys and messages.
 */
public class Tr34AscX9Test {

    @Before
    public void setup() {
        // ASC X9 TR 34 sample certs sometimes include repeated extensions (a violation of the standard)
        Properties.setThreadOverride("org.bouncycastle.x509.ignore_repeated_extensions", true);
    }

    @Test
    public void ascSampleRandomTokenParse() {
        byte[] rand = Tr34RandomToken.decode(AscSampleTr34Messages.RKRD_PEM).getRandomNumber().getOctets();
        assertArrayEquals(Hex.decode("167EB0E72781E4940112233445566778"), rand);
    }

    @Test
    public void ascSampleCheckKdhBindToken() throws Exception {
        // Despite the name this CMS is not actually signed
        Tr34KdhCredentialToken.decode(Tr34CryptoUtils.pemToDer(AscSampleTr34Messages.SAMPLE_CT_KDH_PEM));
    }

    @Test
    public void ascSampleCheckKdhUnbindToken() throws Exception {
        Tr34RandomToken randomToken = Tr34RandomToken.create(Hex.decode("7DEA1C00894E246A"));
        Tr34KdhUnbindToken unbindToken = Tr34KdhUnbindToken.decode(AscSampleTr34Messages.SAMPLE_UBT_KDH_PEM);
        X509Certificate krdCert = Tr34CryptoUtils.parseCert(AscSampleTr34KeyStoreData.SAMPLE_KRD_1_CERT_PEM);
        Tr34TokenClient tr34TokenClient = new Tr34TokenClient(AscSampleTr34KeyStoreData.KDH_1);
        tr34TokenClient.verifyKdhUnbindToken(unbindToken, randomToken, krdCert);
    }

    /**
     * BouncyCastle CMS verify doesn't work on the ASC X9 TR 34 samples:
     * See <a href="https://github.com/bcgit/bc-java/issues/1484">bc-java issue 1484</a>
     * See <a href="https://github.com/openssl/openssl/issues/22120">openssl issue 22120</a>
     */
    private static boolean customCmsVerify(Tr34SignedObject signedObject, TrustAnchor trustAnchor) throws Exception {
        PublicKey signerKey;
        if (trustAnchor.getTrustedCert() != null) {
            signerKey = trustAnchor.getTrustedCert().getPublicKey();
        } else {
            signerKey = trustAnchor.getCAPublicKey();
        }

        byte[] data = ((ASN1OctetString) signedObject.getSignedData().getEncapContentInfo().getContent()).getOctets();
        MessageDigest dig = MessageDigest.getInstance("SHA256", Tr34Provider.PROVIDER);
        byte[] computedDigest = dig.digest(data);

        Signature sig = Signature.getInstance("SHA256withRSA", Tr34Provider.PROVIDER);
        sig.initVerify(signerKey);

        DLSet signedAttrs = (DLSet) signedObject.getSignerInfo().getAuthenticatedAttributes();
        if (signedAttrs == null) {
            throw new SecurityException("Missing signed attributes");
        }
        boolean digestMatch = false;
        for (ASN1Encodable attrEncoded : signedAttrs) {
            Attribute attr = Attribute.getInstance(attrEncoded);
            if (CMSAttributes.messageDigest.equals(attr.getAttrType())) {
                byte[] providedDigest = ((ASN1OctetString) attr.getAttrValues().getObjectAt(0)).getOctets();
                if (Arrays.equals(computedDigest, providedDigest)) {
                    digestMatch = true;
                    break;
                }
            }
        }
        if (!digestMatch) {
            return false;
        }

        sig.update(new DLSetWithoutReSort(signedAttrs).getEncoded(ASN1Encoding.DER));

        byte[] signature = signedObject.getSignerInfo().getEncryptedDigest().getOctets();
        return sig.verify(signature);
    }

    static class MalformedTwoPassKeyTokenFixer {

        private static void setField(Object object, String fieldName, Object fieldValue) {
            Class<?> clazz = object.getClass();
            while (clazz != null) {
                try {
                    Field field = clazz.getDeclaredField(fieldName);
                    field.setAccessible(true);
                    field.set(object, fieldValue);
                    return;
                } catch (NoSuchFieldException e) {
                    clazz = clazz.getSuperclass();
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            }
            throw new IllegalArgumentException("No such field");
        }

        private static ASN1Sequence createSha256RsaesOaepParams() {
            AlgorithmIdentifier hashAlgorithm =
                    new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);
            AlgorithmIdentifier maskGenFunc =
                    new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, hashAlgorithm);
            AlgorithmIdentifier pSourceAlgorithm =
                    new AlgorithmIdentifier(PKCSObjectIdentifiers.id_pSpecified, new DEROctetString(new byte[0]));

            ASN1EncodableVector v = new ASN1EncodableVector(3);
            v.add(new DERTaggedObject(true, 0, hashAlgorithm));
            v.add(new DERTaggedObject(true, 1, maskGenFunc));
            v.add(new DERTaggedObject(true, 2, pSourceAlgorithm));

            ASN1EncodableVector o = new ASN1EncodableVector(2);
            o.add(PKCSObjectIdentifiers.id_RSAES_OAEP);
            o.add(new DERSequence(v));

            return new DERSequence(o);
        }

        public static CMSEnvelopedData fixEnveloped(CMSEnvelopedData in) {
            try {
                ASN1Sequence root = ASN1Sequence.getInstance(in.getEncoded());

                ASN1TaggedObject child1 = (ASN1TaggedObject) root.getObjectAt(1);
                ASN1Sequence subSeq = (ASN1Sequence) child1.getBaseObject();
                ASN1Set inSet = (ASN1Set) subSeq.getObjectAt(1);
                subSeq = (ASN1Sequence) inSet.getObjectAt(0);
                subSeq = (ASN1Sequence) subSeq.getObjectAt(2);

                // Modify element 2 (RSA OAEP params) which is both corrupt by BC standards
                ASN1Sequence fixedRsaOaepParams = createSha256RsaesOaepParams();
                ASN1Encodable[] elements = fixedRsaOaepParams.toArray();
                setField(subSeq, "elements", elements);

                return new CMSEnvelopedData(root.getEncoded());
            } catch (IOException | CMSException e) {
                throw new Tr34Exception("Unable to fix CMS enveloped data", e);
            }
        }
    }

    /**
     * This sample is malformed, test will fail. See comments below.
     */
    @Ignore("Malformed sample")
    @Test
    public void ascSampleTwoPassKeyTokenParse() throws Exception {
        Tr34TwoPassKeyToken resp = Tr34TwoPassKeyToken.decode(AscSampleTr34Messages.SAMPLE_KDH_KT_2_PASS_FOR_KRD_1_CMS);

        // Verify the response (can't use x509 sample cert because it is malformed with duplicate extensions)
        TrustAnchor trustAnchor = new TrustAnchor("C=US,O=TR34 Samples,CN=TR34 Sample CA KDH",
                Tr34CryptoUtils.parsePublicKey(AscSampleTr34Messages.SAMPLE_KDH_1_PUB_KEY_PEM), null);

        Tr34TokenClient tr34TokenClient = new Tr34TokenClient(AscSampleTr34KeyStoreData.KDH_1);

        // Use custom verify since SET is misordered per BC expectations (OpenSSL allows it)
        if (!customCmsVerify(resp, trustAnchor)) {
            throw new Tr34Exception("Verification failed");
        }

        // Getting "Not a valid OAEP Parameter encoding", and hacking the enveloped data but then getting "data wrong"
        // deep in Bouncy Castle when processing the OAEP Mask, no idea how to work around that, even OpenSSL fails
        CMSEnvelopedData enveloped = new CMSEnvelopedData(new ContentInfo(PKCSObjectIdentifiers.envelopedData,
                resp.getEnvelopedData()));
        enveloped = MalformedTwoPassKeyTokenFixer.fixEnveloped(enveloped);

        tr34TokenClient.decrypt(enveloped,
                Tr34CryptoUtils.parsePrivateKey(CloverSampleTr34KeyStoreData.TR34_KRD_1_PrivateKey_Pem));
    }

    @Test
    public void ascSampleKeyBlockParse() {
        Tr34KeyBlock.decode(AscSampleTr34Messages.SAMPLE_CLEAR_AES_KEY_BLOCK);
    }

    @Test
    public void ascSampleBindParse() throws Exception {
        CMSSignedData csd = new CMSSignedData(Tr34CryptoUtils.pemToDer(AscSampleTr34Messages.SAMPLE_CT_KDH_PEM));

        Collection<X509CertificateHolder> holders =
                csd.getCertificates().getMatches(new Selector<X509CertificateHolder>() {
            @Override
            public boolean match(X509CertificateHolder obj) {
                return true;
            }

            @Override
            public Object clone() {
                throw new UnsupportedOperationException();
            }
        });

        X509Certificate kdh = null;

        for (X509CertificateHolder holder : holders) {
            kdh = Tr34CryptoUtils.parseCert(holder.getEncoded());
        }

        X509Certificate rootCert = AscSampleTr34KeyStoreData.KDH_1.getRootCert();

        List<X509Certificate> kdhIssuerChain = AscSampleTr34KeyStoreData.KDH_1.getKdhIssuerChain();

        X509Certificate kdhCaCert = kdhIssuerChain.get(0);

        // Build a complete chain including the root and verify
        LinkedList<X509Certificate> kdhChain = new LinkedList<>(kdhIssuerChain);
        kdhChain.addFirst(kdh);
        kdhChain.addLast(rootCert);
        Tr34CryptoUtils.verifyCertificateChain(kdhChain, rootCert);

        Collection<X509CRLHolder> crlHolders = csd.getCRLs().getMatches(new Selector<X509CRLHolder>() {
            @Override
            public boolean match(X509CRLHolder obj) {
                return true;
            }

            @Override
            public Object clone() {
                throw new UnsupportedOperationException();
            }
        });

        for (X509CRLHolder crlHolder : crlHolders) {
            Tr34CryptoUtils.verifyCrl(crlHolder, kdhCaCert);
        }
    }

    /**
     * This sample is malformed, test will fail.
     */
    @Ignore("Malformed sample")
    @Test
    public void ascSampleRebindParse() throws Exception {
        Tr34KdhRebindToken rbt = Tr34KdhRebindToken.decode(AscSampleTr34Messages.SAMPLE_REBIND_KDH_TOKEN_PEM);
    }

    @Test
    public void ascSampleCaUnbindParse() throws Exception {
        Tr34CaUnbindToken ubt = Tr34CaUnbindToken.decode(AscSampleTr34Messages.SAMPLE_UBT_CA_PEM);
    }

    /**
     * This sample is malformed, test will fail.
     */
    @Ignore("Malformed sample")
    @Test
    public void ascSampleCaReindParse() throws Exception {
        Tr34CaRebindToken.decode(AscSampleTr34Messages.SAMPLE_RBT_CA_PEM);
    }

    @Test
    public void ascSampleCredentialTokenParse() throws Exception {
        Tr34KrdCredentialToken ct = Tr34KrdCredentialToken.decode(AscSampleTr34Messages.SAMPLE_CT_KRD_PEM);
    }

}

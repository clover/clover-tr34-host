package com.clover.tr34;

import com.clover.tr34.samples.AscSampleTr34KeyStoreData;
import com.clover.tr34.samples.AscSampleTr34Messages;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertArrayEquals;

@Ignore("Enable after populating redacted ASC X9 TR-34 sample messages")
public class Tr34AscX9Test {

    @Before
    public void setup() {
        // ASC X9 TR 34 sample certs sometimes include repeated extensions
        Properties.setThreadOverride("org.bouncycastle.x509.ignore_repeated_extensions", true);
    }

    @Test
    public void ascSampleRandomTokenParse() {
        byte[] rand = Tr34RandomToken.create(AscSampleTr34Messages.RKRD_PEM).getRandomNumber().getOctets();
        assertArrayEquals(Hex.decode("167EB0E72781E4940112233445566778"), rand);
    }

    @Test
    public void ascSampleCheckKdhBindToken() throws Exception {
        // Despite the name this CMS is not actually signed
        new CMSSignedData(Tr34CryptoUtils.pemToDer(AscSampleTr34Messages.SAMPLE_CT_KDH_PEM));
    }

    @Test
    public void ascSampleCheckKdhUnbindToken() throws Exception {
        Tr34RandomToken randomToken = Tr34RandomToken.createFromNonce(Hex.decode("7DEA1C00894E246A"));
        Tr34KdhUnbindToken unbindToken = Tr34KdhUnbindToken.create(AscSampleTr34Messages.SAMPLE_UBT_KDH_PEM);
        X509Certificate krdCert = Tr34CryptoUtils.parseCert(AscSampleTr34KeyStoreData.SAMPLE_KRD_1_CERT_PEM);
        Tr34TokenFactory processor = new Tr34TokenFactory(AscSampleTr34KeyStoreData.KDH_1);
        processor.verifyKdhUnbindToken(unbindToken, randomToken, krdCert);
    }

    /**
     * BouncyCastle CMS verify doesn't work on the ASC X9 TR 34 samples:
     * See <a href="https://github.com/bcgit/bc-java/issues/1484">bc-java issue 1484</a>
     * See <a href="https://github.com/openssl/openssl/issues/22120">openssl issue 22120</a>
     */
    private static boolean customCmsVerify(Tr34SignedObject signedObject, PubKeyOrCert pubKeyOrCert) throws Exception {
        PublicKey signerKey;
        if (pubKeyOrCert.isCert()) {
            signerKey = pubKeyOrCert.cert.getPublicKey();
        } else {
            signerKey = pubKeyOrCert.pubKey;
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

    /**
     * This sample is malformed, test will fail.
     */
    @Ignore("Malformed sample")
    @Test
    public void ascSampleTwoPassKeyTokenParse() throws Exception {
        Tr34RandomToken req = Tr34RandomToken.create(AscSampleTr34Messages.RKRD_PEM);

        Tr34TwoPassKeyToken resp = Tr34TwoPassKeyToken.create(AscSampleTr34Messages.SAMPLE_KDH_KT_2_PASS_FOR_KRD_1_CMS);

        // Verify the response (can't use x509 sample cert because it is malformed with duplicate extensions)
        PubKeyOrCert pubKeyOrCert = new PubKeyOrCert(Tr34CryptoUtils.parsePublicKey(AscSampleTr34Messages.SAMPLE_KDH_1_PUB_KEY_PEM));

        Tr34TokenFactory tr34Processor = new Tr34TokenFactory(AscSampleTr34KeyStoreData.KDH_1);

        // Use custom verify since SET is misordered
        if (true) {
            if (!customCmsVerify(resp, pubKeyOrCert)) {
                throw new Tr34Exception("Verification failed");
            }
        } else {
            tr34Processor.verifyTwoPassKeyTokenResponse(resp, req);
        }

        // Getting "Not a valid OAEP Parameter encoding"...
        // Probably not worth making their sample work
        tr34Processor.decrypt(resp, Tr34CryptoUtils.parsePrivateKey(AscSampleTr34KeyStoreData.SAMPLE_KRD_1_PRIVATE_KEY_PEM));
    }

    @Test
    public void ascSampleKeyBlockParse() {
        Tr34KeyBlock.create(AscSampleTr34Messages.SAMPLE_CLEAR_AES_KEY_BLOCK);
    }

    @Test
    public void ascSampleBindParse() throws Exception {
        CMSSignedData csd = new CMSSignedData(Tr34CryptoUtils.pemToDer(AscSampleTr34Messages.SAMPLE_CT_KDH_PEM));

        System.out.println("csd=" + csd);
        new Asn1TreePrinter(Tr34CryptoUtils.decodeToAsn1(AscSampleTr34Messages.SAMPLE_CT_KDH_PEM)).print();

        Collection<X509CertificateHolder> holders = csd.getCertificates().getMatches(new Selector<X509CertificateHolder>() {
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
            System.out.println("Cert: " + holder);
            kdh = Tr34CryptoUtils.parseCert(holder.getEncoded());
        }

        X509Certificate rootCert = AscSampleTr34KeyStoreData.KDH_1.getRootCert();

        X509Certificate kdhCaCert = AscSampleTr34KeyStoreData.KDH_1.getKdhCaCert();

        Tr34CryptoUtils.verifyCertificateChain(new X509Certificate[] {kdh, kdhCaCert, rootCert}, rootCert);

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
        Tr34KdhRebindToken.create(AscSampleTr34Messages.SAMPLE_REBIND_KDH_TOKEN_PEM);
    }

    @Test
    public void ascSampleCaUnbindParse() throws Exception {
        Tr34CaUnbindToken.create(AscSampleTr34Messages.SAMPLE_UBT_CA_PEM);
    }

    /**
     * This sample is malformed, test will fail.
     */
    @Ignore("Malformed sample")
    @Test
    public void ascSampleCaReindParse() throws Exception {
        Tr34CaRebindToken.create(AscSampleTr34Messages.SAMPLE_RBT_CA_PEM);
    }

}

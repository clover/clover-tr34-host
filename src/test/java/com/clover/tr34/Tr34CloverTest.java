package com.clover.tr34;

import com.clover.tr34.samples.CloverSampleTr34KeyStoreData;
import com.clover.tr34.samples.CloverSampleTr34Messages;

import org.bouncycastle.cms.CMSSignedData;

import org.junit.Test;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertEquals;


/**
 * Tests using Clover generated sample certificates, keys and messages.
 */
public class Tr34CloverTest {

    private static final List<X509Certificate> krd1Chain;
    private static final X509Certificate krdCert;

    static {
        krdCert = Tr34CryptoUtils.parseCert(CloverSampleTr34KeyStoreData.TR34_KRD_1_Cert_Pem);

        List<X509Certificate> chain = new LinkedList<>();
        chain.add(krdCert);
        chain.add(Tr34CryptoUtils.parseCert(CloverSampleTr34KeyStoreData.TR34_KRD_CA_Cert_Pem));
        krd1Chain = Collections.unmodifiableList(chain);
    }

    @Test
    public void cloverRandomTokenCreate() {
        byte[] rand = Tr34RandomToken.createNewRandom().getRandomNumber().getOctets();
        assertEquals(16, rand.length);
    }

    @Test
    public void cloverRandomTokenCreateAndParse() {
        byte[] rand = Tr34RandomToken.decode(Tr34RandomToken.createNewRandom().toASN1Primitive())
                .getRandomNumber().getOctets();
        assertEquals(16, rand.length);
    }

    @Test
    public void cloverKeyBlockCreate() {
        Tr34KeyStoreData trustStore = CloverSampleTr34KeyStoreData.KDH_1;
        String header = "D0256K0AB00E0000";
        byte[] key = new byte[16];
        Tr34KeyBlock.create(header, key, trustStore.getKdhCert());
    }

    @Test
    public void cloverGenerateKdhCredentialToken() throws Exception {
        Tr34KeyStoreData keyStoreData = CloverSampleTr34KeyStoreData.KDH_1;
        Tr34TokenFactory factory = new Tr34TokenFactory(keyStoreData);

        Tr34KdhCredentialToken kdhBindToken = factory.generateKdhCredentialToken(keyStoreData.getKdhRevocationList(),
                Tr34CryptoUtils.createHoursFromNowDate(24L * keyStoreData.nextCrlUpdateDays()));

        CMSSignedData cmsSignedData = kdhBindToken.getCMSSignedData();

        assertNotNull(cmsSignedData.getCertificates());
        assertEquals(1L, cmsSignedData.getCertificates().getMatches(Tr34CryptoUtils.ALL_CERT_SELECTOR).size());
        assertNotNull(cmsSignedData.getCRLs());
        assertEquals(1L, cmsSignedData.getCRLs().getMatches(Tr34CryptoUtils.ALL_CRL_SELECTOR).size());
    }

    @Test
    public void cloverGenerateKdhUnbindToken() throws Exception {
        Tr34KeyStoreData trustStore = CloverSampleTr34KeyStoreData.KDH_1;
        Tr34RandomToken randomToken = Tr34RandomToken.createNewRandom();

        Tr34TokenFactory factory = new Tr34TokenFactory(trustStore);
        Tr34KdhUnbindToken unbindToken = factory.generateKdhUnbindToken(randomToken, krd1Chain);

        Tr34TokenClient client = new Tr34TokenClient(trustStore);
        client.verifyKdhUnbindToken(unbindToken, randomToken, krd1Chain.get(0));
    }

    @Test
    public void cloverGenerateTwoPassKeyToken() throws Exception {
        Tr34KeyStoreData trustStore = CloverSampleTr34KeyStoreData.KDH_1;
        Tr34TokenFactory factory = new Tr34TokenFactory(trustStore);

        // Step 1: create a request
        Tr34RandomToken reqRandToken = Tr34RandomToken.createNewRandom();
        PrivateKey krdPrivateKey = Tr34CryptoUtils.parsePrivateKey(CloverSampleTr34KeyStoreData.TR34_KRD_1_PrivateKey_Pem);

        // Step 2: generate a response
        byte[] symmetricAesKey = new byte[16];
        new Random().nextBytes(symmetricAesKey);
        Tr34TwoPassKeyToken resp = factory.generateTwoPassKeyToken(reqRandToken, krd1Chain, symmetricAesKey);

        // Step 3: verify the response
        Tr34TokenClient client = new Tr34TokenClient(trustStore);
        client.verifyTwoPassKeyTokenResponse(resp, reqRandToken);

        // Step 4: decrypt the response
        Tr34KeyBlock decryptedKeyBlock = client.decrypt(resp, krdPrivateKey);

        // Verify successful decryption result
        String header = Tr34KeyBlockHeaderFactory.createHeaderForAesTr31Kbk();
        Tr34KeyBlock newKeyBlock = Tr34KeyBlock.create(header, symmetricAesKey, trustStore.getKdhCert());
        assertEquals(newKeyBlock, decryptedKeyBlock);
    }

    @Test
    public void cloverGenerateRebindToken() throws Exception {
        Tr34KeyStoreData trustStore = CloverSampleTr34KeyStoreData.KDH_1;
        Tr34TokenFactory factory = new Tr34TokenFactory(trustStore);

        Tr34RandomToken randomToken = Tr34RandomToken.createNewRandom();
        X509Certificate newKdhCert = Tr34CryptoUtils.parseCert(CloverSampleTr34KeyStoreData.TR34_KDH_2_Cert_Pem);

        Tr34KdhRebindToken rebindToken = factory.generateKdhRebindToken(randomToken, krd1Chain, newKdhCert);

        Tr34TokenClient client = new Tr34TokenClient(trustStore);
        client.verifyKdhRebindToken(rebindToken, randomToken, krdCert);
    }

    @Test
    public void cloverGenerateCaUnbindToken() throws Exception {
        Tr34KeyStoreData trustStore = CloverSampleTr34KeyStoreData.KDH_1;
        Tr34TokenFactory factory = new Tr34TokenFactory(trustStore);

        X509Certificate oldKdhCert = Tr34CryptoUtils.parseCert(CloverSampleTr34KeyStoreData.TR34_KDH_1_Cert_Pem);

        Tr34CaUnbindToken caUnbindToken = factory.generateCaUnbindToken(krd1Chain, oldKdhCert);

        Tr34TokenClient client = new Tr34TokenClient(trustStore);
        client.verifyCaUnbindToken(caUnbindToken, krdCert, oldKdhCert);
    }

    @Test
    public void cloverGenerateCaRebindToken() throws Exception {
        Tr34KeyStoreData trustStore = CloverSampleTr34KeyStoreData.KDH_1;
        Tr34TokenFactory factory = new Tr34TokenFactory(trustStore);

        X509Certificate oldKdhCert = Tr34CryptoUtils.parseCert(CloverSampleTr34KeyStoreData.TR34_KDH_1_Cert_Pem);
        X509Certificate newKdhCert = Tr34CryptoUtils.parseCert(CloverSampleTr34KeyStoreData.TR34_KDH_2_Cert_Pem);

        Tr34CaRebindToken rebindToken = factory.generateCaRebindToken(krd1Chain, oldKdhCert, newKdhCert);

        Tr34TokenClient client = new Tr34TokenClient(trustStore);
        client.verifyCaRebindToken(rebindToken, krdCert, oldKdhCert);
    }

    @Test
    public void cloverGenerateKrdCredentialToken() {
        Tr34KrdCredentialToken ct = Tr34KrdCredentialToken.create(krdCert);
    }

    @Test
    public void cloverParseKrdCredentialToken() {
        Tr34KrdCredentialToken ct = Tr34KrdCredentialToken.decode(CloverSampleTr34Messages.CT_KRD_Pem);
    }

}

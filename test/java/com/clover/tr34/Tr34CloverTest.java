package com.clover.tr34;

import com.clover.tr34.samples.CloverDevTr34KeyStoreData;
import com.clover.tr34.samples.CloverSampleTr34Messages;
import org.bouncycastle.cms.CMSSignedData;

import org.junit.Test;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertEquals;


public class Tr34CloverTest {

    @Test
    public void cloverRandomTokenCreate() {
        byte[] rand = Tr34RandomToken.createNewRandom().getRandomNumber().getOctets();
        assertEquals(16, rand.length);
    }

    @Test
    public void cloverRandomTokenCreateAndParse() {
        byte[] rand = Tr34RandomToken.create(Tr34RandomToken.createNewRandom().toASN1Primitive())
                .getRandomNumber().getOctets();
        assertEquals(16, rand.length);
    }

    @Test
    public void cloverGenerateKdhCredentialToken() throws Exception {
        Tr34KeyStoreData keyStoreData = CloverDevTr34KeyStoreData.KDH_1;
        Tr34TokenFactory processor = new Tr34TokenFactory(keyStoreData);

        Tr34KdhCredentialToken kdhBindToken = processor.generateKdhCredentialToken(keyStoreData.getKdhRevocationList(),
                Tr34CryptoUtils.createHoursFromNowDate(24L * keyStoreData.nextCrlUpdateDays()));

        CMSSignedData cmsSignedData = kdhBindToken.getCMSSignedData();
        byte[] cmsDer = cmsSignedData.getEncoded();

        assertNotNull(cmsSignedData.getCertificates());
        assertEquals(1L, cmsSignedData.getCertificates().getMatches(Tr34CryptoUtils.ALL_CERT_SELECTOR).size());
        assertNotNull(cmsSignedData.getCRLs());
        assertEquals(1L, cmsSignedData.getCRLs().getMatches(Tr34CryptoUtils.ALL_CRL_SELECTOR).size());
    }

    @Test
    public void cloverGenerateKdhUnbindToken() throws Exception {
        Tr34KeyStoreData trustStore = CloverDevTr34KeyStoreData.KDH_1;
        X509Certificate krdCert = Tr34CryptoUtils.parseCert(CloverDevTr34KeyStoreData.TR34_KRD_1_Cert_Pem);
        Tr34RandomToken randomToken = Tr34RandomToken.createNewRandom();

        Tr34KdhUnbindToken unbindToken = Tr34KdhUnbindToken.create(randomToken, krdCert, trustStore.getKdhKeyStoreData());

        Tr34TokenFactory processor = new Tr34TokenFactory(trustStore);
        processor.verifyKdhUnbindToken(unbindToken, randomToken, krdCert);
    }

    @Test
    public void cloverTwoPassKeyTokenCreate() throws Exception {
        Tr34KeyStoreData trustStore = CloverDevTr34KeyStoreData.KDH_1;

        // Step 1: create a request
        Tr34RandomToken req = Tr34RandomToken.createNewRandom();
        X509Certificate krdCert = Tr34CryptoUtils.parseCert(CloverDevTr34KeyStoreData.TR34_KRD_1_Cert_Pem);
        PrivateKey krdPrivateKey = Tr34CryptoUtils.parsePrivateKey(CloverDevTr34KeyStoreData.TR34_KRD_1_PrivateKey_Pem);

        String header = Tr34KeyBlockHeaderFactory.createHeaderForAesTr31Kbk();
        byte[] symmetricAesKey = new byte[16];
        Tr34KeyBlock newKeyBlock = Tr34KeyBlock.create(header, symmetricAesKey, trustStore.getKdhCert());

        // Step 2: generate a response
        Tr34TwoPassKeyToken resp = Tr34TwoPassKeyToken.create(req, krdCert, newKeyBlock, trustStore.getKdhKeyStoreData());

        // Step 3: verify the response
        Tr34TokenFactory tr34Processor = new Tr34TokenFactory(trustStore);
        tr34Processor.verifyTwoPassKeyTokenResponse(resp, req);

        // Step 4: decrypt the response
        Tr34KeyBlock decryptedKeyBlock = tr34Processor.decrypt(resp, krdPrivateKey);

        assertEquals(newKeyBlock, decryptedKeyBlock);
    }

    @Test
    public void cloverKeyBlockCreate() {
        Tr34KeyStoreData trustStore = CloverDevTr34KeyStoreData.KDH_1;
        String header = "D0256K0AB00E0000";
        byte[] key = new byte[16];
        Tr34KeyBlock.create(header, key, trustStore.getKdhCert());
    }

    @Test
    public void cloverGenerateRebindToken() throws Exception {
        Tr34KeyStoreData trustStore = CloverDevTr34KeyStoreData.KDH_1;
        X509Certificate krdCert = Tr34CryptoUtils.parseCert(CloverDevTr34KeyStoreData.TR34_KRD_1_Cert_Pem);
        Tr34RandomToken randomToken = Tr34RandomToken.createNewRandom();

        X509Certificate newKdhCert = Tr34CryptoUtils.parseCert(CloverDevTr34KeyStoreData.TR34_KDH_2_Cert_Pem);

        Tr34KdhRebindToken rebindToken = Tr34KdhRebindToken.create(randomToken, krdCert, newKdhCert,
                trustStore.getKdhKeyStoreData());

        Tr34TokenFactory processor = new Tr34TokenFactory(trustStore);
        processor.verifyKdhRebindToken(rebindToken, randomToken, krdCert);
    }

    @Test
    public void cloverGenerateCaUnbindToken() throws Exception {
        Tr34KeyStoreData trustStore = CloverDevTr34KeyStoreData.KDH_1;
        X509Certificate krdCert = Tr34CryptoUtils.parseCert(CloverDevTr34KeyStoreData.TR34_KRD_1_Cert_Pem);

        X509Certificate oldKdhCert = Tr34CryptoUtils.parseCert(CloverDevTr34KeyStoreData.TR34_KDH_1_Cert_Pem);

        Tr34CaUnbindToken caUnbindToken = Tr34CaUnbindToken.create(krdCert, oldKdhCert, trustStore.getKrdCaKeyStoreData());

        Tr34TokenFactory processor = new Tr34TokenFactory(trustStore);
        processor.verifyCaUnbindToken(caUnbindToken, krdCert, oldKdhCert);
    }

    @Test
    public void cloverGenerateCaRebindToken() throws Exception {
        Tr34KeyStoreData trustStore = CloverDevTr34KeyStoreData.KDH_1;
        X509Certificate krdCert = Tr34CryptoUtils.parseCert(CloverDevTr34KeyStoreData.TR34_KRD_1_Cert_Pem);
        X509Certificate oldKdhCert = Tr34CryptoUtils.parseCert(CloverDevTr34KeyStoreData.TR34_KDH_1_Cert_Pem);
        X509Certificate newKdhCert = Tr34CryptoUtils.parseCert(CloverDevTr34KeyStoreData.TR34_KDH_2_Cert_Pem);

        Tr34CaRebindToken rebindToken = Tr34CaRebindToken.create(krdCert, oldKdhCert, newKdhCert, trustStore.getKrdCaKeyStoreData());

        Tr34TokenFactory processor = new Tr34TokenFactory(trustStore);
        processor.verifyCaRebindToken(rebindToken, krdCert, oldKdhCert);
    }

    @Test
    public void cloverParseKrdCredentialToken() {
        Tr34KrdCredentialToken.create(CloverSampleTr34Messages.CT_KRD_Pem);
    }

}

package com.clover.tr34;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Holds the identifying certificates and keys for one KDH operator and one KRD vendor. When the
 * KDH and KRD are operated by different organizations the private key material for only one
 * organization will be available.
 */
public abstract class Tr34KeyStoreData {

    /**
     * Per TR-34 both KRD and KDH must form a trusted relationship with the root CA.
     */
    public abstract X509Certificate getRootCert();

    public abstract X509Certificate getKdhCaCert();

    public abstract X509Certificate getKdhCert();

    public abstract X509Certificate getKrdCaCert();

    public abstract Tr34ScdKeyStoreData getKdhKeyStoreData();

    public abstract Tr34ScdKeyStoreData getKdhCaKeyStoreData();

    public abstract Tr34ScdKeyStoreData getKrdCaKeyStoreData();

    public abstract List<Tr34KdhRevocation> getKdhRevocationList();

    public abstract int nextCrlUpdateDays();

}

package com.clover.tr34;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Holder of a certificate and private key for one secure cryptographic device (SCD).
 */
public class Tr34ScdKeyStoreData {

    public final X509Certificate cert;
    public final PrivateKey privateKey;

    public Tr34ScdKeyStoreData(X509Certificate cert, PrivateKey privateKey) {
        this.cert = cert;
        this.privateKey = privateKey;
    }

}

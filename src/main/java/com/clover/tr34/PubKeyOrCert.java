package com.clover.tr34;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class PubKeyOrCert {

    X509Certificate cert;
    PublicKey pubKey;

    public PubKeyOrCert(PublicKey key) {
        pubKey = key;
    }

    public PubKeyOrCert(X509Certificate cert) {
        this.cert = cert;
    }

    boolean isCert() {
        return cert != null;
    }
}
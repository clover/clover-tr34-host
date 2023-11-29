package com.clover.tr34;

import java.math.BigInteger;
import java.security.cert.CRLReason;
import java.util.Date;

/**
 * Holds revocation details for a KDH certificate. Certificates are identified only by serial.
 */
public final class Tr34KdhRevocation {

    final BigInteger serial;
    final Date revocationDate;
    final CRLReason revocationReason;

    public Tr34KdhRevocation(BigInteger serial, Date revocationDate, CRLReason revocationReason) {
        this.serial = serial;
        this.revocationDate = revocationDate;
        this.revocationReason = revocationReason;
    }

    @Override
    public String toString() {
        return "CertRevocation{" +
                "serial=" + serial +
                ", revocationDate=" + revocationDate +
                ", revocationReason=" + revocationReason +
                '}';
    }
}

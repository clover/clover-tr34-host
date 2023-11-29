package com.clover.tr34;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.util.io.pem.PemGenerationException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;

import java.io.IOException;

/**
 * Utility class to encode TR-34 objects in PEM format. The TR-34 standard does not define
 * the descriptor strings.
 */
public final class Tr34PEMGenerator implements PemObjectGenerator {

    private final ASN1Object obj;

    public Tr34PEMGenerator(ASN1Object o) {
        this.obj = o;
    }

    @Override
    public PemObject generate() throws PemGenerationException {
        String  type;

        try {
            if (obj instanceof Tr34RandomToken) {
                type = "TR34 RANDOM TOKEN";
            } else if (obj instanceof Tr34TwoPassKeyToken) {
                type = "TR34 TWO PASS KEY TOKEN";
            } else if (obj instanceof Tr34KrdCredentialToken) {
                type = "TR34 KRD CREDENTIAL TOKEN";
            } else if (obj instanceof Tr34KdhCredentialToken) {
                type = "TR34 KDH BIND TOKEN";
            } else if (obj instanceof Tr34KdhUnbindToken) {
                type = "TR34 KDH UNBIND TOKEN";
            } else if (obj instanceof Tr34KdhRebindToken) {
                type = "TR34 KDH REBIND TOKEN";
            } else if (obj instanceof Tr34CaUnbindToken) {
                type = "TR34 CA UNBIND TOKEN";
            } else if (obj instanceof Tr34CaRebindToken) {
                type = "TR34 CA REBIND TOKEN";
            } else {
                throw new PemGenerationException("unknown object passed");
            }

            return new PemObject(type, obj.getEncoded());
        } catch (IOException e) {
            throw new PemGenerationException("failure", e);
        }
    }

}

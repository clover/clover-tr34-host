package com.clover.tr34;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemGenerationException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.IOException;
import java.io.StringWriter;

/**
 * Utility class to encode TR-34 objects in PEM format. The TR-34 standard does not define
 * the descriptor strings, these were chosen by Clover.
 */
public class Tr34PEMGenerator implements PemObjectGenerator {

    public static final String TR34_RANDOM_TOKEN = "TR34 RANDOM TOKEN";
    public static final String TR34_TWO_PASS_KEY_TOKEN = "TR34 TWO PASS KEY TOKEN";
    public static final String TR34_KRD_CREDENTIAL_TOKEN = "TR34 KRD CREDENTIAL TOKEN";
    public static final String TR34_KDH_CREDENTIAL_TOKEN = "TR34 KDH CREDENTIAL TOKEN";
    public static final String TR34_KDH_UNBIND_TOKEN = "TR34 KDH UNBIND TOKEN";
    public static final String TR34_KDH_REBIND_TOKEN = "TR34 KDH REBIND TOKEN";
    public static final String TR34_CA_UNBIND_TOKEN = "TR34 CA UNBIND TOKEN";
    public static final String TR34_CA_REBIND_TOKEN = "TR34 CA REBIND TOKEN";

    protected final ASN1Object obj;

    public Tr34PEMGenerator(ASN1Object o) {
        this.obj = o;
    }

    @Override
    public PemObject generate() throws PemGenerationException {
        String  type;

        try {
            if (obj instanceof Tr34RandomToken) {
                type = TR34_RANDOM_TOKEN;
            } else if (obj instanceof Tr34TwoPassKeyToken) {
                type = TR34_TWO_PASS_KEY_TOKEN;
            } else if (obj instanceof Tr34KrdCredentialToken) {
                type = TR34_KRD_CREDENTIAL_TOKEN;
            } else if (obj instanceof Tr34KdhCredentialToken) {
                type = TR34_KDH_CREDENTIAL_TOKEN;
            } else if (obj instanceof Tr34KdhUnbindToken) {
                type = TR34_KDH_UNBIND_TOKEN;
            } else if (obj instanceof Tr34KdhRebindToken) {
                type = TR34_KDH_REBIND_TOKEN;
            } else if (obj instanceof Tr34CaUnbindToken) {
                type = TR34_CA_UNBIND_TOKEN;
            } else if (obj instanceof Tr34CaRebindToken) {
                type = TR34_CA_REBIND_TOKEN;
            } else {
                throw new PemGenerationException("unknown object passed");
            }

            return new PemObject(type, obj.getEncoded());
        } catch (IOException e) {
            throw new PemGenerationException("failure", e);
        }
    }

    public static String encodeToPem(Object asn1) {
        try {
            StringWriter sw = new StringWriter();

            if (asn1 instanceof Tr34Object) {
                try (PemWriter pw = new PemWriter(sw)) {
                    pw.writeObject(new Tr34PEMGenerator((ASN1Object) asn1).generate());
                }
            } else {
                try (JcaPEMWriter jpw = new JcaPEMWriter(sw)) {
                    jpw.writeObject(asn1);
                }
            }

            return sw.toString();
        } catch (IOException e) {
            throw new Tr34Exception(e);
        }
    }

}

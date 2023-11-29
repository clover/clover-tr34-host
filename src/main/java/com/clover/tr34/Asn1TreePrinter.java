package com.clover.tr34;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

import java.io.IOException;
import java.lang.reflect.Field;
import java.text.ParseException;
import java.util.HashMap;

/**
 * Prints ASN.1 trees in a human-readable form.
 */
public final class Asn1TreePrinter {

    private static final HashMap<ASN1ObjectIdentifier, String> sAsn1IdNameMap = new HashMap<>();

    static {
        populateIdNameMap(PKCSObjectIdentifiers.class);
        populateIdNameMap(NISTObjectIdentifiers.class);
        populateIdNameMap(X509ObjectIdentifiers.class);
        populateIdNameMap(Tr34ObjectIdentifiers.class);
    }

    private static void populateIdNameMap(Class<?> clazz) {
        for (Field field : clazz.getDeclaredFields()) {
            String name = field.getName();

            try {
                Object value = field.get(PKCSObjectIdentifiers.class);
                if (value instanceof ASN1ObjectIdentifier) {
                    sAsn1IdNameMap.put((ASN1ObjectIdentifier) value, name);
                }
            } catch (IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private int indent = 0;
    private ASN1Encodable obj;

    public Asn1TreePrinter(ASN1Encodable obj) {
        this.obj = obj;
    }

    public void print() {
        print(obj);
        System.out.println();
    }

    private void printIndent() {
        System.out.println();
        for (int i = 0; i < indent; i++) {
            System.out.print(" ");
        }
    }

    private void print(ASN1Encodable obj) {
        printIndent();
        System.out.print(obj.getClass().getSimpleName());

        if (obj instanceof ASN1String) {
            ASN1String as = (ASN1String) obj;
            System.out.print(" string(\"" + as.getString() + "\")");
        }

        indent += 2;

        if (obj instanceof ASN1Sequence) {
            for (ASN1Encodable asn1Encodable : (ASN1Sequence) obj) {
                print(asn1Encodable);
            }
        } else if (obj instanceof ASN1Set) {
            for (ASN1Encodable asn1Encodable : (ASN1Set) obj) {
                print(asn1Encodable);
            }
        } else if (obj instanceof ASN1TaggedObject) {
            ASN1TaggedObject ato = (ASN1TaggedObject) obj;
            System.out.print(" class (" + ato.getTagClass() + ") tag (" + ato.getTagNo() + ")");
            print(ato.getBaseObject());
        } else if (obj instanceof ASN1Integer) {
            ASN1Integer ai = (ASN1Integer) obj;
            System.out.print(" value (" + ai.getValue() + ")");
        } else if (obj instanceof ASN1ObjectIdentifier) {
            ASN1ObjectIdentifier aio = (ASN1ObjectIdentifier) obj;
            String obIdName = sAsn1IdNameMap.get(aio);
            if (obIdName == null) {
                obIdName = "unknown";
            }
            System.out.print(" id (" + aio.getId() + ") pkcs (" + obIdName + ")");
        } else if (obj instanceof ASN1OctetString) {
            ASN1OctetString aos = (ASN1OctetString) obj;
            System.out.print(" size (" + aos.getOctetsLength() + ")");
            try {
                ASN1Primitive inner = ASN1Primitive.fromByteArray(aos.getOctets());
                if (inner != null) {
                    print(inner);
                }
            } catch (IOException e) {
                // ignored
            }
        } else if (obj instanceof ASN1UTCTime) {
            try {
                System.out.print(" utctime (" + ((ASN1UTCTime) obj).getDate() + ")");
            } catch (ParseException e) {
                System.out.print(" utctime (parse err)");
            }
        }

        indent -=2;
    }


}

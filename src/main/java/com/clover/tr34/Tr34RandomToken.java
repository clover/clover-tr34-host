package com.clover.tr34;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSet;

import java.security.SecureRandom;


/**
 * See B.12 RTKRD – KRD Random Number Token
 */
public class Tr34RandomToken extends Tr34Object {

    private static final SecureRandom sRand = new SecureRandom();

    private final ASN1Sequence rootNode;

    private Tr34RandomToken(ASN1Sequence asn1) {
        this.rootNode = asn1;
    }

    public static Tr34RandomToken decode(Object encoded) {
        return new Tr34RandomToken((ASN1Sequence) Tr34CryptoUtils.decodeToAsn1(encoded));
    }

    public static Tr34RandomToken create(byte[] nonce) {
        ASN1OctetString random = new DEROctetString(nonce);
        ASN1Set set = new DLSet(random);
        return new Tr34RandomToken(new DLSequence(new ASN1Encodable[] { Tr34ObjectIdentifiers.randomNonce, set }));
    }

    public static Tr34RandomToken createNewRandom() {
        byte[] nonce = new byte[16];
        sRand.nextBytes(nonce);
        return create(nonce);
    }

    public ASN1OctetString getRandomNumber() {
        // Must be pkcs-9-at-randomNonce
        ASN1ObjectIdentifier identifier = (ASN1ObjectIdentifier) rootNode.getObjectAt(0);
        if (!Tr34ObjectIdentifiers.randomNonce.equals(identifier)) {
            throw new Tr34Exception("Invalid random token identifier");
        }

        ASN1Set set = (ASN1Set) rootNode.getObjectAt(1);
        ASN1OctetString octetString = (ASN1OctetString) set.getObjectAt(0);

        // ASC X9 TR 34 samples use either 8 or 16
        if (octetString.getOctetsLength() < 8 || octetString.getOctetsLength() > 16) {
            throw new Tr34Exception("Unsupported nonce length: " + octetString.getOctetsLength());
        }

        return octetString;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return rootNode;
    }
}

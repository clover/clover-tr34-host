package com.clover.tr34;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x509.Certificate;

import java.security.cert.X509Certificate;

/**
 * See 5.4.2 TR34 Attribute Header.
 */
public final class Tr34KeyBlock extends Tr34Object {

    private final ASN1Sequence rootNode;
    private final ASN1Sequence keyHeaderSeq;
    private final ASN1Integer version;
    private final IssuerAndSerialNumber issuerAndSerialNumber;
    private final ASN1OctetString clearKey;
    private final ASN1OctetString keyHeader;

    /**
     * Note that the specification describes enum v1 as having value 0 but in the B.2.2.2.4 sample
     * the integer value 1 is used. It is presumed that the ASN.1 specification is incorrect and v1
     * should actually have the integer value 1.
     * <p>
     * See Annex D:
     * <pre>
     * KeyBlock ::= SEQUENCE {
     *      version        INTEGER { v1(0) },
     *      idKDH          SignerIdentifier,
     *      clearKey       ClearKey,
     *      keyBlockHeader KeyBlockHeader
     * }
     * </pre>
     */
    public static final long VERSION_1 = 1;

    public static Tr34KeyBlock create(Object encoded) {
        return new Tr34KeyBlock((ASN1Sequence) Tr34CryptoUtils.decodeToAsn1(encoded));
    }

    public static Tr34KeyBlock create(String header, byte[] symmetricKey, X509Certificate kdhLeafCert) {
        try {
            ASN1Integer version = new ASN1Integer(VERSION_1);
            IssuerAndSerialNumber issuerAndSerialNumber =
                    new IssuerAndSerialNumber(Certificate.getInstance(kdhLeafCert.getEncoded()));
            ASN1OctetString clearKey = new DEROctetString(symmetricKey);
            ASN1OctetString keyHeader = new DEROctetString(header.getBytes());
            ASN1Set keyHeaderSet = new DLSet(keyHeader);
            ASN1Sequence keyHeaderSeq = new DLSequence(new ASN1Encodable[] { CMSObjectIdentifiers.data, keyHeaderSet });

            return new Tr34KeyBlock(new DLSequence(new ASN1Encodable[] { version, issuerAndSerialNumber, clearKey, keyHeaderSeq }));
        } catch (Exception e) {
            throw new Tr34Exception(e);
        }
    }

    public Tr34KeyBlock(ASN1Sequence asn1) {

        if (asn1.size() != 4) {
            throw new Tr34Exception("Invalid key block content");
        }

        version = (ASN1Integer) asn1.getObjectAt(0);
        if (version.longValueExact() != VERSION_1) {
            throw new Tr34Exception("Unsupported key block version: " + version.longValueExact());
        }

        issuerAndSerialNumber = IssuerAndSerialNumber.getInstance(asn1.getObjectAt(1));

        clearKey = (ASN1OctetString) asn1.getObjectAt(2);
        if (clearKey.getOctetsLength() != 16 && clearKey.getOctetsLength() != 24) {
            throw new Tr34Exception("Symmetric key must be 128 bit or 192 bit");
        }

        keyHeaderSeq = (ASN1Sequence) asn1.getObjectAt(3);
        if (keyHeaderSeq.size() != 2) {
            throw new Tr34Exception("Invalid key header sequence size");
        }
        if (!keyHeaderSeq.getObjectAt(0).equals(CMSObjectIdentifiers.data)) {
            throw new Tr34Exception("Invalid key header sequence identifier");
        }

        ASN1Set keyHeaderSet = (ASN1Set) keyHeaderSeq.getObjectAt(1);
        if (keyHeaderSet.size() != 1) {
            throw new Tr34Exception("Invalid key header set size");
        }
        keyHeader = (ASN1OctetString) keyHeaderSet.getObjectAt(0);
        if (keyHeader.getOctetsLength() != 16) {
            throw new Tr34Exception("Key header must be 16 chars");
        }

        rootNode = asn1;
    }

    public ASN1Sequence getFullKeyHeader() {
        return keyHeaderSeq;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return rootNode;
    }

}

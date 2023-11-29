package com.clover.tr34;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DLSet;

/**
 * Bouncy castle resorts DLSets when encoding, this is a hack to not do that.
 */
public class DLSetWithoutReSort extends DLSet {

    static ASN1Encodable[] getElements(DLSet set) {
        ASN1Encodable[] elements = new ASN1Encodable[set.size()];
        int i = 0;
        for (ASN1Encodable e : set) {
            elements[i++] = e;
        }
        return elements;
    }

    protected DLSetWithoutReSort(DLSet set) {
        super(getElements(set));
        sortedElements = elements;
    }

}

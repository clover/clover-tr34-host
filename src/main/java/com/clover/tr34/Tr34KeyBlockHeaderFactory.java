package com.clover.tr34;


final class Tr34KeyBlockHeaderFactory {

    // Note: Care should be taken to ensure that this field does not denote the
    // length of the key, as this will leak potentially sensitive information.

    // K1 : TR-31 Key Block Protection Key
    // D : For decrypting only
    // N : Is non-exportable by the receiving SCD (For Key Blocks being
    //     transmitted, exportability is in the context of the recipient SCD.)

    public static String createHeaderForTdesTr31Kbk() {
        return "B0000K1TD00N0000";
    }

    public static String createHeaderForAesTr31Kbk() {
        return "D0000K1AD00N0000";
    }

}

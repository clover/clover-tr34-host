package com.clover.tr34;


final class Tr34KeyBlockHeaderFactory {

    // Note: Care should be taken to ensure that this field does not denote the
    // length of the key, as this will leak potentially sensitive information.

    // K1 : TR-31 Key Block Protection Key
    // D : For decrypting only
    // E : Is exportable

    public static String createHeaderForTdesTr31Kbk() {
        return "A0000K1TD00E0000";
    }

    public static String createHeaderForAesTr31Kbk() {
        return "D0000K1AD00E0000";
    }

}

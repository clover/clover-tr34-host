package com.clover.tr34.samples;

/**
 * Samples from ASC X9 TR34 2019 standards document and errata document.
 * <p>
 * <b>ALL SAMPLES ARE REDACTED FOR COPYRIGHT</b>. Purchase a copy of the TR-34
 * specification and paste the corresponding PEM strings to test.
 * <p>
 * Warning: samples are not totally reliable, see docs for each sample for
 * details.
 */
public final class AscSampleTr34Messages {

    /**
     * B.12 RTKRD – KRD Random Number Token
     */
    public static final String RKRD_PEM =
            "redacted";

    /**
     * ASC X9 TR 34-2019 Corrigendum (Errata)
     * B.9.1 2 Pass Key Token
     * <p>
     * BouncyCastle CMS verify doesn't work on this sample for several reasons:
     * <br>
     * See <a href="https://github.com/bcgit/bc-java/issues/1484">bc-java issue 1484</a>
     * <br>
     * See <a href="https://github.com/openssl/openssl/issues/22120">openssl issue 22120</a>
     * <p>
     * Furthermore, something the RSA OAEP params are not encoded in the ASN.1 form specified in
     * RFC 8017 section A.2.1 titled "RSAES-OAEP", even after correcting the params there is
     * something wrong with the encryption and both OpenJDK and Bouncy Castle crypto providers
     * fail when trying to decrypt it.
     */
    public static final String SAMPLE_KDH_KT_2_PASS_FOR_KRD_1_CMS =
            "redacted";

    /**
     * B.11 RBTKDH – KDH Rebind Token
     * <p>
     * This particular sample is encoded incorrectly. The eContent is not a SignedData
     * sequence but is instead the streamed guts of a SignedData without the sequence.
     * Best assumption is that it is malformed by accident since it really isn't valid
     * ASN.1 as it is, and also since the description at B.11 RBTKDH – KDH Rebind Token
     * specifically says it should be a SEQUENCE, notice:
     * <pre>
     * eContentType ContentType, -- id-signedData
     * eContent [0] EXPLICIT OCTET STRING OPTIONAL {
     *   SignedData ::= SEQUENCE {
     *     version Version (v3 | vx9-73, ...),
     *     digestAlgorithms DigestAlgorithmIdentifiers, -- no digest algorithms
     *     -- ...
     *   }
     * }
     * </pre>
     */
    public static final String SAMPLE_REBIND_KDH_TOKEN_PEM =
            "redacted";

    /**
     * Extracted from B.6 CTKDH – The KDH Credential Token
     */
    public static final String SAMPLE_KDH_1_PUB_KEY_PEM =
            "redacted";

    /**
     * B.2.2.2.4 Sample AES Key Block Using IssuerAndSerialNumber
     */
    public static final String SAMPLE_CLEAR_AES_KEY_BLOCK =
            "redacted";

    /**
     * B.6 CTKDH – The KDH Credential Token
     */
    public static final String SAMPLE_CT_KDH_PEM =
            "redacted";

    /**
     * B.14 UBTKDH – KDH Unbind Token
     */
    public static final String SAMPLE_UBT_KDH_PEM =
            "redacted";

    /**
     * B.13 UBTCA_UNBIND – Higher Level Authority Unbind Token
     */
    public static final String SAMPLE_UBT_CA_PEM =
            "redacted";

    /**
     * B.10 RBTCA_UNBIND – Higher Level Authority Rebind Token
     * <p>
     * This particular sample is encoded incorrectly. The eContent is not a SignedData
     * sequence but is instead the streamed guts of a SignedData without the sequence.
     * <p>
     * Same problem as {@link #SAMPLE_REBIND_KDH_TOKEN_PEM}.
     */
    public static final String SAMPLE_RBT_CA_PEM =
            "redacted";

    /**
     * B.7 CTKRD - The KRD Credential Token
     */
    public static final String SAMPLE_CT_KRD_PEM =
            "redacted";
}

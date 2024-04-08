package com.clover.tr34;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.PKIXRevocationChecker.Option;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Simplifies validation of certificates.
 */
public class Tr34CertValidator {

    private static final String PKIX = "PKIX";

    private final CertStore certStore;
    private final Set<Option> revocationCheckerOptions;
    private final Set<TrustAnchor> trustAnchors;
    private Provider provider;
    private boolean validateDates = true;

    /**
     * Constructor
     *
     * @param trustAnchors Provides root of trust certificates
     * @param certStore Provides CRLs
     * @param revocationCheckerOptions Options to use when checking certificate revocation
     */
    public Tr34CertValidator(Set<TrustAnchor> trustAnchors, CertStore certStore, Set<Option> revocationCheckerOptions) {
        if (trustAnchors == null || trustAnchors.isEmpty()) {
            throw new IllegalArgumentException("Need at least one trust anchor");
        }

        this.trustAnchors = Collections.unmodifiableSet(trustAnchors);
        this.certStore = certStore;
        if (revocationCheckerOptions == null) {
            this.revocationCheckerOptions = null;
        } else {
            if (certStore == null) {
                throw new IllegalArgumentException("Revocation options require CertStore");
            }
            this.revocationCheckerOptions = Collections.unmodifiableSet(revocationCheckerOptions);
        }
    }

    public Tr34CertValidator(TrustAnchor... trustAnchors) {
        this(new HashSet<>(Arrays.asList(trustAnchors)), null, null);
    }

    public Tr34CertValidator withProvider(Provider provider) {
        this.provider = provider;
        return this;
    }

    public Tr34CertValidator withoutDateValidation() {
        this.validateDates = false;
        return this;
    }

    /**
     * Validate the certificate chain against the trust anchors. Throws SecurityException on any error or validation
     * failure. If successful the TrustAnchor against which the chain validated is returned.
     */
    public TrustAnchor validate(CertPath certPath) throws SecurityException {
        try {
            CertPathValidator cpv = CertPathValidator.getInstance(PKIX, provider);
            PKIXRevocationChecker rc = (PKIXRevocationChecker) cpv.getRevocationChecker();
            PKIXParameters certPathParameters = new PKIXParameters(trustAnchors);

            if (certStore != null) {
                rc.setOptions(revocationCheckerOptions);
                certPathParameters.addCertPathChecker(rc);
                certPathParameters.addCertStore(certStore);
                certPathParameters.setRevocationEnabled(true);
            } else {
                certPathParameters.setRevocationEnabled(false);
            }

            if (!validateDates) {
                List<X509Certificate> dateInvariantCerts = new ArrayList<>();
                for (Certificate cert : certPath.getCertificates()) {
                    dateInvariantCerts.add(new DateInvariantX509Certificate((X509Certificate) cert));
                }

                certPath = CertificateFactory.getInstance("X.509", provider).generateCertPath(dateInvariantCerts);
            }

            PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) cpv.validate(certPath, certPathParameters);

            List<CertPathValidatorException> softErrs = rc.getSoftFailExceptions();
            if (softErrs != null) {
                for (CertPathValidatorException e : softErrs) {
                    System.out.println("Warning during validation (soft): " + e);
                }
            }
            return result.getTrustAnchor();
        } catch (GeneralSecurityException e) {
            throw new SecurityException("Certificate validation failed", e);
        }
    }

    private static class DateInvariantX509Certificate extends X509Certificate {

        private final X509Certificate orig;

        DateInvariantX509Certificate(X509Certificate orig) {
            if (orig == null) {
                throw new NullPointerException();
            }
            this.orig = orig;
        }

        @Override
        public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
            // Allow any date
        }

        @Override
        public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
            // Allow any date
        }

        @Override
        public Set<String> getCriticalExtensionOIDs() {
            return orig.getCriticalExtensionOIDs();
        }

        @Override
        public byte[] getExtensionValue(String oid) {
            return orig.getExtensionValue(oid);
        }

        @Override
        public Set<String> getNonCriticalExtensionOIDs() {
            return orig.getNonCriticalExtensionOIDs();
        }

        @Override
        public boolean hasUnsupportedCriticalExtension() {
            return orig.hasUnsupportedCriticalExtension();
        }

        @Override
        public int getBasicConstraints() {
            return orig.getBasicConstraints();
        }

        @Override
        public Principal getIssuerDN() {
            return orig.getIssuerDN();
        }

        @Override
        public boolean[] getIssuerUniqueID() {
            return orig.getIssuerUniqueID();
        }

        @Override
        public boolean[] getKeyUsage() {
            return orig.getKeyUsage();
        }

        @Override
        public Date getNotAfter() {
            return new Date(Long.MAX_VALUE);
        }

        @Override
        public Date getNotBefore() {
            return new Date(Long.MIN_VALUE);
        }

        @Override
        public BigInteger getSerialNumber() {
            return orig.getSerialNumber();
        }

        @Override
        public String getSigAlgName() {
            return orig.getSigAlgName();
        }

        @Override
        public String getSigAlgOID() {
            return orig.getSigAlgOID();
        }

        @Override
        public byte[] getSigAlgParams() {
            return orig.getSigAlgParams();
        }

        @Override
        public byte[] getSignature() {
            return orig.getSignature();
        }

        @Override
        public Principal getSubjectDN() {
            return orig.getSubjectDN();
        }

        @Override
        public boolean[] getSubjectUniqueID() {
            return orig.getSubjectUniqueID();
        }

        @Override
        public byte[] getTBSCertificate() throws CertificateEncodingException {
            return orig.getTBSCertificate();
        }

        @Override
        public int getVersion() {
            return orig.getVersion();
        }

        @Override
        public byte[] getEncoded() throws CertificateEncodingException {
            return orig.getEncoded();
        }

        @Override
        public PublicKey getPublicKey() {
            return orig.getPublicKey();
        }

        @Override
        public String toString() {
            return orig.toString();
        }

        @Override
        public void verify(PublicKey key) throws CertificateException, InvalidKeyException,
                NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
            orig.verify(key);
        }

        @Override
        public void verify(PublicKey key, String sigProvider) throws CertificateException,
                InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
                SignatureException {
            orig.verify(key, sigProvider);
        }

        @Override
        public List<String> getExtendedKeyUsage() throws CertificateParsingException {
            return orig.getExtendedKeyUsage();
        }

        @Override
        public Collection<List<?>> getIssuerAlternativeNames() throws CertificateParsingException {
            return orig.getIssuerAlternativeNames();
        }

        @Override
        public X500Principal getIssuerX500Principal() {
            return orig.getIssuerX500Principal();
        }

        @Override
        public Collection<List<?>> getSubjectAlternativeNames() throws CertificateParsingException {
            return orig.getSubjectAlternativeNames();
        }

        @Override
        public X500Principal getSubjectX500Principal() {
            return orig.getSubjectX500Principal();
        }

        @Override
        public boolean equals(Object other) {
            return orig.equals(other);
        }

        @Override
        public int hashCode() {
            return orig.hashCode();
        }
    }
}
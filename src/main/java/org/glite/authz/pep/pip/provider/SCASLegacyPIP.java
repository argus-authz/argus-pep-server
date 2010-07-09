/*
 * Copyright (c) Members of the EGEE Collaboration. 2006-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.glite.authz.pep.pip.provider;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;

import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Subject;
import org.glite.authz.pep.pip.PIPProcessingException;
import org.glite.voms.FQAN;
import org.glite.voms.PKIStore;
import org.glite.voms.PKIUtils;
import org.glite.voms.VOMSAttribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A policy information point that extracts information from a X.509, version 3, certificate. The certificate may
 * include VOMS attribute certificates. All extract information is added to the subject(s) containing a valid
 * certificate chain.
 * 
 * The PEM encoded end entity certificate, and its certificate chain, are expected to be bound to the subject attribute
 * {@value #X509_CERT_CHAIN_ID}. Only one end-entity certificate may be present in the chain. If the end entity
 * certificate contains a VOMS attribute certificate, and VOMS certificate validation is enabled, information from that
 * attribute certificate will also be added to the subject. Only one VOMS attribute certificate may be present in the
 * end-entity certificate.
 * 
 * @see <a href="https://twiki.cnaf.infn.it/cgi-bin/twiki/view/VOMS">VOMS website</a>
 */
public class SCASLegacyPIP extends AbstractX509PIP {

    /**
     * The ID of the subject attribute, {@value} , containing the end-entity certificate's issuer's DN in the
     * non-standard OpenSSL format.
     */
    public static final String SUBJECT_X509_ID = "http://authz-interop.org/xacml/subject/subject-x509-id";

    /** The ID of the subject attribute, {@value} , containing the end-entity certificate's issuer's DN. */
    public static final String X509_DN_ISSUER = "http://authz-interop.org/xacml/subject/subject-x509-issuer";

    /** The ID of the subject attribute, {@value} , containing the VO given in the VOMS attribute certificate. */
    public static final String VOMS_VO = "http://authz-interop.org/xacml/subject/vo";

    /**
     * The ID of the subject attribute, {@value} , containing the DN of the VOMS service that signed the VOMS attribute
     * certificate.
     */
    public static final String VOMS_SIGNER = "http://authz-interop.org/xacml/subject/voms-signing-subject";

    /** The ID of the subject attribute, {@value} , containing the DN of the signer of the VOMS service's certificate. */
    public static final String VOMS_SIGNER_ISSUER = "http://authz-interop.org/xacml/subject/voms-signing-issuer";

    /** The ID of the subject attribute, {@value} , containing the FQANs given in the VOMS attribute certificate. */
    public static final String VOMS_FQAN = "http://authz-interop.org/xacml/subject/voms-fqan";

    /** The ID of the subject attribute, {@value} , containing the primary FQAN given in the VOMS attribute certificate. */
    public static final String VOMS_PRIMARY_FQAN = "http://authz-interop.org/xacml/subject/voms-primary-fqan";

    /** The ID of the subject attribute, {@value} , containing the end-entity certificate's serial number. */
    public static final String X509_SN = "http://authz-interop.org/xacml/subject/certificate-serial-number";

    /** The ID of the subject attribute, {@value} , containing the end-entity certificate's serial number. */
    public static final String X509_CA_SN = "http://authz-interop.org/xacml/subject/ca-serial-number";

    /** The ID of the subject attribute, {@value} , containing the VOMS server hostname and port. */
    public static final String VOMS_DNS_PORT = "http://authz-interop.org/xacml/subject/voms-dns-port";

    /** The ID of the subject attribute, {@value} , containing the end entity certificate CA policy OID. */
    public static final String CA_POLICY_OID = "http://authz-interop.org/xacml/subject/ca-policy-oid";

    /** The ID of the subject attribute, {@value} , containing the end-entity certificate processed by the PIP. */
    public static final String X509_CERT_CHAIN_ID = "http://authz-interop.org/xacml/subject/cert-chain";

    /**
     * The ID of the subject attribute, {@value} , containing the generic attributes given in the VOMS attribute
     * certificate.
     */
    public static final String VOMS_GA = "http://authz-interop.org/xacml/subject/generic-attribute";

    /** Class logger. */
    private Logger log = LoggerFactory.getLogger(SCASLegacyPIP.class);

    /**
     * The constructor for this PIP. This constructor enables support for the VOMS attribute certificates.
     * 
     * @param pipID ID of this PIP
     * @param requireProxy whether a subject's certificate chain must require a proxy in order to be valid
     * @param eeTrustMaterial trust material used to validate the subject's end entity certificate
     * @param acTrustMaterial trust material used to validate the subject's attribute certificate certificate, may be
     *            null of AC support is not desired
     * 
     * @throws ConfigurationException thrown if the configuration of the PIP fails
     */
    public SCASLegacyPIP(String pipID, boolean requireProxy, PKIStore eeTrustMaterial, PKIStore acTrustMaterial)
            throws ConfigurationException {
        super(pipID, requireProxy, eeTrustMaterial, acTrustMaterial);
    }

    /** {@inheritDoc} */
    protected String getCertificateAttributeId() {
        return X509_CERT_CHAIN_ID;
    }

    /** {@inheritDoc} */
    protected boolean appliesToRequest(Request request) {
        for (Subject subject : request.getSubjects()) {
            for (Attribute attrib : subject.getAttributes()) {
                if (X509_CERT_CHAIN_ID.equals(attrib.getId())) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Processes one certificate chain and adds the information to the subjects in the request.
     * 
     * @param endEntityCertificate end entity certificate for the subject currently being processed
     * @param certChain the certificate chain containing the end entity certificate from which information will be
     *            extracted
     * 
     * @return the attribute extracted from the certificate chain
     * 
     * @throws PIPProcessingException thrown if there is a problem reading the information from the certificate chain
     */
    protected Collection<Attribute> processCertChain(X509Certificate endEntityCertificate, X509Certificate[] certChain)
            throws PIPProcessingException {
        if (endEntityCertificate == null || certChain == null || certChain.length == 0) {
            return null;
        }
        X509Certificate caCert = null;
        for (X509Certificate cert : certChain) {
            if (cert.getSubjectX500Principal().equals(endEntityCertificate.getIssuerX500Principal())) {
                caCert = cert;
            }
        }
        if (caCert == null) {
            throw new PIPProcessingException("CA for the end entity certificate was not found in the cert chain");
        }

        log.debug("Extracting end-entity certificate attributes");
        HashSet<Attribute> subjectAttributes = new HashSet<Attribute>();

        // subject X509 ID
        Attribute attribute = new Attribute();
        attribute.setId(SUBJECT_X509_ID);
        attribute.setDataType(Attribute.DT_STRING);
        attribute.getValues().add(PKIUtils.getOpenSSLFormatPrincipal(endEntityCertificate.getSubjectX500Principal()));
        log.debug("Extracted attribute: {}", attribute);
        subjectAttributes.add(attribute);

        // X509 issuer
        attribute = new Attribute();
        attribute.setId(X509_DN_ISSUER);
        attribute.setDataType(Attribute.DT_STRING);
        attribute.getValues().add(PKIUtils.getOpenSSLFormatPrincipal(endEntityCertificate.getIssuerX500Principal()));
        log.debug("Extracted attribute: {}", attribute);
        subjectAttributes.add(attribute);

        // cert serial number
        attribute = new Attribute();
        attribute.setId(X509_SN);
        attribute.setDataType(Attribute.DT_INTEGER);
        attribute.getValues().add(endEntityCertificate.getSerialNumber().toString());
        log.debug("Extracted attribute: {}", attribute);
        subjectAttributes.add(attribute);

        // CA cert serial number
        attribute = new Attribute();
        attribute.setId(X509_CA_SN);
        attribute.setDataType(Attribute.DT_INTEGER);
        attribute.getValues().add(caCert.getSerialNumber().toString());
        log.debug("Extracted attribute: {}", attribute);
        subjectAttributes.add(attribute);

        if (isVOMSSupportEnabled()) {
            Collection<Attribute> vomsAttributes = processVOMS(endEntityCertificate, certChain);
            if (vomsAttributes != null) {
                subjectAttributes.addAll(vomsAttributes);
            }
        }

        return subjectAttributes;
    }

    /**
     * Processes the VOMS attributes and puts valid attributes into the subject object.
     * 
     * @param endEntityCert the end entity certificate for the subject being processed
     * @param certChain certificate chain containing the end entity certificate that contains the VOMS attribute
     *            certificate
     * 
     * @return the attributes extracted from the VOMS attribute certificate
     * 
     * @throws PIPProcessingException thrown if the end entity certificate contains more than one attribute certificate
     */
    @SuppressWarnings("unchecked")
    private Collection<Attribute> processVOMS(X509Certificate endEntityCert, X509Certificate[] certChain)
            throws PIPProcessingException {

        log.debug("Extracting VOMS attribute certificate attributes");
        VOMSAttribute attributeCertificate = extractAttributeCertificate(certChain);
        if (attributeCertificate == null) {
            return null;
        }

        HashSet<Attribute> vomsAttributes = new HashSet<Attribute>();

        // vo
        Attribute attribute = new Attribute();
        attribute.setId(VOMS_VO);
        attribute.setDataType(Attribute.DT_STRING);
        attribute.getValues().add(attributeCertificate.getVO());
        log.debug("Extracted attribute: {}", attribute);
        vomsAttributes.add(attribute);

        // voms signing subject
        attribute = new Attribute();
        attribute.setId(VOMS_SIGNER);
        attribute.setDataType(Attribute.DT_STRING);
        attribute.getValues().add(attributeCertificate.getIssuer());
        vomsAttributes.add(attribute);

        // voms signing issuer
        X509Certificate vomsServerIssuer = (X509Certificate)(attributeCertificate.getCertList().getCerts().get(1));
        attribute = new Attribute();
        attribute.setId(VOMS_SIGNER_ISSUER);
        attribute.setDataType(Attribute.DT_STRING);
        attribute.getValues().add(PKIUtils.getOpenSSLFormatPrincipal(vomsServerIssuer.getSubjectX500Principal()));
        vomsAttributes.add(attribute);

        // Primary and secondary FQANs
        List<FQAN> fqans = attributeCertificate.getListOfFQAN();
        if (fqans != null && !fqans.isEmpty()) {
            Attribute primaryFqanAttribute = new Attribute();
            primaryFqanAttribute.setId(VOMS_PRIMARY_FQAN);
            primaryFqanAttribute.setDataType(Attribute.DT_STRING);
            primaryFqanAttribute.getValues().add(fqans.get(0).getFQAN());
            log.debug("Extracted attribute: {}", primaryFqanAttribute);
            vomsAttributes.add(primaryFqanAttribute);

            // handle rest of the fqans
            Attribute fqanAttribute = new Attribute();
            fqanAttribute.setId(VOMS_FQAN);
            fqanAttribute.setDataType(Attribute.DT_STRING);
            for (FQAN fqan : fqans) {
                fqanAttribute.getValues().add(fqan.getFQAN());
            }
            log.debug("Extracted attribute: {}", fqanAttribute);
            vomsAttributes.add(fqanAttribute);
        }

        // VOMS DNS and Port
        attribute = new Attribute();
        attribute.setId(VOMS_DNS_PORT);
        attribute.setDataType(Attribute.DT_STRING);
        attribute.getValues().add(attributeCertificate.getHostPort());
        vomsAttributes.add(attribute);

        return vomsAttributes;
    }
}
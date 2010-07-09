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

import javax.security.auth.x500.X500Principal;

import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Environment;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.profile.WorkerNodeProfileV1Constants;
import org.glite.authz.pep.pip.PIPProcessingException;
import org.glite.voms.FQAN;
import org.glite.voms.PKIStore;
import org.glite.voms.VOMSAttribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A policy information point that extracts information from a X.509, version 3, certificate. The certificate may
 * include VOMS attribute certificates. All extract information is added to the subject(s) containing a valid
 * certificate chain.
 * 
 * The PEM encoded end entity certificate, and its certificate chain, are expected to be bound to the subject attribute
 * {@value Attribute#ID_SUB_KEY_INFO}. Only one end-entity certificate may be present in the chain. If the end entity
 * certificate contains a VOMS attribute certificate, and VOMS certificate validation is enabled, information from that
 * attribute certificate will also be added to the subject. Only one VOMS attribute certificate may be present in the
 * end-entity certificate.
 * 
 * @see <a href="https://twiki.cnaf.infn.it/cgi-bin/twiki/view/VOMS">VOMS website</a>
 */
public class WorkerNodeProfileV1 extends AbstractX509PIP {

    /** Class logger. */
    private Logger log = LoggerFactory.getLogger(WorkerNodeProfileV1.class);

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
    public WorkerNodeProfileV1(String pipID, boolean requireProxy, PKIStore eeTrustMaterial, PKIStore acTrustMaterial)
            throws ConfigurationException {
        super(pipID, requireProxy, eeTrustMaterial, acTrustMaterial);
    }

    /**
     * Checks whether this PIP applies to this request.
     * 
     * @param request the incoming request to be checked
     * 
     * @return true if this PIP applies to the request, false if not
     */
    protected boolean appliesToRequest(Request request) {
        Environment env = request.getEnvironment();
        if (env != null) {
            for (Attribute attrib : env.getAttributes()) {
                if (WorkerNodeProfileV1Constants.ATT_PROFILE_ID.equals(attrib.getId())
                        && attrib.getValues().contains(WorkerNodeProfileV1Constants.PRO_ID)) {
                    return true;
                }
            }
        }

        log.debug("Skipping PIP '{}', request does not contain worker node v1 profile identifier in environment",
                getId());
        return false;
    }

    /** {@inheritDoc} */
    protected String getCertificateAttributeId() {
        return Attribute.ID_SUB_KEY_INFO;
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

        log.debug("Extracting end-entity certificate attributes");
        HashSet<Attribute> subjectAttributes = new HashSet<Attribute>();

        // get and set the subject DN attribute.
        String endEntitySubjectDN = endEntityCertificate.getSubjectX500Principal().getName(X500Principal.RFC2253);
        Attribute attribute = new Attribute();
        attribute.setId(Attribute.ID_SUB_ID);
        attribute.setDataType(Attribute.DT_X500_NAME);
        attribute.getValues().add(endEntitySubjectDN);
        log.debug("Extracted attribute: {}", attribute);
        subjectAttributes.add(attribute);

        // set the issuer DN attribute.
        attribute = new Attribute();
        attribute.setId(WorkerNodeProfileV1Constants.ATT_SUBJECT_ISSUER);
        attribute.setDataType(Attribute.DT_X500_NAME);
        for (int i = 1; i < certChain.length; i++) {
            attribute.getValues().add(certChain[i].getSubjectX500Principal().getName(X500Principal.RFC2253));
        }
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

        Attribute voAttribute = new Attribute();
        voAttribute.setId(WorkerNodeProfileV1Constants.ATT_VO);
        voAttribute.setDataType(Attribute.DT_STRING);
        voAttribute.getValues().add(attributeCertificate.getVO());
        log.debug("Extracted attribute: {}", voAttribute);
        vomsAttributes.add(voAttribute);

        List<FQAN> fqans = attributeCertificate.getListOfFQAN();
        if (fqans != null && !fqans.isEmpty()) {
            Attribute primaryFqanAttribute = new Attribute();
            primaryFqanAttribute.setId(WorkerNodeProfileV1Constants.ATT_PRIMARY_FQAN);
            primaryFqanAttribute.setDataType(WorkerNodeProfileV1Constants.DAT_FQAN);
            primaryFqanAttribute.getValues().add(fqans.get(0).getFQAN());
            log.debug("Extracted attribute: {}", primaryFqanAttribute);
            vomsAttributes.add(primaryFqanAttribute);

            // handle rest of the fqans
            Attribute fqanAttribute = new Attribute();
            fqanAttribute.setId(WorkerNodeProfileV1Constants.ATT_FQAN);
            fqanAttribute.setDataType(WorkerNodeProfileV1Constants.DAT_FQAN);
            for (FQAN fqan : fqans) {
                fqanAttribute.getValues().add(fqan.getFQAN());
            }
            log.debug("Extracted attribute: {}", fqanAttribute);
            vomsAttributes.add(fqanAttribute);
        }

        return vomsAttributes;
    }
}
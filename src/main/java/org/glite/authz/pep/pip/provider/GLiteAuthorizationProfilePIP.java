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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Environment;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.profile.GLiteAuthorizationProfileConstants;
import org.glite.authz.pep.pip.PIPProcessingException;
import org.glite.voms.FQAN;
import org.italiangrid.voms.VOMSAttribute;
import org.italiangrid.voms.ac.VOMSACValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.emi.security.authn.x509.X509CertChainValidator;

/**
 * The PIP applies to request which have a profile identifier
 * {@value GLiteAuthorizationProfileConstants#ID_ATTRIBUTE_PROFILE_ID} defined
 * in the request environment. By default accept all profile identifier values,
 * but a list of accepted profile identifier values can be specified.
 * <p>
 * The PIP extracts information from a X.509, version 3, certificate. The
 * certificate may include VOMS attribute certificates. All extract information
 * is added to the subject(s) containing a valid certificate chain.
 * <p>
 * The PEM encoded end entity certificate, and its certificate chain, are
 * expected to be bound to the subject attribute
 * {@value Attribute#ID_SUB_KEY_INFO} with a datatype of
 * {@value Attribute#DT_STRING}.
 * <p>
 * Only one end-entity certificate may be present in the chain.
 * <p>
 * If the end entity certificate contains a VOMS attribute certificate, and VOMS
 * certificate validation is enabled, information from that attribute
 * certificate will also be added to the subject. Only one VOMS attribute
 * certificate may be present in the end-entity certificate.
 * 
 * @see <a href="https://twiki.cnaf.infn.it/cgi-bin/twiki/view/VOMS">VOMS
 *      website</a>
 */
public class GLiteAuthorizationProfilePIP extends AbstractX509PIP {

    /** List of accepted profile IDs, if <code>null</code> accept all profile Id */
    private List<String> acceptedProfileIds_= null;

    /** Class logger. */
    private Logger log= LoggerFactory.getLogger(GLiteAuthorizationProfilePIP.class);

    /**
     * The constructor for this PIP. This constructor enables support for the
     * VOMS attribute certificates.
     * 
     * @param pipID
     *            ID of this PIP
     * @param requireProxy
     *            whether a subject's certificate chain must require a proxy in
     *            order to be valid
     * @param x509Validator
     *            trust material used to validate the subject's end entity
     *            certificate
     * @param vomsACValidator
     *            trust material used to validate the subject's attribute
     *            certificate certificate, may be <code>null</code> if AC
     *            support is not desired
     * @param performPKIXValidation
     *            perform or not PKIX validation on the certificate
     * @throws ConfigurationException
     *             thrown if the configuration of the PIP fails
     */
    public GLiteAuthorizationProfilePIP(String pipID, boolean requireProxy,
                                        X509CertChainValidator x509Validator,
                                        VOMSACValidator vomsACValidator,
                                        boolean performPKIXValidation)
                                                                      throws ConfigurationException {
        super(pipID, requireProxy, x509Validator, vomsACValidator);
        performPKIXValidation(performPKIXValidation);
    }

    /**
     * Constructor with a list of accepted profile IDs found in the request
     * environment attribute
     * {@value GLiteAuthorizationProfileConstants#ID_ATTRIBUTE_PROFILE_ID}
     * 
     * @param pipID
     *            ID of this PIP
     * @param requireProxy
     *            whether a subject's certificate chain must require a proxy in
     *            order to be valid
     * @param eeTrustMaterial
     *            trust material used to validate the subject's end entity
     *            certificate
     * @param acTrustMaterial
     *            trust material used to validate the subject's attribute
     *            certificate certificate, may be <code>null</code> if AC
     *            support is not desired
     * @param performPKIXValidation
     *            perform or not PKIX validation on the certificate
     * @param acceptedProfileIds
     *            list of accepted profile IDs found in the request environment.
     *            If <code>null</code> accept every profile IDs, if empty accept
     *            none.
     * @throws ConfigurationException
     *             thrown if the configuration of the PIP fails
     */
    public GLiteAuthorizationProfilePIP(String pipID, boolean requireProxy,
                                        X509CertChainValidator x509Validator,
                                        VOMSACValidator vomsACValidator,
                                        boolean performPKIXValidation,
                                        String[] acceptedProfileIds)
                                                                    throws ConfigurationException {
        this(pipID, requireProxy, x509Validator,vomsACValidator, performPKIXValidation);
        if (acceptedProfileIds == null) {
            // accept all
            log.debug("{}: accept all profile ID values", pipID);
            acceptedProfileIds_= null;
        }
        else if (acceptedProfileIds.length == 0) {
            // accept none
            log.debug("{}: accept NO profile ID value", pipID);
            acceptedProfileIds_= Collections.emptyList();
        }
        else {
            log.debug("{}: accept profile ID values: ", pipID, Arrays.toString(acceptedProfileIds));
            acceptedProfileIds_= new ArrayList<String>(Arrays.asList(acceptedProfileIds));
        }
    }

    /**
     * Checks that the incoming {@link Request} contains a profile identifier
     * attribute in the environment.
     * 
     * @param request
     *            the incoming request to be checked
     * 
     * @return true if this PIP applies to the request, false if not
     */
    protected boolean appliesToRequest(Request request) {
        Environment env= request.getEnvironment();
        if (env != null) {
            for (Attribute attrib : env.getAttributes()) {
                if (GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_PROFILE_ID.equals(attrib.getId())) {
                    if (acceptedProfileIds_ == null) {
                        // accept all profile IDs
                        log.trace("PIP '{}' accept all {} value", getId(), GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_PROFILE_ID);
                        return true;
                    }
                    else if (acceptedProfileIds_.isEmpty()) {
                        // accept none
                        log.warn("PIP '{}' don't accept any profile ID, specify 'acceptedProfileIDs = ...' in config.", getId());
                        return false;
                    }
                    else {
                        // accept only listed one
                        for (String acceptedProfileId : acceptedProfileIds_) {
                            if (attrib.getValues().contains(acceptedProfileId)) {
                                log.trace("PIP '{}' accept {}", getId(), acceptedProfileId);
                                return true;
                            }
                        }
                        log.debug("PIP '{}' don't accept profile ID: {}", getId(), attrib.getValues());
                        return false;
                    }
                }
            }
        }

        log.debug("Skipping PIP '{}', request does not contain a profile identifier in environment", getId());
        return false;
    }

    /** {@inheritDoc} */
    protected String getCertificateAttributeId() {
        return Attribute.ID_SUB_KEY_INFO;
    }

    /** {@inheritDoc} */
    protected String getCertificateAttributeDatatype() {
        return Attribute.DT_STRING;
    }

    /**
     * Processes one certificate chain and adds the information to the subjects
     * in the request.
     * 
     * @param endEntityCertificate
     *            end entity certificate for the subject currently being
     *            processed
     * @param certChain
     *            the certificate chain containing the end entity certificate
     *            from which information will be extracted
     * 
     * @return the attribute extracted from the certificate chain
     * 
     * @throws PIPProcessingException
     *             thrown if there is a problem reading the information from the
     *             certificate chain
     */
    protected Collection<Attribute> processCertChain(X509Certificate endEntityCertificate,
                                                     X509Certificate[] certChain)
            throws PIPProcessingException {
        if (endEntityCertificate == null || certChain == null
                || certChain.length == 0) {
            return null;
        }

        log.debug("Extracting end-entity certificate attributes");
        HashSet<Attribute> subjectAttributes= new HashSet<Attribute>();

        // get and set the subject DN attribute.
        String endEntitySubjectDN= endEntityCertificate.getSubjectX500Principal().getName(X500Principal.RFC2253);
        Attribute attribute= new Attribute();
        attribute.setId(Attribute.ID_SUB_ID);
        attribute.setDataType(Attribute.DT_X500_NAME);
        attribute.getValues().add(endEntitySubjectDN);
        log.debug("Extracted attribute: {}", attribute);
        subjectAttributes.add(attribute);

        // set the issuer DN attribute.
        attribute= new Attribute();
        attribute.setId(GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_SUBJECT_ISSUER);
        attribute.setDataType(Attribute.DT_X500_NAME);
        for (int i= 1; i < certChain.length; i++) {
            attribute.getValues().add(certChain[i].getSubjectX500Principal().getName(X500Principal.RFC2253));
        }
        log.debug("Extracted attribute: {}", attribute);
        subjectAttributes.add(attribute);

        if (isVOMSSupportEnabled()) {
            Collection<Attribute> vomsAttributes= processVOMS(endEntityCertificate, certChain);
            if (vomsAttributes != null) {
                subjectAttributes.addAll(vomsAttributes);
            }
        }

        return subjectAttributes;
    }

    /**
     * Processes the VOMS attributes and puts valid attributes into the subject
     * object.
     * 
     * @param endEntityCert
     *            the end entity certificate for the subject being processed
     * @param certChain
     *            certificate chain containing the end entity certificate that
     *            contains the VOMS attribute certificate
     * 
     * @return the attributes extracted from the VOMS attribute certificate
     * 
     * @throws PIPProcessingException
     *             thrown if the end entity certificate contains more than one
     *             attribute certificate
     */
    private Collection<Attribute> processVOMS(X509Certificate endEntityCert,
                                              X509Certificate[] certChain)
            throws PIPProcessingException {

        log.debug("Extracting VOMS attribute certificate attributes");
        VOMSAttribute attributeCertificate= extractVOMSAttributeCertificate(certChain);
        if (attributeCertificate == null) {
            return null;
        }

        HashSet<Attribute> vomsAttributes= new HashSet<Attribute>();

        Attribute voAttribute= new Attribute();
        voAttribute.setId(GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_VIRTUAL_ORGANIZATION);
        voAttribute.setDataType(Attribute.DT_STRING);
        voAttribute.getValues().add(attributeCertificate.getVO());
        log.debug("Extracted attribute: {}", voAttribute);
        vomsAttributes.add(voAttribute);

        List<FQAN> fqans= attributeCertificate.getListOfFQAN();
        if (fqans != null && !fqans.isEmpty()) {
            Attribute primaryFqanAttribute= new Attribute();
            primaryFqanAttribute.setId(GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_PRIMARY_FQAN);
            primaryFqanAttribute.setDataType(GLiteAuthorizationProfileConstants.DATATYPE_FQAN);
            primaryFqanAttribute.getValues().add(fqans.get(0).getFQAN());
            log.debug("Extracted attribute: {}", primaryFqanAttribute);
            vomsAttributes.add(primaryFqanAttribute);

            // handle rest of the fqans
            Attribute fqanAttribute= new Attribute();
            fqanAttribute.setId(GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_FQAN);
            fqanAttribute.setDataType(GLiteAuthorizationProfileConstants.DATATYPE_FQAN);
            for (FQAN fqan : fqans) {
                fqanAttribute.getValues().add(fqan.getFQAN());
            }
            log.debug("Extracted attribute: {}", fqanAttribute);
            vomsAttributes.add(fqanAttribute);
        }

        return vomsAttributes;
    }
}
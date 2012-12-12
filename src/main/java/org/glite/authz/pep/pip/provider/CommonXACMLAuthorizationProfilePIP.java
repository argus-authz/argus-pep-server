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

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.fqan.FQAN;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Environment;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants;
import org.glite.authz.common.profile.GLiteAuthorizationProfileConstants;
import org.glite.authz.common.util.Base64;
import org.glite.authz.common.util.LazyList;
import org.glite.authz.common.util.Strings;
import org.glite.authz.pep.pip.PIPProcessingException;
import org.italiangrid.voms.VOMSAttribute;
import org.italiangrid.voms.ac.VOMSACValidator;
import org.italiangrid.voms.ac.VOMSValidationResult;
import org.italiangrid.voms.error.VOMSValidationErrorMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.proxy.ProxyUtils;

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
 * {@value Attribute#DT_BASE64_BINARY}.
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
public class CommonXACMLAuthorizationProfilePIP extends AbstractX509PIP {

    static {
        /* add BouncyCastle security provider if not already done */
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** List of accepted profile IDs, if <code>null</code> accept all profile Id */
    private List<String> acceptedProfileIds_= null;

    /** Class logger. */
    private Logger log= LoggerFactory.getLogger(CommonXACMLAuthorizationProfilePIP.class);

    /** Certificate factory */
    private CertificateFactory cf_;

    /**
     * The constructor for this PIP. This constructor enables support for the
     * VOMS attribute certificates.
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
     * @throws ConfigurationException
     *             thrown if the configuration of the PIP fails
     */
    public CommonXACMLAuthorizationProfilePIP(String pipID,
            boolean requireProxy, X509CertChainValidator x509Validator,
            VOMSACValidator vomsACValidator, boolean performPKIXValidation)
            throws ConfigurationException {
        super(pipID, requireProxy, x509Validator, vomsACValidator);
        performPKIXValidation(performPKIXValidation);
        try {
            cf_= CertificateFactory.getInstance("X.509",
                                                Security.getProvider(BouncyCastleProvider.PROVIDER_NAME));
        } catch (CertificateException e) {
            throw new ConfigurationException("Fail to get instance of the X.509 certificate factory",
                                             e);
        }

    }

    /**
     * Constructor with a list of accepted profile IDs found in the request
     * environment attribute
     * {@value CommonXACMLAuthorizationProfileConstants#ID_ATTRIBUTE_PROFILE_ID}
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
    public CommonXACMLAuthorizationProfilePIP(String pipID,
            boolean requireProxy, X509CertChainValidator x509Validator,
            VOMSACValidator vomsACValidator, boolean performPKIXValidation,
            String[] acceptedProfileIds) throws ConfigurationException {
        this(pipID,
             requireProxy,
             x509Validator,
             vomsACValidator,
             performPKIXValidation);
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
            log.debug("{}: accept profile ID values: ",
                      pipID,
                      Arrays.toString(acceptedProfileIds));
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
                if (CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_PROFILE_ID.equals(attrib.getId())) {
                    if (acceptedProfileIds_ == null) {
                        // accept all profile IDs
                        log.trace("PIP '{}' accept all {} value",
                                  getId(),
                                  CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_PROFILE_ID);
                        return true;
                    }
                    else if (acceptedProfileIds_.isEmpty()) {
                        // accept none
                        log.warn("PIP '{}' don't accept any profile ID, specify 'acceptedProfileIDs = ...' in config.",
                                 getId());
                        return false;
                    }
                    else {
                        // accept only listed one
                        for (String acceptedProfileId : acceptedProfileIds_) {
                            if (attrib.getValues().contains(acceptedProfileId)) {
                                log.trace("PIP '{}' accept {}",
                                          getId(),
                                          acceptedProfileId);
                                return true;
                            }
                        }
                        log.debug("PIP '{}' don't accept profile ID: {}",
                                  getId(),
                                  attrib.getValues());
                        return false;
                    }
                }
            }
        }

        log.debug("Skipping PIP '{}', request does not contain a profile identifier in environment",
                  getId());
        return false;
    }

    /**
     * {@inheritDoc}
     * 
     * @return {@value CommonXACMLAuthorizationProfileConstants#ID_ATTRIBUTE_SUBJECT_KEY_INFO}
     */
    protected String getCertificateAttributeId() {
        return CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_SUBJECT_KEY_INFO;
    }

    /**
     * {@inheritDoc}
     * 
     * @return {@value CommonXACMLAuthorizationProfileConstants#DATATYPE_BASE64_BINARY}
     */
    protected String getCertificateAttributeDatatype() {
        return CommonXACMLAuthorizationProfileConstants.DATATYPE_BASE64_BINARY;
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
    protected Collection<Attribute> processCertChain(
            X509Certificate endEntityCertificate, X509Certificate[] certChain)
            throws PIPProcessingException {
        if (endEntityCertificate == null || certChain == null
                || certChain.length == 0) {
            return null;
        }

        log.debug("Extracting EEC attributes...");
        Set<Attribute> subjectAttributes= new HashSet<Attribute>();

        // get and set the subject DN attribute.
        String endEntitySubjectDN= endEntityCertificate.getSubjectX500Principal().getName(X500Principal.RFC2253);
        Attribute subjectIdAttribute= new Attribute(CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_SUBJECT_ID,
                                                    CommonXACMLAuthorizationProfileConstants.DATATYPE_X500_NAME);
        subjectIdAttribute.getValues().add(endEntitySubjectDN);
        log.debug("subject-id attribute: {}", subjectIdAttribute);
        subjectAttributes.add(subjectIdAttribute);

        // set the issuer DN attribute.
        Attribute subjectIssuerAttribute= new Attribute(CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_SUBJECT_ISSUER,
                                                        CommonXACMLAuthorizationProfileConstants.DATATYPE_X500_NAME);
        for (X509Certificate cert : certChain) {
            String issuer= cert.getIssuerX500Principal().getName(X500Principal.RFC2253);
            subjectIssuerAttribute.getValues().add(issuer);
        }
        log.debug("subject-issuer attribute: {}", subjectIssuerAttribute);
        subjectAttributes.add(subjectIssuerAttribute);

        if (isVOMSSupportEnabled()) {
            Collection<Attribute> vomsAttributes= processVOMS(certChain);
            if (vomsAttributes != null) {
                subjectAttributes.addAll(vomsAttributes);
            }
        }

        return subjectAttributes;
    }

    /**
     * Processes the VOMS attributes and extract VO related attributes for the
     * subject object.
     * 
     * @param certChain
     *            certificate chain containing the end entity certificate that
     *            contains the VOMS attribute certificate
     * 
     * @return the attributes extracted from the VOMS attribute certificates or
     *         <code>null</code> if the cert chain doesn't contain any VOMS AC.
     */
    protected Collection<Attribute> processVOMS(X509Certificate[] certChain) {

        log.debug("Extracting VOMS ACs");
        List<VOMSAttribute> vomsAttributes= extractVOMSAttributes(certChain);
        if (vomsAttributes == null) {
            log.debug("No VOMS AC found in cert chain");
            return null;
        }

        Set<Attribute> vomsSubjectAttributes= new HashSet<Attribute>();
        // VO
        Attribute voAttribute= new Attribute();
        voAttribute.setId(CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_VIRTUAL_ORGANIZATION);
        voAttribute.setDataType(CommonXACMLAuthorizationProfileConstants.DATATYPE_STRING);
        // groups
        Attribute primaryGroupAttribute= new Attribute(CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_PRIMARY_GROUP,
                                                       CommonXACMLAuthorizationProfileConstants.DATATYPE_STRING);
        Attribute primaryRoleAttribute= null;
        Attribute groupAttribute= new Attribute(CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_GROUP,
                                                CommonXACMLAuthorizationProfileConstants.DATATYPE_STRING);
        // issuer -> HASHTABLE(groupName, roleAttribute);
        Hashtable<String, Attribute> issuerRoleAttributeHT= new Hashtable<String, Attribute>();
        boolean primaryGroupRole= true;
        for (VOMSAttribute vomsAttribute : vomsAttributes) {
            // VO name
            String voName= vomsAttribute.getVO();
            voAttribute.getValues().add(voName);
            // extract groups and roles from AC -> FQANs
            List<String> fqans= vomsAttribute.getFQANs();
            for (String fqanString : fqans) {
                FQAN fqan;
                try {
                    fqan= FQAN.parseFQAN(fqanString);
                } catch (ParseException e) {
                    log.warn("Failed to parse FQAN: {}. {}",fqanString,e.getMessage());
                    continue;
                }
                // group name
                String groupName= fqan.getGroupName();
                groupAttribute.getValues().add(groupName);
                // role name, issuer is group name
                String roleName= fqan.getRole();
                if (!isNullorNULL(roleName)) {
                    Attribute roleAttribute= issuerRoleAttributeHT.get(groupName);
                    if (roleAttribute == null) {
                        // group didn't issue any role yet, create and add to HT
                        roleAttribute= new Attribute(CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_ROLE,
                                                     CommonXACMLAuthorizationProfileConstants.DATATYPE_STRING,
                                                     groupName);
                        issuerRoleAttributeHT.put(groupName, roleAttribute);
                    }
                    roleAttribute.getValues().add(roleName);
                }
                if (primaryGroupRole) {
                    primaryGroupAttribute.getValues().add(groupName);
                    if (!isNullorNULL(roleName)) {
                        primaryRoleAttribute= new Attribute(CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_PRIMARY_ROLE,
                                                            CommonXACMLAuthorizationProfileConstants.DATATYPE_STRING,
                                                            groupName);
                        primaryRoleAttribute.getValues().add(roleName);
                    }
                    primaryGroupRole= false;
                }
            }
        }
        log.debug("VO attribute: {}", voAttribute);
        vomsSubjectAttributes.add(voAttribute);
        log.debug("Primary group attribute: {}", primaryGroupAttribute);
        vomsSubjectAttributes.add(primaryGroupAttribute);
        log.debug("Group attribute: {}", groupAttribute);
        vomsSubjectAttributes.add(groupAttribute);
        if (primaryRoleAttribute != null) {
            log.debug("Primary role attribute: {}", primaryRoleAttribute);
            vomsSubjectAttributes.add(primaryRoleAttribute);
        }
        if (!issuerRoleAttributeHT.isEmpty()) {
            Collection<Attribute> roleAttributes= issuerRoleAttributeHT.values();
            log.debug("Role attributes: {}", roleAttributes);
            vomsSubjectAttributes.addAll(roleAttributes);
        }
        return vomsSubjectAttributes;
    }

    /**
     * Validate and extract the VOMS ACs from the certificate chain.
     * 
     * @param certChain
     *            the certificate chain
     * @return the list of VOMS ACs or <code>null</code> if the cert chain
     *         doesn't contain any AC.
     */
    private List<VOMSAttribute> extractVOMSAttributes(
            X509Certificate[] certChain) {
        VOMSACValidator validator= getVOMSACValidator();
        String x509Subject= certChain[0].getSubjectX500Principal().getName(X500Principal.RFC2253);
        log.debug("Validating VOMS AC for {}",x509Subject);
        
        List<VOMSValidationResult> results= validator.validateWithResult(certChain);

        if (results.isEmpty()) {
            log.warn("No VOMS attributes found in cert chain: {}",x509Subject);
            return null;
        }

        List<VOMSAttribute> vomsAttributes= new LazyList<VOMSAttribute>();
        for (VOMSValidationResult result : results) {
            if (result.isValid()) {
                vomsAttributes.add(result.getAttributes());
            }
            else {
                List<VOMSValidationErrorMessage> errorMessages= result.getValidationErrors();
                for (VOMSValidationErrorMessage errorMessage : errorMessages) {
                    log.error("VOMS validation fails: " + errorMessage.getMessage());
                    return null;
                }

            }
        }
        if (vomsAttributes.isEmpty()) {
            log.warn("No valid VOMS attributes found in cert chain: {}",x509Subject);
            return null;
        }

        return vomsAttributes;
    }

    /**
     * Gets the certificate chain from the subject's attribute id and datatype
     * 
     * @param subject
     *            subject from which to extract the certificate chain
     * 
     * @return the extracted certificate chain or <code>null</code> if the
     *         subject did not contain a chain of X.509 version 3 certificates
     * 
     * @throws PIPProcessingException
     *             thrown if the subject contained more than one certificate
     *             chain or if the chain was not properly encoded
     * 
     * @see #getCertificateAttributeId()
     * @see #getCertificateAttributeDatatype()
     */
    protected X509Certificate[] extractCertificateChain(Subject subject)
            throws PIPProcessingException {
        List<X509Certificate> certChain= new ArrayList<X509Certificate>();
        for (Attribute attribute : subject.getAttributes()) {
            // check attribute Id and datatype
            if (Strings.safeEquals(attribute.getId(),
                                   getCertificateAttributeId())
                    && Strings.safeEquals(attribute.getDataType(),
                                          getCertificateAttributeDatatype())) {
                // each value is a base64 encoded DER certificate string
                for (Object value : attribute.getValues()) {
                    byte[] derBytes= Base64.decode((String) value);
                    BufferedInputStream bis= new BufferedInputStream(new ByteArrayInputStream(derBytes));
                    try {
                        X509Certificate x509= (X509Certificate) cf_.generateCertificate(bis);
                        // log.trace("X.509 cert {} decoded ",
                        // x509.getSubjectX500Principal().getName());
                        certChain.add(x509);
                    } catch (CertificateException e) {
                        String error= "Fails to decode X.509 certificate: "
                                + e.getMessage();
                        log.error(error);
                        throw new PIPProcessingException(error, e);
                    }
                }

            }
        }

        if (certChain.isEmpty()) {
            log.debug("No attribute: {} datatype: {} found in Subject",getCertificateAttributeId(),getCertificateAttributeDatatype());
            return null;
        }
        
        boolean proxyPresent= false;
        for (X509Certificate cert : certChain) {
            if (cert.getVersion() < 3) {
                log.warn("Subject certificate {} is not a version 3, or greater, certificate, certificate chain ignored",
                         cert.getSubjectX500Principal().getName(X500Principal.RFC2253));
                return null;
            }
            if (isProxyCertificateRequired() && ProxyUtils.isProxy(cert)) {
                proxyPresent= true;
            }
        }

        if (isProxyCertificateRequired() && !proxyPresent) {
            log.warn("Proxy is required, but none found");
            return null;
        }

        return certChain.toArray(new X509Certificate[certChain.size()]);
    }

    /** the "NULL" string */
    private static final String NULL_STRING= "NULL";

    /**
     * Returns <code>true</code> iff the str is <code>null</code> or case
     * insensitive equals to the "NULL" string.
     * 
     * @param str
     *            string to check
     * @return <code>true</code> iff the str is <code>null</code> or case
     *         insensitive equals to the "NULL" string.
     */
    static private boolean isNullorNULL(String str) {
        if (str == null)
            return true;
        else
            return NULL_STRING.equalsIgnoreCase(str);
    }

}
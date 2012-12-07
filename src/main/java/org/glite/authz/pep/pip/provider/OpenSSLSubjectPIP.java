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

import java.util.Arrays;
import java.util.List;

import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.profile.GLiteAuthorizationProfileConstants;
import org.glite.authz.common.util.LazyList;
import org.glite.authz.pep.pip.PIPProcessingException;
import org.glite.authz.pep.utils.DN;
import org.glite.authz.pep.utils.DNHandler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A Policy Information Point which transform OpenSSL oneline format DN into
 * RFC2253 format DN.
 * <p>
 * By default, all request subject attributes
 * {@value GLiteAuthorizationProfileConstants#ID_ATTRIBUTE_SUBJECT_ID} and
 * {@value GLiteAuthorizationProfileConstants#ID_ATTRIBUTE_SUBJECT_ISSUER} with the
 * data type of {@value GLiteAuthorizationProfileConstants#DATATYPE_STRING} will be
 * converted to their {@value GLiteAuthorizationProfileConstants#DATATYPE_X500_NAME}
 * data type.
 * 
 * @see DNHandler
 * @see DN
 */
public final class OpenSSLSubjectPIP extends AbstractPolicyInformationPoint {

    /** Class logger. */
    private final Logger log= LoggerFactory.getLogger(OpenSSLSubjectPIP.class);

    /** Default list of subject attribute IDs what must be converted: {@value} */
    public final static List<String> DEFAULT_OPENSSL_SUBJECT_ATTRIBUTE_IDS= Arrays.asList(GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_SUBJECT_ISSUER,
                                                                                  GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_SUBJECT_ID);

    /**
     * Default list of subject attribute datatype what must be converted: {@value}
     */
    public final static List<String> DEFAULT_OPENSSL_SUBJECT_ATTRIBUTE_DATATYPES= Arrays.asList(GLiteAuthorizationProfileConstants.DATATYPE_STRING);

    /** List of subject attribute IDs what must be converted */
    private List<String> subjectAttributeIDs_= null;

    /** List of subject attribute datatypes what must be converted */
    private List<String> subjectAttributeDataTypes_= null;

    /**
     * Constructor.
     * 
     * @param pipid
     *            The PIP identifier name
     */
    public OpenSSLSubjectPIP(String pipid) {
        super(pipid);
        subjectAttributeIDs_= DEFAULT_OPENSSL_SUBJECT_ATTRIBUTE_IDS;
        subjectAttributeDataTypes_= DEFAULT_OPENSSL_SUBJECT_ATTRIBUTE_DATATYPES;
    }

    /** {@inheritDoc} */
    public boolean populateRequest(Request request)
            throws PIPProcessingException {
        boolean applied= false;
        for (Subject subject : request.getSubjects()) {
            List<Attribute> rfcAttributes= new LazyList<Attribute>();
            for (Attribute attribute : subject.getAttributes()) {
                if (subjectAttributeDataTypes_.contains(attribute.getDataType())
                        && subjectAttributeIDs_.contains(attribute.getId())) {
                    applied= true;
                    Attribute rfcAttribute= new Attribute(attribute.getId(),
                                                          GLiteAuthorizationProfileConstants.DATATYPE_X500_NAME,
                                                          attribute.getIssuer());
                    for (Object value : attribute.getValues()) {
                        String opensslDN= value.toString();
                        DN dn= DNHandler.getDNRFC2253(opensslDN);
                        String rfcDN= dn.getRFCDN();
                        if (log.isDebugEnabled()) {
                            log.debug("OpenSSL DN {} converted to {}",
                                      opensslDN,
                                      rfcDN);
                        }
                        rfcAttribute.getValues().add(rfcDN);
                    }
                    rfcAttributes.add(rfcAttribute);
                }
            }
            // add all converted DN in the same subject
            if (!rfcAttributes.isEmpty()) {
                subject.getAttributes().addAll(rfcAttributes);
            }
        } // all subjects
        return applied;
    }

    /**
     * Set the list of subject attribute IDs to convert.
     * 
     * @param subjectAttributeIDs
     *            the subjectAttributeIDs to set
     */
    protected void setSubjectAttributeIDs(List<String> subjectAttributeIDs) {
        this.subjectAttributeIDs_= subjectAttributeIDs;
    }

    /**
     * Set the list of subject attribute data types to convert.
     * 
     * @param subjectAttributeDataTypes
     *            the subjectAttributeDataTypes to set
     */
    protected void setSubjectAttributeDataTypes(
            List<String> subjectAttributeDataTypes) {
        this.subjectAttributeDataTypes_= subjectAttributeDataTypes;
    }

}

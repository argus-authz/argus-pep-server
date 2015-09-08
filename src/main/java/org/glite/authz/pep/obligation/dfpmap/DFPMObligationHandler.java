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

package org.glite.authz.pep.obligation.dfpmap;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.glite.authz.common.fqan.FQAN;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.AttributeAssignment;
import org.glite.authz.common.model.Obligation;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Result;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.profile.GLiteAuthorizationProfileConstants;
import org.glite.authz.pep.obligation.AbstractObligationHandler;
import org.glite.authz.pep.obligation.ObligationProcessingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An obligation handler that transforms an
 * {@value GLiteAuthorizationProfileConstants#ID_OBLIGATION_LOCAL_ENV_MAP} obligation
 * in to a {@value GLiteAuthorizationProfileConstants#ID_OBLIGATION_POSIX_ENV_MAP}
 * obligation. The POSIX login name and primary and secondary group values are
 * determined by mapping the {@value Attribute#ID_SUB_ID},
 * {@value GLiteAuthorizationProfileConstants#ID_ATTRIBUTE_PRIMARY_FQAN} and
 * {@value GLiteAuthorizationProfileConstants#ID_ATTRIBUTE_FQAN} attributes found
 * within the {@link Subject} of the authorization request.
 */
public class DFPMObligationHandler extends AbstractObligationHandler {

    /** Class logger. */
    private final Logger log= LoggerFactory.getLogger(DFPMObligationHandler.class);

    /** DN/FQAN to POSIX account mapper. */
    private AccountMapper accountMapper;

    /**
     * Request subject must contain a key-info attribute for this OH to apply:
     * Default {@value}
     */
    private boolean requireSubjectKeyInfo= true;

    /**
     * Constructor.
     * 
     * @param name
     *            The obligation handler unique id (name)
     * @param obligationId
     *            The handled obligation ID
     * @param mapper
     *            used to map a subject to a POSIX account
     */
    public DFPMObligationHandler(String name, String obligationId,
            AccountMapper mapper) {
        super(name, obligationId);

        if (mapper == null) {
            throw new IllegalArgumentException("Account mapper may not be null");
        }
        accountMapper= mapper;
    }

    /**
     * Constructor. Default handled obligation ID:
     * {@value GLiteAuthorizationProfileConstants#ID_OBLIGATION_LOCAL_ENV_MAP}
     * 
     * @param name
     *            the obligation handler name
     * @param mapper
     *            mapper used to map a subject to a POSIX account
     */
    public DFPMObligationHandler(String name, AccountMapper mapper) {
        this(name,
             GLiteAuthorizationProfileConstants.ID_OBLIGATION_LOCAL_ENV_MAP,
             mapper);
    }

    /**
     * Constructor.
     * 
     * @param name
     *            the obligation handler name
     * @param precedence
     *            precendence of this obligation handler
     * @param mapper
     *            mapper used to map a subject to a POSIX account
     */
    public DFPMObligationHandler(String name, int precedence,
            AccountMapper mapper) {
        this(name,
             GLiteAuthorizationProfileConstants.ID_OBLIGATION_LOCAL_ENV_MAP,
             mapper);
        setHanderPrecedence(precedence);
    }

    /** {@inheritDoc} */
    public boolean evaluateObligation(Request request, Result result)
            throws ObligationProcessingException {
        boolean applied= false;

        Subject subject= getSubject(request);

        // check for the key-info attribute in the request, if required and not
        // present, don't apply OH
        if (requireSubjectKeyInfo && !subjectContainsKeyInfo(subject)) {
            log.info("{}: Does not apply. Requires a request subject key-info attribute, but none found.",
                     getId());
            return false;
        }

        X500Principal subjectDN= getDN(subject);
        FQAN primaryFQAN= getPrimaryFQAN(subject);
        List<FQAN> secondaryFQANs= getSecondaryFQANs(subject);

        PosixAccount mappedAccount= accountMapper.mapToAccount(subjectDN,
                                                               primaryFQAN,
                                                               secondaryFQANs);

        if (mappedAccount != null) {
            addPosixMappingObligation(result, mappedAccount);
            applied= true;

            // Remove the local environment mapping obligation (even if it
            // appears multiple times)
            // since we've handled it and replaced it with the POSIX mapping
            // obligations
            Iterator<Obligation> obligationItr= result.getObligations().iterator();
            Obligation obligation;
            List<Obligation> removedObligations= new ArrayList<Obligation>();
            while (obligationItr.hasNext()) {
                obligation= obligationItr.next();
                if (getObligationId().equals(obligation.getId())) {
                    removedObligations.add(obligation);
                }
            }
            result.getObligations().removeAll(removedObligations);
            log.info("{}: DN: {} pFQAN: {} FQANs: {} mapped to POSIX account: {}",
                     new Object[] { getId(),
                                   subjectDN.getName(X500Principal.RFC2253),
                                   primaryFQAN, secondaryFQANs, mappedAccount });
        }
        log.debug("Finished processing DN/FQAN to POSIX account mapping obligation for subject {}",
                  subjectDN.getName());
        return applied;
    }

    /**
     * Gets the subject from the request.
     * 
     * @param request
     *            authorization request
     * 
     * @return the subject of the request
     * 
     * @throws ObligationProcessingException
     *             thrown if there is zero or more than one subject in the
     *             request
     */
    private Subject getSubject(Request request)
            throws ObligationProcessingException {
        Set<Subject> subjects= request.getSubjects();
        if (subjects == null || subjects.isEmpty()) {
            throw new ObligationProcessingException("Unable to process request, it does not contain a subject");
        }
        if (subjects.size() != 1) {
            log.warn("Request contains '{}' subject, unable to process it",
                     subjects.size());
            throw new ObligationProcessingException("Requests contains more than one subject");
        }
        return subjects.iterator().next();
    }

    /**
     * Checks if the subject contains at least one key-info attribute.
     * 
     * @param subject
     *            the Subject to check
     * @return <code>true</code> if the subject contains a key-info attribute
     */
    private boolean subjectContainsKeyInfo(Subject subject) {
        Set<Attribute> attributes= subject.getAttributes();
        if (attributes != null) {
            for (Attribute attribute : attributes) {
                if (Attribute.ID_SUB_KEY_INFO.equals(attribute.getId())) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Gets the subject's DN from the subject DN attribute.
     * 
     * @param subject
     *            the subject of the request
     * 
     * @return the subject DN
     * 
     * @throws ObligationProcessingException
     *             thrown if the given attribute contains no values, is not of
     *             the right data type, or its value is not a valid DN
     */
    private X500Principal getDN(Subject subject)
            throws ObligationProcessingException {
        Attribute dnAttribute= null;
        for (Attribute attribute : subject.getAttributes()) {
            if (Attribute.ID_SUB_ID.equals(attribute.getId())
                    && Attribute.DT_X500_NAME.equals(attribute.getDataType())) {
                log.debug("Extracted subject attribute from request: {}",
                          attribute);
                dnAttribute= attribute;
                break;
            }
        }
        if (dnAttribute == null) {
            log.error("Subject of the authorization request did not contain a subject ID attribute {} datatype {}",
                      Attribute.ID_SUB_ID,
                      Attribute.DT_X500_NAME);
            throw new ObligationProcessingException("Invalid request, missing subject attribute: "
                    + Attribute.ID_SUB_ID
                    + " datatype: "
                    + Attribute.DT_X500_NAME);
        }

        Set<?> values= dnAttribute.getValues();
        if (values == null || values.isEmpty()) {
            log.error("Subject ID attribute of the authorization request did not contain any values");
            throw new ObligationProcessingException("Invalid request, subject attribute did not contain any values");
        }

        if (values.size() > 1) {
            log.warn("Subject ID attribute contains more than one value, only the first will be used");
        }

        try {
            String subjectDN= values.iterator().next().toString();
            return new X500Principal(subjectDN);
        } catch (IllegalArgumentException e) {
            log.error("Value of the Subject ID attribute of the authorization request was not a valid X.509 DN");
            throw new ObligationProcessingException("Invalid request, value of the Subject ID attribute was not a valid X.509 DN");
        }
    }

    /**
     * @param requireSubjectKeyInfo
     *            the requireSubjectKeyInfo to set
     */
    protected void setRequireSubjectKeyInfo(boolean requireSubjectKeyInfo) {
        this.requireSubjectKeyInfo= requireSubjectKeyInfo;
    }

    /**
     * Gets the primary FQAN from the request subject.
     * 
     * @param subject
     *            the subject of the request
     * 
     * @return the primary FQAN
     * 
     * @throws ObligationProcessingException
     *             thrown if the given attribute contains no values, is not of
     *             the right data type, or its value is not a valid FQAN
     */
    private FQAN getPrimaryFQAN(Subject subject)
            throws ObligationProcessingException {
        Attribute primaryFQANAttribute= null;

        for (Attribute attribute : subject.getAttributes()) {
            if (GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_PRIMARY_FQAN.equals(attribute.getId())) {
                log.debug("Extracted primary FQAN attribute from request: {}",
                          attribute);
                primaryFQANAttribute= attribute;
                break;
            }
        }

        if (primaryFQANAttribute == null) {
            log.debug("Subject of the authorization request did not contain a subject primary FQAN attribute");
            return null;
        }

        if (!GLiteAuthorizationProfileConstants.DATATYPE_FQAN.equals(primaryFQANAttribute.getDataType())) {
            log.error("Subject primary FQAN attribute of the authorization request was of the incorrect data type: {}",
                      primaryFQANAttribute.getDataType());
            throw new ObligationProcessingException("Invalid request, subject attribute of invalid data type");
        }

        Set<?> values= primaryFQANAttribute.getValues();
        if (values == null || values.isEmpty()) {
            log.error("Subject primary FQAN attribute of the authorization request did not contain any values");
            throw new ObligationProcessingException("Invalid request, subject attribute did not contain any values");
        }

        if (values.size() > 1) {
            log.warn("Primary FQAN attribute contains more than one value, only the first will be used");
        }

        try {
            return FQAN.parseFQAN(values.iterator().next().toString());
        } catch (ParseException e) {
            log.error("Value of the Subject primary FQAN attribute of the authorization request was not a valid FQAN",
                      e);
            throw new ObligationProcessingException("Invalid request, subject's primary FQAN attribute value was invalid",
                                                    e);
        }
    }

    /**
     * Gets the secondary FQANs from the request subject.
     * 
     * @param subject
     *            the subject of the request
     * 
     * @return the secondary FQANs
     * 
     * @throws ObligationProcessingException
     *             thrown if the given attribute contains no values, is not of
     *             the right data type, or its value is not a valid FQAN
     */
    private List<FQAN> getSecondaryFQANs(Subject subject)
            throws ObligationProcessingException {
        Attribute secondaryFQANsAttribute= null;

        for (Attribute attribute : subject.getAttributes()) {
            if (GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_FQAN.equals(attribute.getId())) {
                log.debug("Extracted secondary FQAN attribute from request: {}",
                          attribute);
                secondaryFQANsAttribute= attribute;
                break;
            }
        }

        if (secondaryFQANsAttribute == null) {
            log.debug("Subject of the authorization request did not contain a subject secondary FQAN attribute");
            return null;
        }

        if (!GLiteAuthorizationProfileConstants.DATATYPE_FQAN.equals(secondaryFQANsAttribute.getDataType())) {
            log.error("Subject secondary FQAN attribute of the authorization request was of the incorrect data type: {}",
                      secondaryFQANsAttribute.getDataType());
            throw new ObligationProcessingException("Invalid request, subject attribute of invalid data type");
        }

        Set<?> values= secondaryFQANsAttribute.getValues();
        if (values == null || values.isEmpty()) {
            log.error("Subject secondary FQAN attribute of the authorization request did not contain any values");
            throw new ObligationProcessingException("Invalid request, subject attribute did not contain any values");
        }

        List<FQAN> secondaryFQANs= new ArrayList<FQAN>();
        Iterator<?> valueItr= values.iterator();
        String value= null;
        while (valueItr.hasNext()) {
            try {
                value= valueItr.next().toString();
                FQAN parsedFQAN= FQAN.parseFQAN(value);
                secondaryFQANs.add(parsedFQAN);
            } catch (ParseException e) {
                log.error("Subject's secondary FQAN attribute value " + value
                        + " is not a valid FQAN");
                throw new ObligationProcessingException("Invalid request, subject's secondary FQAN attribute value was invalid");
            }
        }

        return secondaryFQANs;
    }

    /**
     * 
     * Adds a 
     * {@link GLiteAuthorizationProfileConstants#ID_OBLIGATION_POSIX_ENV_MAP} 
     * to the result.
     * 
     * @param result
     *            current result
     * @param account
     *            account whose information will be used to populate the
     *            {@link GLiteAuthorizationProfileConstants#ID_ATTRIBUTE_USER_ID},
     *            {@link GLiteAuthorizationProfileConstants#ID_ATTRIBUTE_PRIMARY_GROUP_ID}
     *            , and
     *            {@link GLiteAuthorizationProfileConstants#ID_ATTRIBUTE_GROUP_ID}
     *            attribute assignments of the obligation
     */
    protected void addPosixMappingObligation(Result result, PosixAccount account) {
        Obligation posixMapping= new Obligation();
        posixMapping.setId(GLiteAuthorizationProfileConstants.ID_OBLIGATION_POSIX_ENV_MAP);
        posixMapping.setFulfillOn(Result.DECISION_PERMIT);

        AttributeAssignment userid= new AttributeAssignment();
        userid.setAttributeId(GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_USER_ID);
        userid.setDataType(Attribute.DT_STRING);
        userid.setValue(account.getLoginName());
        posixMapping.getAttributeAssignments().add(userid);

        if (account.getPrimaryGroup() != null) {
            String groupId= account.getPrimaryGroup();
            AttributeAssignment primaryGroupId= new AttributeAssignment();
            primaryGroupId.setAttributeId(GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_PRIMARY_GROUP_ID);
            primaryGroupId.setDataType(Attribute.DT_STRING);
            primaryGroupId.setValue(groupId);
            posixMapping.getAttributeAssignments().add(primaryGroupId);
            // BUG FIX: profile attribute/group-id doesn't contain primary group
            // see https://savannah.cern.ch/bugs/index.php?64340
            AttributeAssignment secondaryGroupId= new AttributeAssignment();
            secondaryGroupId.setAttributeId(GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_GROUP_ID);
            secondaryGroupId.setDataType(Attribute.DT_STRING);
            secondaryGroupId.setValue(groupId);
            posixMapping.getAttributeAssignments().add(secondaryGroupId);
        }

        if (account.getSecondaryGroups() != null
                && !account.getSecondaryGroups().isEmpty()) {
            for (String secondaryGroup : account.getSecondaryGroups()) {
                AttributeAssignment secondaryGroupId= new AttributeAssignment();
                secondaryGroupId.setAttributeId(GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_GROUP_ID);
                secondaryGroupId.setDataType(Attribute.DT_STRING);
                secondaryGroupId.setValue(secondaryGroup);
                posixMapping.getAttributeAssignments().add(secondaryGroupId);
            }
        }

        result.getObligations().add(posixMapping);
    }
}
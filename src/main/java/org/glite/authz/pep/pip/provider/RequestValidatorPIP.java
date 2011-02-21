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

import java.util.Set;

import org.glite.authz.common.model.Action;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Environment;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Resource;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.model.util.Strings;
import org.glite.authz.pep.pip.PIPProcessingException;

/**
 * An incoming authorization request validator.
 * <p>
 * Throws a PIPProcessingException if the request doesn't contain at least one
 * subject, one resource and one action, or if the attribute within them don't
 * have any value or have a null or stripped empty ("", "    ", ...) value.
 */
public final class RequestValidatorPIP extends AbstractPolicyInformationPoint {

    /** Validation of request subjects enabled ? Default: {@value} */
    private boolean validateRequestSubjects_= true;

    /** Validation of request resources enabled ? Default: {@value} */
    private boolean validateRequestResources_= true;

    /** Validation of request action enabled ? Default: {@value} */
    private boolean validateRequestAction_= true;

    /** Validation of request environment enabled ? Default: {@value} */
    private boolean validateRequestEnvironment_= false;

    /**
     * Constructor.
     * 
     * @param pipid
     *            The PIP identifier
     */
    public RequestValidatorPIP(String pipid) {
        super(pipid);
    }

    /** {@inheritDoc} */
    public boolean populateRequest(Request request)
            throws PIPProcessingException, IllegalStateException {
        boolean applied= false;
        if (validateRequestSubjects_) {
            applied= true;
            Set<Subject> subjects= request.getSubjects();
            if (subjects.size() < 1) {
                throw new PIPProcessingException("request does not contain any subject");
            }
            for (Subject subject : subjects) {
                validateAttributes(subject.getAttributes(), "subject");
            }
        }
        if (validateRequestResources_) {
            applied= true;
            Set<Resource> resources= request.getResources();
            if (resources.size() < 1) {
                throw new PIPProcessingException("request does not contain any resource");
            }
            for (Resource resource : resources) {
                validateAttributes(resource.getAttributes(), "resource");
            }
        }
        if (validateRequestAction_) {
            applied= true;
            Action action= request.getAction();
            if (action == null) {
                throw new PIPProcessingException("request does not contain an action");
            }
            validateAttributes(action.getAttributes(), "action");
        }
        if (validateRequestEnvironment_) {
            applied= true;
            Environment environment= request.getEnvironment();
            if (environment == null) {
                throw new PIPProcessingException("request does not contain an environment");
            }
            validateAttributes(environment.getAttributes(), "environment");
        }
        return applied;
    }

    /**
     * Enable or disable request subjects validation.
     * 
     * @param validateRequestSubjects
     *            enable or disable validation
     */
    protected void setValidateRequestSubjects(boolean validateRequestSubjects) {
        this.validateRequestSubjects_= validateRequestSubjects;
    }

    /**
     * Enable or disable request resources validation.
     * 
     * @param validateRequestResources
     *            enable or disable validation
     */
    protected void setValidateRequestResources(boolean validateRequestResources) {
        this.validateRequestResources_= validateRequestResources;
    }

    /**
     * Enable or disable request action validation.
     * 
     * @param validateRequestAction
     *            enable or disable validation
     */
    protected void setValidateRequestAction(boolean validateRequestAction) {
        this.validateRequestAction_= validateRequestAction;
    }

    /**
     * Enable or disable request environment validation.
     * 
     * @param validateRequestEnvironment
     *            enable or disable validation
     */
    protected void setValidateRequestEnvironment(
            boolean validateRequestEnvironment) {
        this.validateRequestEnvironment_= validateRequestEnvironment;
    }

    /**
     * Checks the attributes set for missing, null or empty (stripped) values.
     * 
     * @param attributes
     *            The attributes set to check
     * @param element
     *            the element name for the error message
     * @throws PIPProcessingException
     *             if a validation check failed, see the error message
     */
    private void validateAttributes(Set<Attribute> attributes, String element)
            throws PIPProcessingException {
        if (attributes.size() < 1) {
            throw new PIPProcessingException("request " + element
                    + " without any attribute");
        }
        for (Attribute attribute : attributes) {
            Set<Object> attributeValues= attribute.getValues();
            if (attributeValues.size() < 1) {
                throw new PIPProcessingException("request " + element
                        + " contains the attribute " + attribute.getId()
                        + " without any value");
            }
            for (Object attributeValue : attributeValues) {
                if (attributeValue == null) {
                    throw new PIPProcessingException("request " + element
                            + " contains the attribute " + attribute.getId()
                            + " with a null value");
                }
                String value= Strings.safeTrimOrNullString(attributeValue.toString());
                if (value == null) {
                    throw new PIPProcessingException("request " + element
                            + " contains the attribute " + attribute.getId()
                            + " with an empty (stripped) value");
                }
            }
        }

    }
}

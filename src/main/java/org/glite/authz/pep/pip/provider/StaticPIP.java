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

import java.util.List;
import java.util.Set;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.model.Action;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Environment;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Resource;
import org.glite.authz.common.model.Subject;
import org.glite.authz.pep.pip.PIPProcessingException;

/** A PIP that provides a static set of attributes to a {@link Request}. */
@ThreadSafe
public class StaticPIP extends AbstractPolicyInformationPoint {

    /** Action attributes to be added to the request. */
    private List<Attribute> actionAttributes;

    /** Environment attributes to be added to the request. */
    private List<Attribute> environmentAttributes;

    /** Resource attributes to be added to the request. */
    private List<Attribute> resourceAttributes;

    /** Subject attributes to be added to the request. */
    private List<Attribute> subjectAttributes;

    /**
     * Whether the given resource attributes should be added to every resource in the request. Default value:
     * <code>false</code>
     */
    private boolean addAttributesToAllResources;

    /**
     * Whether the given subject attributes should be added to every resource in the request. Default value:
     * <code>false</code>
     */
    private boolean addAttributesToAllSubjects;

    /**
     * Constructor.
     * 
     * @param pipId the ID of this PIP
     * @param action attributes to be added to the action attributes in the request
     * @param environment attributes to be added to the environment attributes in the request
     * @param resource attributes to be added to the resource attributes in the request
     * @param subject attributes to be added to the subject attributes in the request
     */
    public StaticPIP(String pipId, List<Attribute> action, List<Attribute> environment, List<Attribute> resource,
            List<Attribute> subject) {
        super(pipId);

        addAttributesToAllResources = false;
        addAttributesToAllSubjects = false;

        actionAttributes = action;
        environmentAttributes = environment;
        resourceAttributes = resource;
        subjectAttributes = subject;
    }

    /**
     * Whether resource attributes should be added to all resources within the request. If not, and there is more than
     * one resource in the request at the time the PIP is run, the PIP will error out.
     * 
     * @return whether resource attributes should be added to all resources within the request
     */
    public boolean isAddAttributesToAllResources() {
        return addAttributesToAllResources;
    }

    /**
     * Sets whether resource attributes should be added to all resources within the request.
     * 
     * @param addAll whether resource attributes should be added to all resources within the request
     */
    public void setAddAttributesToAllResources(boolean addAll) {
        addAttributesToAllResources = addAll;
    }

    /**
     * Whether subject attributes should be added to all subjects within the request. If not, and there is more than one
     * subject in the request at the time the PIP is run, the PIP will error out.
     * 
     * @return whether subject attributes should be added to all subject within the request
     */
    public boolean isAddAttributesToAllSubjects() {
        return addAttributesToAllSubjects;
    }

    /**
     * Sets whether subject attributes should be added to all subject within the request.
     * 
     * @param addAll whether subject attributes should be added to all subject within the request
     */
    public void setAddAttributesToAllSubjects(boolean addAll) {
        addAttributesToAllSubjects = addAll;
    }

    /** {@inheritDoc} */
    public boolean populateRequest(Request request) throws PIPProcessingException {
        if (actionAttributes != null && !actionAttributes.isEmpty()) {
            Action action = request.getAction();
            if (action == null) {
                action = new Action();
                request.setAction(action);
            }
            action.getAttributes().addAll(actionAttributes);
        }

        if (environmentAttributes != null && !environmentAttributes.isEmpty()) {
            Environment environment = request.getEnvironment();
            if (environment == null) {
                environment = new Environment();
                request.setEnvironment(environment);
            }
            environment.getAttributes().addAll(environmentAttributes);
        }

        if (resourceAttributes != null && !resourceAttributes.isEmpty()) {
            Set<Resource> resources = request.getResources();
            if (resources.size() > 1 && !addAttributesToAllResources) {
                throw new PIPProcessingException(
                        "More than one Resource present in request and PIP configured to only add attribues to a single Resource");
            }

            if (request.getResources().size() == 0) {
                request.getResources().add(new Resource());
            }

            for (Resource resource : resources) {
                resource.getAttributes().addAll(resourceAttributes);
            }
        }

        if (subjectAttributes != null && !subjectAttributes.isEmpty()) {
            Set<Subject> subjects = request.getSubjects();
            if (subjects.size() > 1 && !addAttributesToAllSubjects) {
                throw new PIPProcessingException(
                        "More than one Subject present in request and PIP configured to only add attribues to a single Subject");
            }

            if (request.getSubjects().size() == 0) {
                request.getSubjects().add(new Subject());
            }

            for (Subject subject : subjects) {
                subject.getAttributes().addAll(subjectAttributes);
            }
        }

        return true;
    }
}
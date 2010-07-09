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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Resource;
import org.glite.authz.common.model.Subject;
import org.glite.authz.pep.pip.PIPProcessingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A policy information that removes all other attributes, from a request, except those on an explicit whitelist.
 */
@ThreadSafe
public class AttributeWhitelistPIP extends AbstractPolicyInformationPoint {
    
    /** Class logger. */
    private Logger log = LoggerFactory.getLogger(AttributeWhitelistPIP.class);

    /** IDs of action attributes allowed to appear in the request. */
    private Set<String> actionAttributes;

    /** IDs of environment attributes allowed to appear in the request. */
    private Set<String> environmentAttributes;

    /** IDs of resource attributes allowed to appear in the request. */
    private Set<String> resourceAttributes;

    /** IDs of subject attributes allowed to appear in the request. */
    private Set<String> subjectAttributes;

    /**
     * Constructor.
     * 
     * @param pipId ID of this policy information point
     * @param acceptedActionAttributeIds IDs of action attributes allowed to appear in the request
     * @param acceptedEnvironmentAttributeIds IDs of environment attributes allowed to appear in the request
     * @param acceptedResourceAttributeIds IDs of resource attributes allowed to appear in the request
     * @param acceptedSubjectAttributeIds IDs of subject attributes allowed to appear in the request
     */
    public AttributeWhitelistPIP(String pipId, String[] acceptedActionAttributeIds,
            String[] acceptedEnvironmentAttributeIds, String[] acceptedResourceAttributeIds,
            String[] acceptedSubjectAttributeIds) {
        super(pipId);

        if (acceptedActionAttributeIds == null) {
            actionAttributes = null;
        } else if (acceptedActionAttributeIds.length == 0) {
            actionAttributes = Collections.emptySet();
        } else {
            actionAttributes = new HashSet<String>(Arrays.asList(acceptedActionAttributeIds));
        }

        if (acceptedEnvironmentAttributeIds == null) {
            environmentAttributes = null;
        } else if (acceptedEnvironmentAttributeIds.length == 0) {
            environmentAttributes = Collections.emptySet();
        } else {
            environmentAttributes = new HashSet<String>(Arrays.asList(acceptedEnvironmentAttributeIds));
        }

        if (acceptedResourceAttributeIds == null) {
            resourceAttributes = null;
        } else if (acceptedResourceAttributeIds.length == 0) {
            resourceAttributes = Collections.emptySet();
        } else {
            resourceAttributes = new HashSet<String>(Arrays.asList(acceptedResourceAttributeIds));
        }

        if (acceptedSubjectAttributeIds == null) {
            subjectAttributes = null;
        } else if (acceptedSubjectAttributeIds.length == 0) {
            subjectAttributes = Collections.emptySet();
        } else {
            subjectAttributes = new HashSet<String>(Arrays.asList(acceptedSubjectAttributeIds));
        }
    }

    /** {@inheritDoc} */
    public boolean populateRequest(Request request) throws PIPProcessingException, IllegalStateException {
        if (request.getAction() != null) {
            log.debug("Filtering action attributes");
            filterAttributes(request.getAction().getAttributes(), actionAttributes);
        }

        if (request.getEnvironment() != null) {
            log.debug("Filtering environment attributes");
            filterAttributes(request.getEnvironment().getAttributes(), environmentAttributes);
        }

        Set<Resource> resources = request.getResources();
        if (resources != null) {
            for (Resource resource : resources) {
                if (resource != null) {
                    log.debug("Filtering resource attributes");
                    filterAttributes(resource.getAttributes(), resourceAttributes);
                }
            }
        }

        Set<Subject> subjects = request.getSubjects();
        if (subjects != null) {
            for (Subject subject : subjects) {
                if (subject != null) {
                    log.debug("Filtering subject attributes");
                    filterAttributes(subject.getAttributes(), subjectAttributes);
                }
            }
        }

        return true;
    }

    /**
     * Removes any attribute from the given set whose ID is not in the accepted ID set. If the accepted ID set is null
     * then no attribute filtering is performed. If the accepted ID set is empty then all attributes are filtered out.
     * 
     * @param attributes attributes to be filtered
     * @param acceptedIds set of accepted attribute IDs
     */
    protected void filterAttributes(Set<Attribute> attributes, Set<String> acceptedIds) {
        if (attributes == null || attributes.isEmpty() || acceptedIds == null) {
            return;
        }

        if (acceptedIds.isEmpty()) {
            log.debug("No attributes allowed, removing all attributes from the request");
            attributes.clear();
        }

        Iterator<Attribute> attribtueItr = attributes.iterator();
        Attribute attribute;
        ArrayList<Attribute> removedAttributes = new ArrayList<Attribute>();
        while (attribtueItr.hasNext()) {
            attribute = attribtueItr.next();
            if (!acceptedIds.contains(attribute.getId())) {
                log.debug("Attribute {} not allowed, removing it from the request.", attribute.getId());
                removedAttributes.add(attribute);
            }
        }
        attributes.removeAll(removedAttributes);
    }
}
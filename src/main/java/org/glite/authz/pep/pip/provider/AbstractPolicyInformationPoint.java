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

import org.glite.authz.pep.pip.PIPException;
import org.glite.authz.pep.pip.PolicyInformationPoint;
import org.glite.authz.common.util.Strings;

/**
 * Base class for {@link PolicyInformationPoint} implementations that provides no-op implementation of the
 * {@link PolicyInformationPoint#start()} and {@link PolicyInformationPoint#start()} methods.
 */
public abstract class AbstractPolicyInformationPoint implements PolicyInformationPoint {

    /** ID for the policy information point. */
    private String id;

    /** Constructor. */
    protected AbstractPolicyInformationPoint() {

    }

    /**
     * Constructor.
     * 
     * @param pipid ID for the policy information point, may not be null or empty
     */
    protected AbstractPolicyInformationPoint(String pipid) {
        setId(pipid);
    }

    /** {@inheritDoc} */
    public String getId() {
        return id;
    }

    /**
     * Sets the ID for the policy information point.
     * 
     * @param pipid ID for the policy information point, may not be null or empty
     */
    protected void setId(String pipid) {
        String tempId = Strings.safeTrimOrNullString(pipid);
        if (tempId == null) {
            throw new IllegalArgumentException("Policy Information Point ID may not be null or empty");
        }
        id = tempId;
    }

    /** {@inheritDoc} */
    public void start() throws PIPException {
        // nothing to do
    }

    /** {@inheritDoc} */
    public void stop() throws PIPException {
        // nothing to do
    }
}
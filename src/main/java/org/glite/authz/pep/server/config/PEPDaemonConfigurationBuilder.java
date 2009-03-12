/*
 * Copyright 2008 EGEE Collaboration
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.glite.authz.pep.server.config;

import java.util.ArrayList;
import java.util.List;

import net.jcip.annotations.NotThreadSafe;

import org.glite.authz.common.config.AbstractServiceConfigurationBuilder;

/** A builder of {@link PEPDaemonConfiguration}s. */
@NotThreadSafe
public class PEPDaemonConfigurationBuilder extends AbstractServiceConfigurationBuilder<PEPDaemonConfiguration> {

    /** Registered policy decision point endpoints. */
    private List<String> pdpEndpoints;

    /** Constrcutor. */
    public PEPDaemonConfigurationBuilder() {
        super();
        pdpEndpoints = new ArrayList<String>();
    }

    public PEPDaemonConfigurationBuilder(PEPDaemonConfiguration prototype) {
        super(prototype);
        if (prototype.getPDPEndpoints() != null) {
            pdpEndpoints = new ArrayList<String>(prototype.getPDPEndpoints());
        } else {
            pdpEndpoints = new ArrayList<String>();
        }
    }
    
    /**
     * Gets a mutable list of registered PDP endpoints.
     * 
     * @return list of registered PDP endpoints
     */
    public List<String> getPDPEndpoints() {
        return pdpEndpoints;
    }
    
    /** {@inheritDoc} */
    public PEPDaemonConfiguration build() {
        PEPDaemonConfiguration config = new PEPDaemonConfiguration();
        populateConfiguration(config);
        config.setPDPEndpoints(pdpEndpoints);
        return config;
    }
}
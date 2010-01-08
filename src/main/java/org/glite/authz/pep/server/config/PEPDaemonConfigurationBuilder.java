/*
 * Copyright 2009 Members of the EGEE Collaboration.
 * See http://www.eu-egee.org/partners for details on the copyright holders. 
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
import org.glite.authz.pep.pip.PolicyInformationPoint;
import org.glite.authz.pep.obligation.ObligationService;

/** A builder of {@link PEPDaemonConfiguration}s. */
@NotThreadSafe
public class PEPDaemonConfigurationBuilder extends AbstractServiceConfigurationBuilder<PEPDaemonConfiguration> {

    /** Registered policy decision point endpoints. */
    private List<String> pdpEndpoints;

    /** Maximum number of responses to keep cached. */
    private int maxCachedResponses;

    /** Number milliseconds for which a response cache entry is valid. */
    private long cachedResponseTTL;
    
    /** Registered policy information points. */
    private List<PolicyInformationPoint> pips;

    /** Obligation processing service. */
    private ObligationService obligationService;

    /** Constructor. */
    public PEPDaemonConfigurationBuilder() {
        super();
        pdpEndpoints = new ArrayList<String>();
        pips = new ArrayList<PolicyInformationPoint>();
    }

    /**
     * Constructor that initializes this builder with the properties from the prototype configuration.
     * 
     * @param prototype the prototype configuration
     */
    public PEPDaemonConfigurationBuilder(PEPDaemonConfiguration prototype) {
        super(prototype);

        if (prototype.getPDPEndpoints() != null) {
            pdpEndpoints = new ArrayList<String>(prototype.getPDPEndpoints());
        } else {
            pdpEndpoints = new ArrayList<String>();
        }

        cachedResponseTTL = prototype.getCachedResponseTTL();
        maxCachedResponses = prototype.getMaxCachedResponses();
    }

    /**
     * Gets the duration, in milliseconds, responses will be cached.
     * 
     * @return duration, in milliseconds, responses will be cached
     */
    public long getCachedResponseTTL() {
        return cachedResponseTTL;
    }

    /**
     * Gets the maximum number of responses that will be cached.
     * 
     * @return maximum number of responses that will be cached
     */
    public int getMaxCachedResponses() {
        return maxCachedResponses;
    }

    /**
     * Sets the duration, in milliseconds, responses will be cached.
     * 
     * @param ttl duration, in milliseconds, responses will be cached
     */
    public void setCachedResponseTTL(long ttl) {
        cachedResponseTTL = ttl;
    }

    /**
     * Sets the maximum number of responses that will be cached.
     * 
     * @param max maximum number of responses that will be cached
     */
    public void setMaxCachedResponses(int max) {
        maxCachedResponses = max;
    }

    /**
     * Gets a mutable list of registered PDP endpoints.
     * 
     * @return list of registered PDP endpoints
     */
    public List<String> getPDPEndpoints() {
        return pdpEndpoints;
    }
    
    /**
     * Gets the registered policy information points.
     * 
     * @return registered policy information points
     */
    public List<PolicyInformationPoint> getPolicyInformationPoints() {
        return pips;
    }

    /**
     * Gets the obligation processing service.
     * 
     * @return obligation processing service
     */
    public ObligationService getObligationService() {
        return obligationService;
    }

    /**
     * Sets the obligation processing service.
     * 
     * @param service obligation processing service
     */
    public void setObligationService(ObligationService service) {
        obligationService = service;
    }

    /** {@inheritDoc} */
    public PEPDaemonConfiguration build() {
        PEPDaemonConfiguration config = new PEPDaemonConfiguration();
        populateConfiguration(config);
        config.setPDPEndpoints(pdpEndpoints);
        config.setCachedResponseTTL(cachedResponseTTL);
        config.setMaxCachedResponses(maxCachedResponses);
        config.setPolicyInformationPoints(pips);
        config.setObligationService(obligationService);
        return config;
    }
}
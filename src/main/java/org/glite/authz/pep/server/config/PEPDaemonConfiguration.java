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
import java.util.Collections;
import java.util.List;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.ServiceMetrics;
import org.glite.authz.common.config.AbstractServiceConfiguration;
import org.glite.authz.pep.obligation.ObligationService;
import org.glite.authz.pep.pip.PolicyInformationPoint;
import org.glite.authz.pep.server.Version;

/** Implementation of {@link PEPDaemonConfiguration}. */
@ThreadSafe
public class PEPDaemonConfiguration extends AbstractServiceConfiguration {

    /** Registered policy decision point endpoints. */
    private List<String> pdpEndpoints;

    /** Maximum number of responses to keep cached. */
    private int maxCachedResponses;

    /** Number milliseconds for which a response cache entry is valid. */
    private long cachedResponseTTL;

    /** Registered {@link PolicyInformationPoint}s. */
    private List<PolicyInformationPoint> pips;

    /** Obligation processing service. */
    private ObligationService obligationService;

    /** Constructor. */
    public PEPDaemonConfiguration() {
        super(new ServiceMetrics(Version.getServiceIdentifier()));
        pdpEndpoints = null;
        maxCachedResponses = 0;
        cachedResponseTTL = 0;
        pips = new ArrayList<PolicyInformationPoint>();
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
     * Gets an immutable list of PDP endpoints (URLs) to which requests may be sent.
     * 
     * @return list of PDP endpoints to which requests may be sent
     */
    public List<String> getPDPEndpoints() {
        return pdpEndpoints;
    }

    /**
     * Gets the policy information points meant to be applied to each request.
     * 
     * @return policy information points meant to be applied to each request
     */
    public List<PolicyInformationPoint> getPolicyInformationPoints() {
        return pips;
    }

    /**
     * Gets the service used to process response obligations.
     * 
     * @return service used to process response obligations
     */
    public ObligationService getObligationService() {
        return obligationService;
    }

    /**
     * Sets the duration, in milliseconds, responses will be cached.
     * 
     * @param ttl duration, in milliseconds, responses will be cached
     */
    protected final synchronized void setCachedResponseTTL(long ttl) {
        if (ttl < 1) {
            throw new IllegalArgumentException("Cache response time to live must be greater than zero");
        }

        if (cachedResponseTTL != 0) {
            throw new IllegalStateException("Cached response TTL has already been set, it may not be changed.");
        }
        cachedResponseTTL = ttl;
    }

    /**
     * Sets the maximum number of responses that will be cached.
     * 
     * @param max maximum number of responses that will be cached, must be greater than zero
     */
    protected final synchronized void setMaxCachedResponses(int max) {
        if (max < 0) {
            throw new IllegalArgumentException("Max resonse cache size must be greater than zero");
        }

        if (maxCachedResponses != 0) {
            throw new IllegalStateException("Max response cache size has already been set, it may not be changed.");
        }
        maxCachedResponses = max;
    }

    /**
     * Sets the list of PDP endpoints (URLs) to which requests may be sent.
     * 
     * @param endpoints list of PDP endpoints (URLs) to which requests may be sent
     */
    protected final synchronized void setPDPEndpoints(List<String> endpoints) {
        if (endpoints == null || endpoints.size() == 0) {
            return;
        }

        if (pdpEndpoints != null) {
            throw new IllegalStateException("PDP endpoints have already been set, they may not be changed.");
        }

        pdpEndpoints = Collections.unmodifiableList(endpoints);
    }

    /**
     * Sets the policy information points.
     * 
     * @param policyInformationPoints policy information point
     */
    protected final synchronized void setPolicyInformationPoints(List<PolicyInformationPoint> policyInformationPoints) {
        if (policyInformationPoints == null || policyInformationPoints.isEmpty()) {
            return;
        }

        if (pips != null) {
            throw new IllegalArgumentException(
                    "Policy Information Points have already been set, they may not be changed");
        }
        pips = Collections.unmodifiableList(policyInformationPoints);
    }

    /**
     * Sets the obligation processing service.
     * 
     * @param service obligation processing service
     */
    protected final synchronized void setObligationService(ObligationService service) {
        if (service == null) {
            return;
        }

        if (obligationService != null) {
            throw new IllegalArgumentException("Obligation service has already been set, they may not be changed");
        }
        obligationService = service;
    }
}
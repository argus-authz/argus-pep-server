
package org.glite.authz.pep.server.config;

import java.util.Collections;
import java.util.List;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.config.AbstractServiceConfiguration;
import org.glite.authz.pep.server.PEPDaemonMetrics;

/** Implementation of {@link PEPDaemonConfiguration}. */
@ThreadSafe
public class PEPDaemonConfiguration extends AbstractServiceConfiguration {

    /** Registered policy decision point endpoints. */
    private List<String> pdpEndpoints;

    /** Daemon metrics. */
    private PEPDaemonMetrics metrics;

    /** Constructor. */
    public PEPDaemonConfiguration() {
        super();
        pdpEndpoints = null;
        metrics = new PEPDaemonMetrics();
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
     * Sets the list of PDP endpoints (URLs) to which requests may be sent.
     * 
     * @param endpoints list of PDP endpoints (URLs) to which requests may be sent
     */
    protected synchronized final void setPDPEndpoints(List<String> endpoints){
        if(endpoints == null || endpoints.size() == 0){
            return;
        }
        
        if(pdpEndpoints != null){
            throw new IllegalStateException("PDP endpoints have already been set, they may not be changed.");
        }
        
        pdpEndpoints = Collections.unmodifiableList(endpoints);
    }

    /**
     * Gets the usage metrics for the service.
     * 
     * @return usage metrics for the service
     */
    public PEPDaemonMetrics getMetrics() {
        return metrics;
    }

    //TODO extra metrics to super class

}
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

package org.glite.authz.pep.pip;

import java.util.List;

import org.glite.authz.common.http.JettyAdminService;
import org.glite.authz.common.http.ShutdownTask;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A task that shuts down all the {@link PolicyInformationPoint} by calling
 * {@link PolicyInformationPoint#stop()}.
 * <p>
 * This task is intended to be used as a shutdown task within a
 * {@link JettyAdminService}.
 */
public class PolicyInformationPointsShutdownTask implements ShutdownTask {

    /** Class logger. */
    private Logger log= LoggerFactory.getLogger(PolicyInformationPointsShutdownTask.class);

    /** List of PIP */
    List<PolicyInformationPoint> pips_;

    /**
     * Constructor
     * 
     * @param pips List of {@link PolicyInformationPoint}
     */
    public PolicyInformationPointsShutdownTask(List<PolicyInformationPoint> pips) {
        pips_= pips;
    }

    /** {@inheritDoc} */
    public void run() {
        log.info("Stopping all PIPs");
        if (pips_ != null) {
            for (PolicyInformationPoint pip : pips_) {
                log.debug("Stopping PIP {}", pip.getId());
                try {
                    pip.stop();
                } catch (PIPException e) {
                    log.error("Can not stop " + pip.getId(), e);
                }
            }
        }

    }
}
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

import org.glite.authz.common.fqan.FQAN;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** A matching strategy used to match {@link FQAN}s against other FQANs, possibly containing the wildcard '*'. */
public class FQANMatchStrategy implements DFPMMatchStrategy<FQAN> {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(FQANMatchStrategy.class);

    /** {@inheritDoc} */
    public boolean isMatch(String dfpmKey, FQAN candidate) {
        // dfmpKey can be a FQAN regexp pattern
        boolean regexpMatches = false;
        try {
            regexpMatches = candidate.matches(dfpmKey);
        } catch (ParseException e) {
            log.debug(e.getMessage(), e);
        }
        if (log.isTraceEnabled()) {
            log.trace("'{}' matches '{}' ? {}", new Object[] { candidate, dfpmKey, regexpMatches });
        }
        return regexpMatches;

    }

}
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

import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.glite.authz.pep.obligation.ObligationProcessingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** A strategy for mapping a subject's DN and primary FQAN to an account indicator. */
public class DNPrimaryFQANAccountIndicatorMappingStrategy implements AccountIndicatorMappingStrategy {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(DNPrimaryFQANAccountIndicatorMappingStrategy.class);

    /** DN/FQAN to POSIX account name indicator mappings. */
    private DFPM loginNameMapping;

    /** Strategy to see if a {@link DFPM} key matches a given {@link X500Principal}. */
    private DFPMMatchStrategy<X500Principal> dnMatchStrategy;

    /** Strategy to see if a {@link DFPM} key matches a given {@link FQAN}. */
    private DFPMMatchStrategy<FQAN> fqanMatchStrategy;

    /** Whether to prefer a DN based mapping for the account indicator. */
    private boolean preferDNforAccountIndicator;

    /**
     * Constructor.
     * 
     * @param mappings DN/FQAN to POSIX account name indicator mappings, may not be null
     * @param dnMatching strategy to see if a {@link DFPM} key matches a given {@link X500Principal}, may not be null
     * @param fqanMatching strategy to see if a {@link DFPM} key matches a given {@link FQAN}, may not be null
     * @param preferDNmappings whether to prefer a DN based mapping, over an FQAN based mapping, for the account
     *            indicator
     */
    public DNPrimaryFQANAccountIndicatorMappingStrategy(DFPM mappings, DFPMMatchStrategy<X500Principal> dnMatching,
            DFPMMatchStrategy<FQAN> fqanMatching, boolean preferDNmappings) {
        if (mappings == null) {
            throw new IllegalArgumentException("DN/FQAN to POSIX mapping may not be null");
        }
        loginNameMapping = mappings;

        if (dnMatching == null) {
            throw new IllegalArgumentException("DN matching strategy may not be null");
        }
        dnMatchStrategy = dnMatching;

        if (fqanMatching == null) {
            throw new IllegalArgumentException("FQAN matching strategy may not be null");
        }
        fqanMatchStrategy = fqanMatching;

        preferDNforAccountIndicator = preferDNmappings;
    }

    /** {@inheritDoc} */
    public String mapToAccountIndicator(X500Principal subjectDN, FQAN primaryFQAN, List<FQAN> secondaryFQANs)
            throws ObligationProcessingException {
        log.debug("Starting to map subject {} with primary FQAN {} to account indicator", subjectDN
                .getName(X500Principal.RFC2253), primaryFQAN);
        String indicatorFromDN = null;
        String indicatorFromFQAN = null;

        // Loop over the entries in the login name map file
        // if the map key is meant to match a DN check it against the subject DN
        // if the map key is meant to match a FQAN check it against the primary FQAN
        // we keep track of both the first match against the DN and primary FQAN so that if whichever
        // the preferred account indicator does not match any entry we don't have to go loop through
        // the list again to see if the other indicator matches
        for (String mapKey : loginNameMapping.keySet()) {
            if (indicatorFromDN == null && loginNameMapping.isDNMapEntry(mapKey)
                    && dnMatchStrategy.isMatch(mapKey, subjectDN)) {
                indicatorFromDN = loginNameMapping.get(mapKey).get(0);
                if (preferDNforAccountIndicator) {
                    break;
                }
            }

            if (primaryFQAN != null && indicatorFromFQAN == null && loginNameMapping.isFQANMapEntry(mapKey)
                    && fqanMatchStrategy.isMatch(mapKey, primaryFQAN)) {
                indicatorFromFQAN = loginNameMapping.get(mapKey).get(0);
                if (!preferDNforAccountIndicator) {
                    break;
                }
            }
        }

        // If we get to this point then our preferred account indicator did not yield a match
        // so we return the second choice, which may be null if that didn't match either
        String accountIndicator;
        if (preferDNforAccountIndicator) {
            accountIndicator = (indicatorFromDN != null) ? indicatorFromDN : indicatorFromFQAN;
        } else {
            accountIndicator = (indicatorFromFQAN != null) ? indicatorFromFQAN : indicatorFromDN;
        }

        log.debug("Subject {} with primary FQAN {} mapped to account indicator {}", new Object[] {
                subjectDN.getName(X500Principal.RFC2253), primaryFQAN, accountIndicator });
        return accountIndicator;
    }
}
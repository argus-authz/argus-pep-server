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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.glite.authz.common.fqan.FQAN;
import org.glite.authz.pep.obligation.ObligationProcessingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A strategy for mapping a subject's DN, primary and secondary FQANs to primary and secondary groups.
 */
public class DNFQANGroupNameMappingStrategy implements GroupNameMappingStrategy {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(DNFQANGroupNameMappingStrategy.class);

    /** DN/FQAN to POSIX group name mappings. */
    private DFPM groupNameMapping;

    /** Strategy to see if a {@link DFPM} key matches a given {@link FQAN}. */
    private DFPMMatchStrategy<FQAN> fqanMatchStrategy;

    /** Strategy to see if a {@link DFPM} key matches a given {@link X500Principal}. */
    private DFPMMatchStrategy<X500Principal> dnMatchStrategy;

    /** Whether to prefer a DN based mapping for the primary group name mapping. */
    private boolean preferDNForPrimaryGroupName;

    /**
     * Constructor.
     * 
     * @param groupMappings DN/FQAN to POSIX group name mappings, may not be null
     * @param dnMatching strategy to see if a {@link DFPM} key matches a given {@link X500Principal}, may not be null
     * @param fqanMatching strategy to see if a {@link DFPM} key matches a given {@link FQAN}, may not be null
     * @param preferDNmappings whether to prefer a DN based mapping, over an FQAN based mapping, for the primary group
     *            name
     */
    public DNFQANGroupNameMappingStrategy(DFPM groupMappings, DFPMMatchStrategy<X500Principal> dnMatching,
            DFPMMatchStrategy<FQAN> fqanMatching, boolean preferDNmappings) {
        if (groupMappings == null) {
            throw new IllegalArgumentException("DN/FQAN to POSIX group mapping may not be null");
        }
        groupNameMapping = groupMappings;

        if (dnMatching == null) {
            throw new IllegalArgumentException("DN matching strategy may not be null");
        }
        dnMatchStrategy = dnMatching;

        if (fqanMatching == null) {
            throw new IllegalArgumentException("FQAN matching strategy may not be null");
        }
        fqanMatchStrategy = fqanMatching;

        preferDNForPrimaryGroupName = preferDNmappings;
    }

    /** {@inheritDoc} */
    public List<String> mapToGroupNames(X500Principal subjectDN, FQAN primaryFQAN, List<FQAN> secondaryFQANs)
            throws ObligationProcessingException {
        log.debug("Mapping group names for subject {} with primary FQAN {} and secondary FQANs {}", new Object[] {
                subjectDN.getName(), primaryFQAN, secondaryFQANs });

        List<String> dnGroupNames = new ArrayList<String>();
        List<String> fqanGroupNames = new ArrayList<String>();

        for (String mapKey : groupNameMapping.keySet()) {
            if (groupNameMapping.isDNMapEntry(mapKey)) {
                if (subjectDN != null) {
                    if (dnMatchStrategy.isMatch(mapKey, subjectDN)) {
                        List<String> grNames = groupNameMapping.get(mapKey);
                        dnGroupNames.addAll(grNames);
                    }
                }
            } else if (groupNameMapping.isFQANMapEntry(mapKey)) {
                if (primaryFQAN != null) {
                    if (fqanMatchStrategy.isMatch(mapKey, primaryFQAN)) {
                        List<String> grNames = groupNameMapping.get(mapKey);
                        fqanGroupNames.addAll(grNames);
                    }
                }
            }
        }
        for (String mapKey : groupNameMapping.keySet()) {
            if (groupNameMapping.isFQANMapEntry(mapKey)) {
                if (secondaryFQANs != null) {
                    for (FQAN secondaryFQAN : secondaryFQANs) {
                        if (fqanMatchStrategy.isMatch(mapKey, secondaryFQAN)) {
                            List<String> grNames = groupNameMapping.get(mapKey);
                            fqanGroupNames.addAll(grNames);
                        }
                    }
                }
            }
        }
        List<String> groupNames = new ArrayList<String>();
        if (log.isTraceEnabled()) {
            log.trace("DN groups: {} FQAN groups: {}", dnGroupNames, fqanGroupNames);
        }
        if (preferDNForPrimaryGroupName) {
            groupNames.addAll(dnGroupNames);
            groupNames.addAll(fqanGroupNames);
        } else {
            groupNames.addAll(fqanGroupNames);
            groupNames.addAll(dnGroupNames);
        }

        removeDuplicates(groupNames);

        log.debug("Subject {} with primary FQAN {} and secondary FQANs {} mapped to group names: {}", new Object[] {
                subjectDN.getName(), primaryFQAN, secondaryFQANs, groupNames });
        return groupNames;
    }

    /**
     * Removes duplicates names from the list. The first occurrence is retained.
     * 
     * @param groupNames list of names from which duplicates should be removed.
     */
    private void removeDuplicates(List<String> groupNames) {
        HashSet<String> alreadySeen = new HashSet<String>();

        String name;
        Iterator<String> nameItr = groupNames.iterator();
        while (nameItr.hasNext()) {
            name = nameItr.next();
            if (alreadySeen.contains(name)) {
                nameItr.remove();
            } else {
                alreadySeen.add(name);
            }
        }
    }
}
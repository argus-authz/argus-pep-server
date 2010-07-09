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

import org.glite.authz.pep.obligation.ObligationProcessingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** A strategy for mapping a subject's primary and secondary FQANs to primary and secondary groups. */
public class FQANGroupNameMappingStrategy implements GroupNameMappingStrategy {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(FQANGroupNameMappingStrategy.class);

    /** DN/FQAN to POSIX group name mappings. */
    private DFPM groupNameMapping;

    /** Strategy to see if a {@link DFPM} key matches a given {@link FQAN}. */
    private DFPMMatchStrategy<FQAN> fqanMatchStrategy;

    /**
     * Constructor.
     * 
     * @param mappings DN/FQAN to POSIX group name mappings, may not be null
     * @param fqanMatching strategy to see if a {@link DFPM} key matches a given {@link FQAN}, may not be null
     */
    public FQANGroupNameMappingStrategy(DFPM mappings, DFPMMatchStrategy<FQAN> fqanMatching) {
        if (mappings == null) {
            throw new IllegalArgumentException("DN/FQAN to POSIX mapping may not be null");
        }
        groupNameMapping = mappings;

        if (fqanMatching == null) {
            throw new IllegalArgumentException("FQAN matching strategy may not be null");
        }
        fqanMatchStrategy = fqanMatching;
    }

    /** {@inheritDoc} */
    public List<String> mapToGroupNames(X500Principal subjectDN, FQAN primaryFQAN, List<FQAN> secondaryFQANs)
            throws ObligationProcessingException {
        log.debug("Starting to map subject {} with primary FQAN {} and second FQANs {} to group names", new Object[] {
                subjectDN.getName(X500Principal.RFC2253), primaryFQAN, secondaryFQANs });

        if(primaryFQAN == null){
            log.error("Primary FQAN for subject " + subjectDN.getName() + " is null, group mapping can not be performed");
            throw new ObligationProcessingException("Primary FQAN is null, group mapping can not be performed");
        }
        
        ArrayList<String> groups = new ArrayList<String>();

        String firstGroupFromFQAN = null;
        for (String mapKey : groupNameMapping.keySet()) {
            if (groupNameMapping.isFQANMapEntry(mapKey)) {
                if (firstGroupFromFQAN == null && fqanMatchStrategy.isMatch(mapKey, primaryFQAN)) {
                    firstGroupFromFQAN = groupNameMapping.get(mapKey).get(0);
                }

                if (secondaryFQANs != null) {
                    for (FQAN secondaryFQAN : secondaryFQANs) {
                        if (fqanMatchStrategy.isMatch(mapKey, secondaryFQAN)) {
                            groups.addAll(groupNameMapping.get(mapKey));
                        }
                    }
                }
            }
        }

        if (firstGroupFromFQAN == null) {
            throw new ObligationProcessingException("Subject " + subjectDN.getName(X500Principal.RFC2253)
                    + " could not be mapped to a primary group");
        }
        groups.add(0, firstGroupFromFQAN);

        removeDuplicates(groups);
        log.debug("Subject {} with primary FQAN {} and second FQANs {} mapped to group names {}",
                new Object[] { subjectDN.getName(X500Principal.RFC2253), primaryFQAN, secondaryFQANs, groups });
        return groups;
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
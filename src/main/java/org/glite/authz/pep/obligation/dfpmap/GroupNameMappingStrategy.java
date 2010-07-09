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

/**
 * A strategy for mapping a subject, identified by a DN, primary FQAN, and secondary FQANs to a set of POSIX group
 * names.
 */
public interface GroupNameMappingStrategy {

    /**
     * Maps a subject to a set of POSIX group names.
     * 
     * @param subjectDN subject's DN
     * @param primaryFQAN subject's primary FQAN
     * @param secondaryFQANs subject's secondary FQANs
     * 
     * @return the group names with the primary group being the first element in the list, or null
     * 
     * @throws ObligationProcessingException thrown if there is a problem mapping the user to POSIX group names
     */
    public List<String> mapToGroupNames(X500Principal subjectDN, FQAN primaryFQAN, List<FQAN> secondaryFQANs)
            throws ObligationProcessingException;
}
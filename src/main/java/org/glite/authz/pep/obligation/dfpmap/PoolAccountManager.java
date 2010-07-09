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

/** A manager of pool accounts. */
public interface PoolAccountManager {
    
    /**
     * Checks whether the given account indicator represents is associated with pool accounts.
     * 
     * @param accountIndicator the account indicator
     * 
     * @return true if the account indiciator is associated with pool accounts, false if not
     */
    public boolean isPoolAccountPrefix(String accountIndicator);

    /**
     * Gets the pool account prefix from the account indicator. If the indicator does not represent a pool account name
     * prefix null is returned.
     * 
     * @param accountIndicator the account indicator
     * 
     * @return the pool account name prefix or null if the indicator is not associated with pool accounts
     */
    public String getPoolAccountPrefix(String accountIndicator);

    /**
     * Gets all pool account name prefixes for the managed accounts.
     * 
     * @return name prefixes for the managed accounts
     */
    public List<String> getPoolAccountNamePrefixes();

    /**
     * Gets a list of all the managed pool accounts.
     * 
     * @return list of all the managed pool accounts
     */
    public List<String> getPoolAccountNames();

    /**
     * Gets a list of all the managed pool accounts with a given prefix.
     * 
     * @param prefix pool account name prefix
     * 
     * @return list of all the managed pool accounts with a given prefix
     */
    public List<String> getPoolAccountNames(String prefix);

    /**
     * Maps a subject to a pool account with the given prefix.
     * 
     * @param accountNamePrefix pool account name prefix
     * @param subjectDN subject's DN
     * @param primaryGroup subject's primary groups
     * @param secondaryGroups subject's second groups
     * 
     * @return pool account to which the subject was mapped
     * 
     * @throws ObligationProcessingException thrown if there is a problem mapping the user to an account
     */
    public String mapToAccount(String accountNamePrefix, X500Principal subjectDN, String primaryGroup,
            List<String> secondaryGroups) throws ObligationProcessingException;
}
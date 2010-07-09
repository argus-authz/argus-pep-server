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
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import org.glite.authz.pep.obligation.ObligationProcessingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An in-memory manager for pool accounts.
 * 
 * This implementation is not generally useful in production environments but is useful for testing and to provide an
 * example of the various steps and checks needed when doing pool account management without having to worry about the
 * underlying persistent store.
 */
public class MemoryBackedPoolAcountManager implements PoolAccountManager {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(MemoryBackedPoolAcountManager.class);

    /** Managed pool accounts indexed by prefix. */
    private HashMap<String, List<String>> managedAccounts;

    /** Current assigned accounts. Indexes are of the form dn{:primary_group_name{:secondary_group_name}*}? */
    private HashMap<String, String> currentAccountMappings;

    /**
     * Constructor.
     * 
     * @param managedAccounts pool accounts to be managed
     */
    public MemoryBackedPoolAcountManager(List<String> poolAccounts) {
        managedAccounts = new HashMap<String, List<String>>();
        currentAccountMappings = new HashMap<String, String>();

        if (poolAccounts != null) {
            Pattern accountPrefixPat = Pattern.compile("^(\\p{Alpha}*)\\p{Digit}*$");
            Matcher prefixMatcher;
            String prefix;
            for (String account : poolAccounts) {
                prefixMatcher = accountPrefixPat.matcher(account);
                if (prefixMatcher.find()) {
                    prefix = prefixMatcher.group(1);
                    if (prefix != null) {
                        addManagedPoolAccount(prefix, account);
                    } else {
                        log.warn("{} did not contain a valid pool account name prefix, ignoring it");
                    }
                } else {
                    log.warn("{} is not a valid pool account name, ignoring it");
                }
            }
        }
    }
    
    /** {@inheritDoc} */
    public List<String> getPoolAccountNamePrefixes() {
        return new ArrayList<String>(managedAccounts.keySet());
    }

    /** {@inheritDoc} */
    public List<String> getPoolAccountNames() {
        ArrayList<String> allManagedAccounts = new ArrayList<String>();
        for (List<String> accountSet : managedAccounts.values()) {
            allManagedAccounts.addAll(accountSet);
        }

        return allManagedAccounts;
    }

    /** {@inheritDoc} */
    public List<String> getPoolAccountNames(String prefix) {
        return managedAccounts.get(prefix);
    }

    /** {@inheritDoc} */
    public boolean isPoolAccountPrefix(String accountIndicator) {
        return accountIndicator.startsWith(".");
    }
    
    /** {@inheritDoc} */
    public String getPoolAccountPrefix(String accountIndicator) {
        if(isPoolAccountPrefix(accountIndicator)){
            return accountIndicator.substring(1);
        }
        return null;
    }

    /** {@inheritDoc} */
    public synchronized String mapToAccount(String accountNamePrefix, X500Principal subjectDN, String primaryGroup,
            List<String> secondaryGroups) throws ObligationProcessingException {
        if(accountNamePrefix.startsWith(".")){
            accountNamePrefix = accountNamePrefix.substring(1);
        }
        
        log.debug("Mapping subject {} with primary group {} and secondary groups {} to a pool account with prefix {}",
                new Object[] { subjectDN.getName(), primaryGroup, secondaryGroups, accountNamePrefix });
        String accountMappingKey = createAccountMappingKey(subjectDN, primaryGroup, secondaryGroups);

        String loginName = currentAccountMappings.get(accountMappingKey);
        if (loginName != null) {
            log.debug("Subject {} has an existing account mapping to account {}", subjectDN.getName(), loginName);
            if (!loginName.startsWith(accountNamePrefix)) {
                log.error("Subject " + subjectDN.getName() + " has an existing mapping to account " + loginName
                        + " but this account name does not start with the pool account name prefix, "
                        + accountNamePrefix + ", to which they were mapped.");
                throw new ObligationProcessingException("Error with existing pool account mapping for this subject");
            }
            return loginName;
        }

        List<String> managedAccounts = getPoolAccountNames(accountNamePrefix);
        if (managedAccounts == null) {
            return null;
        }

        log.debug("Subject {} does not have an existing pool account mapping, attempting to create a new one", subjectDN.getName());
        for (String account : managedAccounts) {
            if (!currentAccountMappings.values().contains(account)) {
                log.debug("Subject {} given a new pool account mapping to account {}", subjectDN.getName(), account);
                loginName = account;
                currentAccountMappings.put(accountMappingKey, account);
                return loginName;
            }
        }

        log.warn("No pool account, with prefix {}, available to which {} could be mapped", accountNamePrefix, subjectDN
                .getName());
        return null;
    }

    /**
     * Creates an account mapping key associated with a pool account. The key is in the form:
     * canonical_dn{:primary_group_name{:secondary_group_names}*}?
     * 
     * @param subjectDN DN of the subject
     * @param primaryGroup name of the subject's primary group
     * @param secondaryGroups names of the subject's secondary groups
     * 
     * @return the constructed account mapping key
     */
    private String createAccountMappingKey(X500Principal subjectDN, String primaryGroup, List<String> secondaryGroups) {
        StringBuilder builder = new StringBuilder(subjectDN.getName(X500Principal.CANONICAL));

        if (primaryGroup != null) {
            builder.append(":").append(primaryGroup);

            if (secondaryGroups != null) {
                for (String name : secondaryGroups) {
                    builder.append(":").append(name);
                }
            }
        }

        return builder.toString();
    }

    /**
     * Adds a pool account to the list of managed accounts.
     * 
     * @param prefix the pool account name prefix
     * @param loginName the pool account name
     */
    private void addManagedPoolAccount(String prefix, String loginName) {
        if (!loginName.startsWith(prefix)) {
            throw new IllegalArgumentException("Account name " + loginName
                    + " does not begin with the provided pool account name prefix " + prefix);
        }

        List<String> accounts = managedAccounts.get(prefix);

        if (accounts == null) {
            accounts = new ArrayList<String>();
            managedAccounts.put(prefix, accounts);
        }

        accounts.add(loginName);
    }
}

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

import java.util.Collections;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.glite.authz.common.fqan.FQAN;
import org.glite.authz.pep.obligation.ObligationProcessingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Maps a subject to a POSIX account based on the subject's DN, primary FQAN, and secondary FQANs. */
public class AccountMapper {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(AccountMapper.class);

    /** Strategy used to map a subject to a pool account indicator. */
    private final AccountIndicatorMappingStrategy accountIndicatorMappingStrategy;

    /** Strategy used to map a subject to a set of group names. */
    private final GroupNameMappingStrategy groupNameMappingStrategy;

    /** Manager used to track and access pool accounts. */
    private final PoolAccountManager poolAccountManager;

    /**
     * Whether the failure to map a primary group name cause the {@link #mapToAccount(X500Principal, FQAN, List)} method
     * to fail or not. Default: {@value}
     */
    private boolean noPrimaryGroupNameIsError = false;

    /**
     * Constructor.
     * 
     * @param aimStrategy strategy used to map a subject to a pool account indicator
     * @param gnmStrategy strategy used to map a subject to a set of group names
     * @param pam manager used to track and access pool accounts
     */
    public AccountMapper(AccountIndicatorMappingStrategy aimStrategy, GroupNameMappingStrategy gnmStrategy,
            PoolAccountManager pam) {
        if (aimStrategy == null) {
            throw new IllegalArgumentException("Account indiciator mapping strategy may not be null");
        }
        accountIndicatorMappingStrategy = aimStrategy;

        if (gnmStrategy == null) {
            throw new IllegalArgumentException("Group name mapping strategy may not be null");
        }
        groupNameMappingStrategy = gnmStrategy;

        if (pam == null) {
            throw new IllegalArgumentException("Pool account manager may not be null");
        }
        poolAccountManager = pam;
    }

    /**
     * Constructor.
     * 
     * @param aimStrategy strategy used to map a subject to a pool account indicator
     * @param gnmStrategy strategy used to map a subject to a set of group names
     * @param pam manager used to track and access pool accounts
     * @param noPrimaryGroupNameIsError whether the failure to map a primary group name cause an error or not
     */
    public AccountMapper(AccountIndicatorMappingStrategy aimStrategy, GroupNameMappingStrategy gnmStrategy,
            PoolAccountManager pam, boolean noPrimaryGroupNameIsError) {
        this(aimStrategy, gnmStrategy, pam);
        this.noPrimaryGroupNameIsError = noPrimaryGroupNameIsError;
    }

    /**
     * Maps a subject to a POSIX account.
     * 
     * @param subjectDN subject's DN
     * @param primaryFQAN subject's primary FQAN, may be null
     * @param secondaryFQANs subject's secondary FQANs, may be null
     * 
     * @return account to which the subject is mapped
     * 
     * @throws ObligationProcessingException thrown is there is a problem mapping the subject to an account
     */
    public PosixAccount mapToAccount(X500Principal subjectDN, FQAN primaryFQAN, List<FQAN> secondaryFQANs)
            throws ObligationProcessingException {
        if (subjectDN==null) {
            String error= "Can not map without Subject DN";
            log.error(error);
            throw new ObligationProcessingException(error);
        }
        return mapToAccountByDNFQAN(subjectDN, primaryFQAN, secondaryFQANs);
    }

    /**
     * Maps a subject, identified by a DN and set of FQANs, to an account.
     * 
     * @param subjectDN DN of the subject
     * @param primaryFQAN subject's primary FQAN
     * @param secondaryFQANs subject's secondary FQAN
     * 
     * @return account to which the subject is mapped
     * 
     * @throws ObligationProcessingException thrown if there is a problem mapping the user to an account
     */
    private PosixAccount mapToAccountByDNFQAN(X500Principal subjectDN, FQAN primaryFQAN, List<FQAN> secondaryFQANs)
            throws ObligationProcessingException {
        log.debug("Mapping subject {} with primary FQAN {} and secondary FQANs {} to a POSIX account", new Object[] {
                subjectDN, primaryFQAN, secondaryFQANs });

        String accountIndicator = accountIndicatorMappingStrategy.mapToAccountIndicator(subjectDN, primaryFQAN,
                secondaryFQANs);
        if (accountIndicator == null) {
            String error = "Failed to map subject DN " + subjectDN + ", primary FQAN " + primaryFQAN
                    + ", secondary FQANs " + secondaryFQANs + " to an account indicator";
            log.error(error);
            throw new ObligationProcessingException(error);
        }

        boolean indicatorIsPoolAccountPrefix = false;
        if (poolAccountManager.isPoolAccountPrefix(accountIndicator)) {
            indicatorIsPoolAccountPrefix = true;
            accountIndicator = poolAccountManager.getPoolAccountPrefix(accountIndicator);
        }
        log.debug("Subject {} mapped to account indiciator {}", subjectDN.getName(), accountIndicator);

        String primaryGroupName = null;
        List<String> secondaryGroupNames = null;
        List<String> groupNames = groupNameMappingStrategy.mapToGroupNames(subjectDN, primaryFQAN, secondaryFQANs);
        if (groupNames != null && !groupNames.isEmpty()) {
            primaryGroupName = groupNames.get(0);
            if (groupNames.size() > 1) {
                secondaryGroupNames = groupNames.subList(1, groupNames.size());
            } else {
                secondaryGroupNames = Collections.emptyList();
            }
        }

        // if noPrimaryGroupNameIsError throw an error
        if (primaryGroupName == null && noPrimaryGroupNameIsError) {
            String error = "Failed to map subject DN " + subjectDN.getName() + ", primary FQAN " + primaryFQAN
                    + ", secondary FQANs " + secondaryFQANs + " to a POSIX primary group";
            log.error(error);
            throw new ObligationProcessingException(error);
        }

        log.debug("Subject {} mapped to POSIX group {} and secondary groups {}", new Object[] { subjectDN.getName(),
                primaryGroupName, secondaryGroupNames, });

        String loginName;
        if (indicatorIsPoolAccountPrefix) {
            loginName = poolAccountManager.mapToAccount(accountIndicator, subjectDN, primaryGroupName,
                    secondaryGroupNames);
        } else {
            loginName = accountIndicator;
        }
        if (loginName == null) {
            String error = "Failed to map subject DN " + subjectDN.getName() + ", primary FQAN " + primaryFQAN
                    + ", secondary FQANs " + secondaryFQANs + " to a POSIX login name";
            log.error(error);
            throw new ObligationProcessingException(error);
        }
        log.debug("Subject {} mapped to POSIX login name {}", subjectDN.getName(), loginName);

        return new PosixAccount(loginName, primaryGroupName, secondaryGroupNames);
    }
}
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

import java.io.File;
import java.io.FilenameFilter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.httpclient.URIException;
import org.apache.commons.httpclient.util.URIUtil;
import org.glite.authz.common.util.Strings;
import org.glite.authz.pep.obligation.ObligationProcessingException;
import org.glite.voms.PKIUtils;
import org.jruby.ext.posix.FileStat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link PoolAccountManager} implementation that uses the filesystem as a persistence mechanism.
 * 
 * The mapping directory must be prepopulated with files whose names represent every pool account to be managed.
 */
public class GridMapDirPoolAccountManager implements PoolAccountManager {

    /** Class logger. */
    private Logger log = LoggerFactory.getLogger(GridMapDirPoolAccountManager.class);

    /** Directory containing the grid mappings. */
    private final File gridMapDirectory;

    /**
     * Regexp pattern used to identify pool account names. Contains a single group match whose value is the pool account
     * name prefix.
     * 
     * Bug fix: https://savannah.cern.ch/bugs/?66574
     */
    private final Pattern poolAccountNamePattern= Pattern.compile("^(\\w*[a-zA-z])\\d+$");

    /**
     * Constructor.
     * 
     * @param gridMapDir existing, readable, and writable directory where grid mappings will be recorded
     */
    public GridMapDirPoolAccountManager(File gridMapDir) {
        if (!gridMapDir.exists()) {
            throw new IllegalArgumentException("Grid map directory " + gridMapDir.getAbsolutePath() + " does not exist");
        }

        if (!gridMapDir.canRead()) {
            throw new IllegalArgumentException("Grid map directory " + gridMapDir.getAbsolutePath()
                    + " is not readable by this process");
        }

        if (!gridMapDir.canWrite()) {
            throw new IllegalArgumentException("Grid map directory " + gridMapDir.getAbsolutePath()
                    + " is not writable by this process");
        }

        gridMapDirectory = gridMapDir;
    }

    /** {@inheritDoc} */
    public List<String> getPoolAccountNamePrefixes() {
        ArrayList<String> poolAccountNames = new ArrayList<String>();

        Matcher nameMatcher;
        File[] files = gridMapDirectory.listFiles();
        for (File file : files) {
            if (file.isFile()) {
                nameMatcher = poolAccountNamePattern.matcher(file.getName());
                if (nameMatcher.matches() && !poolAccountNames.contains(nameMatcher.group(1))) {
                    poolAccountNames.add(nameMatcher.group(1));
                }
            }
        }

        return poolAccountNames;
    }

    /** {@inheritDoc} */
    public List<String> getPoolAccountNames() {
        return Arrays.asList(getAccountFileNames(null));
    }

    /** {@inheritDoc} */
    public List<String> getPoolAccountNames(String prefix) {
        return Arrays.asList(getAccountFileNames(Strings.safeTrimOrNullString(prefix)));
    }

    /** {@inheritDoc} */
    public boolean isPoolAccountPrefix(String accountIndicator) {
        return accountIndicator.startsWith(".");
    }

    /** {@inheritDoc} */
    public String getPoolAccountPrefix(String accountIndicator) {
        if (isPoolAccountPrefix(accountIndicator)) {
            return accountIndicator.substring(1);
        }
        return null;
    }

    /** {@inheritDoc} */
    public String mapToAccount(String accountNamePrefix, X500Principal subjectDN, String primaryGroup,
            List<String> secondaryGroups) throws ObligationProcessingException {
        String subjectIdentifier = buildSubjectIdentifier(subjectDN, primaryGroup, secondaryGroups);

        log.debug("Checking if there is an existing account mapping for subject {} with primary group {} and secondary groups {}",
                  new Object[] { subjectDN.getName(), primaryGroup, secondaryGroups });
        String accountName = getAccountNameByKey(accountNamePrefix, subjectIdentifier);
        if (accountName != null) {
            log.debug("An existing account mapping has mapped subject {} with primary group {} and secondary groups {} to pool account {}",
                      new Object[] { subjectDN.getName(), primaryGroup, secondaryGroups, accountName });
            return accountName;
        }

        accountName = createMapping(accountNamePrefix, subjectIdentifier);
        if (accountName != null) {
            log.debug("A new account mapping has mapped subject {} with primary group {} and secondary groups {} to pool account {}",
                      new Object[] { subjectDN.getName(), primaryGroup, secondaryGroups, accountName });
        } else {
            log.debug("No pool account was available to which subject {} with primary group {} and secondary groups {} could be mapped",
                      new Object[] { subjectDN.getName(), primaryGroup, secondaryGroups });
        }
        return accountName;
    }

    /**
     * Gets the user account to which a given subject had previously been mapped.
     * 
     * @param accountNamePrefix prefix of the account to which the subject should be mapped
     * @param subjectIdentifier key identifying the subject
     * 
     * @return account to which the subject was mapped or null if not map currently exists
     * 
     * @throws ObligationProcessingException thrown if the link count on the pool account name file or the account key
     *             file is more than 2
     */
    private String getAccountNameByKey(String accountNamePrefix, String subjectIdentifier)
            throws ObligationProcessingException {
        File subjectIdentifierFile = new File(buildSubjectIdentifierFilePath(subjectIdentifier));
        if (!subjectIdentifierFile.exists()) {
            return null;
        }

        FileStat subjectIdentifierFileStat = PosixUtil.getFileStat(subjectIdentifierFile.getAbsolutePath());
        if (subjectIdentifierFileStat.nlink() != 2) {
            log.error("The subject identifier file " + subjectIdentifierFile.getAbsolutePath()
                    + " has a link count greater than 2.  This mapping is corrupted and can not be used.");
            throw new ObligationProcessingException("Unable to map subject to a POSIX account");
        }

        FileStat accountFileStat;
        for (File accountFile : getAccountFiles(accountNamePrefix)) {
            accountFileStat = PosixUtil.getFileStat(accountFile.getAbsolutePath());
            if (accountFileStat.ino() == subjectIdentifierFileStat.ino()) {
                if (accountFileStat.nlink() != 2) {
                    log.error("The pool account file " + accountFile.getAbsolutePath()
                            + " has a link count greater than 2.  This mapping is corrupted and can not be used.");
                }
                return accountFile.getName();
            }
        }

        return null;
    }

    /**
     * Creates a mapping between an account and a subject identified by the account key.
     * 
     * @param accountNamePrefix prefix of the pool account names
     * @param subjectIdentifier key identifying the subject mapped to the account
     * 
     * @return the account to which the subject was mapped or null if not account was available
     */
    public String createMapping(String accountNamePrefix, String subjectIdentifier) {
        FileStat accountFileStat;
        for (File accountFile : getAccountFiles(accountNamePrefix)) {
            log.debug("Checking if grid map account {} may be linked to subject identifier {}", accountFile.getName(),
                    subjectIdentifier);
            String subjectIdentifierFilePath = buildSubjectIdentifierFilePath(subjectIdentifier);
            accountFileStat = PosixUtil.getFileStat(accountFile.getAbsolutePath());
            if (accountFileStat.nlink() == 1) {
                PosixUtil.createLink(accountFile.getAbsolutePath(), subjectIdentifierFilePath, false);
                accountFileStat = PosixUtil.getFileStat(accountFile.getAbsolutePath());
                if (accountFileStat.nlink() == 2) {
                    log.debug("Linked subject identifier {} to pool account file {}", subjectIdentifier, accountFile
                            .getName());
                    return accountFile.getName();
                }
                new File(subjectIdentifierFilePath).delete();
            }
            log.debug("Could not map to account {}", accountFile.getName());
        }

        return null;
    }

    /**
     * Creates an identifier for the subject that is based on the subject's DN and primary and secondary groups.
     * 
     * @param subjectDN DN of the subject
     * @param primaryGroupName primary group to which the subject was assigned, may be null
     * @param secondaryGroupNames secondary groups to which the subject assigned, may be null
     * 
     * @return the identifier for the subject
     */
    private String buildSubjectIdentifier(X500Principal subjectDN, String primaryGroupName,
            List<String> secondaryGroupNames) {
        StringBuilder identifier = new StringBuilder();

        try {
            String encodedId = URIUtil.encodeWithinPath(PKIUtils.getOpenSSLFormatPrincipal(subjectDN, true));
            identifier.append(encodedId.toLowerCase());
        } catch (URIException e) {
            throw new RuntimeException("US-ASCII charset required to be supported by JVM but is not available");
        }

        if (primaryGroupName != null) {
            identifier.append(":").append(primaryGroupName);
        }

        if (secondaryGroupNames != null && !secondaryGroupNames.isEmpty()) {
            TreeSet<String> sortedNames = new TreeSet<String>(secondaryGroupNames);
            for (String name : sortedNames) {
                identifier.append(":").append(name);
            }
        }

        return identifier.toString();
    }

    /**
     * Builds the absolute path to the subject identifier file.
     * 
     * @param subjectIdentifier the subject identifier
     * 
     * @return the absolute path to the subject identifier file
     */
    private String buildSubjectIdentifierFilePath(String subjectIdentifier) {
        return gridMapDirectory.getAbsolutePath() + File.separator + subjectIdentifier;
    }

    /**
     * Gets a list of account files where the file names begin with the given prefix.
     * 
     * @param prefix prefix with which the file names should begin, may be null to signify all file names
     * 
     * @return the selected account files
     */
    private File[] getAccountFiles(final String prefix) {
        return gridMapDirectory.listFiles(new FilenameFilter() {
            public boolean accept(File dir, String name) {
                Matcher nameMatcher = poolAccountNamePattern.matcher(name);
                if (nameMatcher.matches()) {
                    // BUG FIX: https://savannah.cern.ch/bugs/?66574
                    if (prefix == null || prefix.equals(nameMatcher.group(1))) {
                        return true;
                    }
                }
                return false;
            }
        });
    }

    /**
     * Gets a list of account file names where the names begin with the given prefix.
     * 
     * @param prefix prefix with which the file names should begin, may be null to signify all file names
     * 
     * @return the selected account file names
     */
    private String[] getAccountFileNames(final String prefix) {
        return gridMapDirectory.list(new FilenameFilter() {
            public boolean accept(File dir, String name) {
                Matcher nameMatcher = poolAccountNamePattern.matcher(name);
                if (nameMatcher.matches()) {
                    // BUG FIX: https://savannah.cern.ch/bugs/?66574
                    if (prefix == null || prefix.equals(nameMatcher.group(1))) {
                        return true;
                    }
                }
                return false;
            }
        });
    }
}
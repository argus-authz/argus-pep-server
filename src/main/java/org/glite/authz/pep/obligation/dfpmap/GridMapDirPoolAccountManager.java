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
import java.util.BitSet;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.httpclient.URIException;
import org.apache.commons.httpclient.util.URIUtil;
import org.glite.authz.common.util.Strings;
import org.glite.authz.pep.obligation.ObligationProcessingException;
import org.jruby.ext.posix.FileStat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.emi.security.authn.x509.impl.OpensslNameUtils;

/**
 * A {@link PoolAccountManager} implementation that uses the filesystem as a
 * persistence mechanism.
 * 
 * The mapping directory must be prepopulated with files whose names represent
 * every pool account to be managed.
 */
public class GridMapDirPoolAccountManager implements PoolAccountManager {

    /** Class logger. */
    private Logger log= LoggerFactory.getLogger(GridMapDirPoolAccountManager.class);

    /** Directory containing the grid mappings. */
    private final File gridMapDirectory_;

    /**
     * Determine the lease filename should contains the secondary group names or
     * not.
     * <p>
     * Bug fix: https://savannah.cern.ch/bugs/?83317
     * 
     * @see GridMapDirPoolAccountManager#buildSubjectIdentifier(X500Principal,
     *      String, List)
     */
    private boolean useSecondaryGroupNamesForMapping_= true;

    /**
     * Regexp pattern used to identify pool account names.
     * <p>
     * Contains a single group match whose value is the pool account name
     * prefix.
     * <ul>
     * <li>Bug fix: https://savannah.cern.ch/bugs/?66574
     * <li>Bug fix: https://savannah.cern.ch/bugs/?80526
     * </ul>
     */
    private final Pattern poolAccountNamePattern_= Pattern.compile("^([a-zA-Z][a-zA-Z0-9._-]*?)[0-9]++$");

    /**
     * Constructor.
     * 
     * @param gridMapDir
     *            existing, readable, and writable directory where grid mappings
     *            will be recorded
     * @param useSecondaryGroupNamesForMapping
     *            if the lease filename in the gridmapDir should contains
     *            secondary group names or not
     */
    public GridMapDirPoolAccountManager(File gridMapDir,
                                        boolean useSecondaryGroupNamesForMapping) {
        if (!gridMapDir.exists()) {
            throw new IllegalArgumentException("Grid map directory "
                    + gridMapDir.getAbsolutePath() + " does not exist");
        }

        if (!gridMapDir.canRead()) {
            throw new IllegalArgumentException("Grid map directory "
                    + gridMapDir.getAbsolutePath()
                    + " is not readable by this process");
        }

        if (!gridMapDir.canWrite()) {
            throw new IllegalArgumentException("Grid map directory "
                    + gridMapDir.getAbsolutePath()
                    + " is not writable by this process");
        }

        gridMapDirectory_= gridMapDir;
        useSecondaryGroupNamesForMapping_= useSecondaryGroupNamesForMapping;
    }

    /** {@inheritDoc} */
    public List<String> getPoolAccountNamePrefixes() {
        ArrayList<String> poolAccountNames= new ArrayList<String>();

        Matcher nameMatcher;
        File[] files= gridMapDirectory_.listFiles();
        for (File file : files) {
            if (file.isFile()) {
                nameMatcher= poolAccountNamePattern_.matcher(file.getName());
                if (nameMatcher.matches()
                        && !poolAccountNames.contains(nameMatcher.group(1))) {
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

    /**
     * {@inheritDoc}
     * <ul>
     * <li>BUG FIX: https://savannah.cern.ch/bugs/index.php?83281
     * <li>BUG FIX: https://savannah.cern.ch/bugs/index.php?84846
     * </ul>
     * */
    public String mapToAccount(String accountNamePrefix,
                               X500Principal subjectDN, String primaryGroup,
                               List<String> secondaryGroups)
            throws ObligationProcessingException {
        String subjectIdentifier= buildSubjectIdentifier(subjectDN, primaryGroup, secondaryGroups);
        File subjectIdentifierFile= new File(buildSubjectIdentifierFilePath(subjectIdentifier));

        log.debug("Checking if there is an existing account mapping for subject {} with primary group {} and secondary groups {}", new Object[] {
                subjectDN.getName(), primaryGroup, secondaryGroups });
        String accountName= getExistingMapping(accountNamePrefix, subjectIdentifier);
        if (accountName != null) {
            // BUG FIX: https://savannah.cern.ch/bugs/index.php?83281
            // touch the subjectIdentifierFile every time a mapping is re-done.
            PosixUtil.touchFile(subjectIdentifierFile);

            log.debug("An existing account mapping has mapped subject {} with primary group {} and secondary groups {} to pool account {}", new Object[] {
                    subjectDN.getName(), primaryGroup, secondaryGroups,
                    accountName });
            return accountName;
        }

        accountName= createMapping(accountNamePrefix, subjectIdentifier);
        if (accountName != null) {
            // BUG FIX: https://savannah.cern.ch/bugs/index.php?84846
            // touch the subjectIdentifierFile the first time a mapping is done.
            PosixUtil.touchFile(subjectIdentifierFile);
            log.debug("A new account mapping has mapped subject {} with primary group {} and secondary groups {} to pool account {}", new Object[] {
                    subjectDN.getName(), primaryGroup, secondaryGroups,
                    accountName });
        }
        else {
            log.debug("No pool account was available to which subject {} with primary group {} and secondary groups {} could be mapped", new Object[] {
                    subjectDN.getName(), primaryGroup, secondaryGroups });
        }
        return accountName;
    }

    /**
     * Gets the user account to which a given subject had previously been
     * mapped.
     * 
     * @param accountNamePrefix
     *            prefix of the account to which the subject should be mapped
     * @param subjectIdentifier
     *            key identifying the subject
     * 
     * @return account to which the subject was mapped or <code>null</code> if not mapping
     *         currently exists
     * 
     * @throws ObligationProcessingException
     *             thrown if the link count on the pool account file or the
     *             subject identifier file is different than 2
     */
    private String getExistingMapping(String accountNamePrefix,
                                       String subjectIdentifier)
            throws ObligationProcessingException {
        File subjectIdentifierFile= new File(buildSubjectIdentifierFilePath(subjectIdentifier));
        // the file doesn't exit yet!!!
        if (!subjectIdentifierFile.exists()) {
            return null;
        }

        // if the file exists, it is already mapped and the link count MUST be 2!
        FileStat subjectIdentifierFileStat= PosixUtil.getFileStat(subjectIdentifierFile.getAbsolutePath());
        if (log.isDebugEnabled()) {
            log.debug("Subject identifier file: {} inode: {} nlink: {}", new Object[] { subjectIdentifierFile.getAbsolutePath(), subjectIdentifierFileStat.ino(), subjectIdentifierFileStat.nlink()});
        }
        if (subjectIdentifierFileStat.nlink() != 2) {
            log.error("The subject identifier file {} has a link count different than 2 [inode: {} nlink: {}]: This mapping is corrupted and can not be used", new Object[] { subjectIdentifierFile.getAbsolutePath(), subjectIdentifierFileStat.ino(), subjectIdentifierFileStat.nlink()});
            throw new ObligationProcessingException("Unable to map subject to a POSIX account: Corrupted subject identifier file link count");
        }

        // search the matching (same inode#) pool account file
        for (File accountFile : getAccountFiles(accountNamePrefix)) {
            FileStat accountFileStat= PosixUtil.getFileStat(accountFile.getAbsolutePath());
            if (accountFileStat.ino() == subjectIdentifierFileStat.ino()) {
                if (log.isDebugEnabled()) {
                    log.debug("Pool account file: {} inode: {} nlink: {}", new Object[] { accountFile.getAbsolutePath(), subjectIdentifierFileStat.ino(), subjectIdentifierFileStat.nlink()});
                }
                if (accountFileStat.nlink() != 2) {
                    log.error("The pool account file {} has a link count different than 2 [inode: {} nlink: {}]: This mapping is corrupted and should not be used", new Object[] { accountFile.getAbsolutePath(), accountFileStat.ino(), accountFileStat.nlink() });
                    throw new ObligationProcessingException("Unable to map subject to a POSIX account: Corrupted pool account file link count");
                }

                return accountFile.getName();
            }
        }

        return null;
    }

    /**
     * Creates a mapping between an account and a subject identified by the
     * account key.
     * 
     * @param accountNamePrefix
     *            prefix of the pool account names
     * @param subjectIdentifier
     *            key identifying the subject mapped to the account
     * 
     * @return the account to which the subject was mapped or null if not
     *         account was available
     */
    protected String createMapping(String accountNamePrefix,
                                   String subjectIdentifier) {
        for (File accountFile : getAccountFiles(accountNamePrefix)) {
            log.debug("Checking if grid map account {} may be linked to subject identifier {}", accountFile.getName(), subjectIdentifier);
            String subjectIdentifierFilePath= buildSubjectIdentifierFilePath(subjectIdentifier);
            FileStat accountFileStat= PosixUtil.getFileStat(accountFile.getAbsolutePath());
            if (accountFileStat.nlink() == 1) {
                PosixUtil.createHardlink(accountFile.getAbsolutePath(), subjectIdentifierFilePath);
                accountFileStat= PosixUtil.getFileStat(accountFile.getAbsolutePath());
                if (accountFileStat.nlink() == 2) {
                    log.debug("Linked subject identifier {} to pool account file {}", subjectIdentifier, accountFile.getName());
                    return accountFile.getName();
                }
                new File(subjectIdentifierFilePath).delete();
            }
            log.debug("Could not map to account {}", accountFile.getName());
        }
        log.error("{} pool account is full. Impossible to map {}", accountNamePrefix, subjectIdentifier);
        return null;
    }

    /**
     * Creates an identifier (lease filename) for the subject that is based on
     * the subject's DN and primary and secondary groups. The secondary groups
     * are only included in the identifier if the
     * {@link #useSecondaryGroupNamesForMapping_} is <code>true</code>.
     * <p>
     * Implements the legacy gLExec LCAS/LCMAP lease filename encoding.
     * <ul>
     * <li>BUG FIX: https://savannah.cern.ch/bugs/index.php?83419
     * <li>Bug fix: https://savannah.cern.ch/bugs/?83317
     * </ul>
     * 
     * @param subjectDN
     *            DN of the subject
     * @param primaryGroupName
     *            primary group to which the subject was assigned, may be null
     * @param secondaryGroupNames
     *            ordered list of secondary groups to which the subject
     *            assigned, may be null
     * 
     * @return the identifier for the subject
     */
    protected String buildSubjectIdentifier(X500Principal subjectDN,
                                            String primaryGroupName,
                                            List<String> secondaryGroupNames) {
        StringBuilder identifier= new StringBuilder();

        try {
            String rfc2253Subject= subjectDN.getName();
            String openSSLSubject= OpensslNameUtils.convertFromRfc2253(rfc2253Subject, false);

            // BUG FIX: https://savannah.cern.ch/bugs/index.php?83419
            // encode using the legacy gLExec LCAS/LCMAP algorithm
            String encodedId= encodeSubjectIdentifier(openSSLSubject);
            identifier.append(encodedId);
        } catch (URIException e) {
            throw new RuntimeException("Charset required to be supported by JVM but is not available", e);
        }

        if (primaryGroupName != null) {
            identifier.append(":").append(primaryGroupName);
        }

        // BUG FIX: https://savannah.cern.ch/bugs/?83317
        // use or not secondary groups in lease filename
        if (useSecondaryGroupNamesForMapping_ && secondaryGroupNames != null
                && !secondaryGroupNames.isEmpty()) {
            for (String secondaryGroupName : secondaryGroupNames) {
                identifier.append(":").append(secondaryGroupName);
            }
        }

        return identifier.toString();
    }

    /**
     * Alpha numeric characters set: <code>[0-9a-zA-Z]</code>
     */
    protected static final BitSet ALPHANUM= new BitSet(256);
    // Static initializer for alphanum
    static {
        for (int i= 'a'; i <= 'z'; i++) {
            ALPHANUM.set(i);
        }
        for (int i= 'A'; i <= 'Z'; i++) {
            ALPHANUM.set(i);
        }
        for (int i= '0'; i <= '9'; i++) {
            ALPHANUM.set(i);
        }
    }

    /**
     * Encodes the unescaped subject identifier, typically the user DN.
     * <p>
     * Implements the legacy string encoding used by gLExec LCAS/LCMAP for the
     * lease file names:
     * <ul>
     * <li>URL encode all no alpha-numeric characters <code>[0-9a-zA-Z]</code>
     * <li>apply lower case
     * </ul>
     * 
     * @param unescaped
     *            The unescaped user DN
     * @return encoded, escaped, user DN, compatible with gLExec
     * @throws URIException
     */
    protected String encodeSubjectIdentifier(String unescaped)
            throws URIException {
        String encoded= URIUtil.encode(unescaped, ALPHANUM);
        return encoded.toLowerCase();
    }

    /**
     * Builds the absolute path to the subject identifier file.
     * 
     * @param subjectIdentifier
     *            the subject identifier
     * 
     * @return the absolute path to the subject identifier file
     */
    protected String buildSubjectIdentifierFilePath(String subjectIdentifier) {
        return gridMapDirectory_.getAbsolutePath() + File.separator
                + subjectIdentifier;
    }

    /**
     * Gets a list of account files where the file names begin with the given
     * prefix.
     * <ul>
     * <li>BUG FIX: https://savannah.cern.ch/bugs/?66574
     * </ul>
     * 
     * @param prefix
     *            prefix with which the file names should begin, may be null to
     *            signify all file names
     * 
     * @return the selected account files
     */
    private File[] getAccountFiles(final String prefix) {
        return gridMapDirectory_.listFiles(new FilenameFilter() {
            public boolean accept(File dir, String name) {
                Matcher nameMatcher= poolAccountNamePattern_.matcher(name);
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
     * Gets a list of account file names where the names begin with the given
     * prefix.
     * <ul>
     * <li>BUG FIX: https://savannah.cern.ch/bugs/?66574
     * </ul>
     * 
     * @param prefix
     *            prefix with which the file names should begin, may be null to
     *            signify all file names
     * 
     * @return the selected account file names
     */
    private String[] getAccountFileNames(final String prefix) {
        return gridMapDirectory_.list(new FilenameFilter() {
            public boolean accept(File dir, String name) {
                Matcher nameMatcher= poolAccountNamePattern_.matcher(name);
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
     * @param useSecondaryGroupNamesForMapping
     *            the useSecondaryGroupNamesForMapping_ to set
     */
    protected void setUseSecondaryGroupNamesForMapping(boolean useSecondaryGroupNamesForMapping) {
        this.useSecondaryGroupNamesForMapping_= useSecondaryGroupNamesForMapping;
    }

}

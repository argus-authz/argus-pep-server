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
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
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
    private Logger log = LoggerFactory.getLogger(GridMapDirPoolAccountManager.class);

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
    private boolean useSecondaryGroupNamesForMapping_ = true;

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
    private final Pattern poolAccountNamePattern_ = Pattern.compile("^([a-zA-Z][a-zA-Z0-9._-]*?)[0-9]++$");

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
    public GridMapDirPoolAccountManager(final File gridMapDir, final boolean useSecondaryGroupNamesForMapping) {
	if (!gridMapDir.exists()) {
	    throw new IllegalArgumentException(
		    "Grid map directory " + gridMapDir.getAbsolutePath() + " does not exist");
	}

	if (!gridMapDir.canRead()) {
	    throw new IllegalArgumentException(
		    "Grid map directory " + gridMapDir.getAbsolutePath() + " is not readable by this process");
	}

	if (!gridMapDir.canWrite()) {
	    throw new IllegalArgumentException(
		    "Grid map directory " + gridMapDir.getAbsolutePath() + " is not writable by this process");
	}

	gridMapDirectory_ = gridMapDir;
	useSecondaryGroupNamesForMapping_ = useSecondaryGroupNamesForMapping;
    }

    /** {@inheritDoc} */
    public List<String> getPoolAccountNamePrefixes() {
	ArrayList<String> poolAccountNames = new ArrayList<String>();

	Matcher nameMatcher;
	File[] files = gridMapDirectory_.listFiles();
	for (File file : files) {
	    if (file.isFile()) {
		nameMatcher = poolAccountNamePattern_.matcher(file.getName());
		if (nameMatcher.matches() && !poolAccountNames.contains(nameMatcher.group(1))) {
		    poolAccountNames.add(nameMatcher.group(1));
		}
	    }
	}

	return poolAccountNames;
    }

    public List<String> getPoolAccountNames() {
	return Arrays.asList(getAccountFileNames(null));
    }

    public List<String> getPoolAccountNames(final String prefix) {
	return Arrays.asList(getAccountFileNames(Strings.safeTrimOrNullString(prefix)));
    }

    public boolean isPoolAccountPrefix(final String accountIndicator) {
	return accountIndicator.startsWith(".");
    }

    public String getPoolAccountPrefix(final String accountIndicator) {
	if (isPoolAccountPrefix(accountIndicator)) {
	    return accountIndicator.substring(1);
	}
	return null;
    }

    /***
     * @param accountNamePrefix
     *            Posix account name prefix.
     * @param subjectDN
     *            User's subject DN.
     * @param primaryGroup
     *            User's primary group.
     * @param secondaryGroups
     *            List of user's secondary groups.
     * @throws ObligationProcessingException
     *             Raised if mapping fail.
     * @return The Posix account if the operation end successfully,
     *         <code>null</code> otherwise.
     */
    public String mapToAccount(final String accountNamePrefix, final X500Principal subjectDN, final String primaryGroup,
	    final List<String> secondaryGroups) throws ObligationProcessingException {

	String subjectIdentifier = buildSubjectIdentifier(subjectDN, primaryGroup, secondaryGroups);
	File subjectIdentifierFile = new File(buildSubjectIdentifierFilePath(subjectIdentifier));
	String accountName = null;

	try {
	    log.debug(
		    "mapToAccount: Checking if there is an existing account mapping for subject {} with primary group {} and secondary groups {}",
		    subjectDN.getName(), primaryGroup, secondaryGroups);

	    if (!subjectIdentifierFile.exists()) {
		accountName = createMapping(accountNamePrefix, subjectIdentifier);
	    }

	    if (accountName == null) {
		accountName = getExistingMapping(accountNamePrefix, subjectIdentifier);
	    }

	    if (accountName != null) {
		PosixUtil.touchFile(subjectIdentifierFile);
		log.debug(
			"mapToAccount: Account mapped subject {} with primary group {} and secondary groups {} to pool account {}",
			subjectDN.getName(), primaryGroup, secondaryGroups, accountName);
	    } else {
		log.debug(
			"mapToAccount: No pool account was available to which subject {} with primary group {} and secondary groups {} could be mapped",
			subjectDN.getName(), primaryGroup, secondaryGroups);
	    }
	} catch (Exception e) {
	    String lMessage = "mapToAccount: Error managing account mapping";
	    log.error(lMessage, e);
	    throw new ObligationProcessingException(e);
	}

	return accountName;
    }

    /***
     * Get account of name of already mapped subject DN.
     * 
     * @param pAccountNamePrefix
     *            Posix account prefix.
     * @param pSubjectIdentifier
     *            User subject DN
     * @return Posix account name
     * @throws ObligationProcessingException
     *             Raised if the mapping is corrupted.
     */
    protected String getExistingMapping(final String pAccountNamePrefix, final String pSubjectIdentifier)
	    throws ObligationProcessingException {

	File subjectIdentifierFile = new File(buildSubjectIdentifierFilePath(pSubjectIdentifier));
	long lThreadId = Thread.currentThread().getId();
	String lAccountName = null;

	FileStat subjectIdentifierFileStat = PosixUtil.getFileStat(subjectIdentifierFile.getAbsolutePath());
	int lNumLink = subjectIdentifierFileStat.nlink();

	if (lNumLink < 2) {
	    log.error(
		    "getMapping: The subject identifier file {} has a link count different than 2 [inode: {} nlink: {} thread-id: {}]: This mapping is corrupted and can not be used",
		    subjectIdentifierFile.getAbsolutePath(), subjectIdentifierFileStat.ino(),
		    subjectIdentifierFileStat.nlink(), lThreadId);
	    throw new ObligationProcessingException(
		    "Unable to map subject to a POSIX account: Corrupted subject identifier file link count");
	}

	// search the matching (same inode#) pool account file
	for (File accountFile : getAccountFiles(pAccountNamePrefix)) {
	    FileStat accountFileStat = PosixUtil.getFileStat(accountFile.getAbsolutePath());
	    long lAccountFileINo = accountFileStat.ino();
	    long lSubjectIdentifierFileINo = subjectIdentifierFileStat.ino();
	    if (lAccountFileINo == lSubjectIdentifierFileINo) {
		if (log.isDebugEnabled()) {
		    log.debug("Pool account file: {} inode: {} nlink: {}", accountFile.getAbsolutePath(),
			    lSubjectIdentifierFileINo, subjectIdentifierFileStat.nlink());
		}
		if (accountFileStat.nlink() != 2) {
		    log.error(
			    "getMapping: The pool account file {} has a link count different than 2 [inode: {} nlink: {} thread-id: {}]: This mapping is corrupted and can not be used",
			    accountFile.getAbsolutePath(), lAccountFileINo, accountFileStat.nlink(), lThreadId);
		    throw new ObligationProcessingException(
			    "Unable to map subject to a POSIX account: Corrupted pool account file link count");
		}

		lAccountName = accountFile.getName();
		break;
	    }
	}
	return lAccountName;
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
    protected synchronized String createMapping(final String pAccountNamePrefix, final String pSubjectIdentifier) {

	String lLockFileName = String.format(".lock_%s", pSubjectIdentifier);
	File lLockFile = new File(gridMapDirectory_.getAbsolutePath(), lLockFileName);
	Long lThreadId = Thread.currentThread().getId();

	RandomAccessFile lFile = null;
	FileChannel lFileChannel = null;
	FileLock lLock = null;
	String lAccountName = null;

	try {
	    lFile = new RandomAccessFile(lLockFile, "rw");
	    lFileChannel = lFile.getChannel();
	    lLock = lFileChannel.lock();

	    String subjectIdentifierFilePath = buildSubjectIdentifierFilePath(pSubjectIdentifier);
	    File lSubjectFile = new File(subjectIdentifierFilePath);

	    if (!lSubjectFile.exists()) {

		for (File accountFile : getAccountFiles(pAccountNamePrefix)) {
		    log.debug("Checking if grid map account {} may be linked to subject identifier {}",
			    accountFile.getName(), pSubjectIdentifier);

		    FileStat accountFileStat = PosixUtil.getFileStat(accountFile.getAbsolutePath());
		    if (accountFileStat.nlink() == 1) {
			PosixUtil.createHardlink(accountFile.getAbsolutePath(), subjectIdentifierFilePath);
			accountFileStat = PosixUtil.getFileStat(accountFile.getAbsolutePath());
			if (accountFileStat.nlink() == 2) {
			    lAccountName = accountFile.getName();
			    log.debug("Linked subject identifier {} to pool account file {}", pSubjectIdentifier,
				    lAccountName);
			    break;
			}
			if (PosixUtil.getFileStat(subjectIdentifierFilePath).nlink() < 2) {
			    new File(subjectIdentifierFilePath).delete();
			}
		    }
		    log.debug("Could not map to account {}", accountFile.getName());
		}
		if (lAccountName == null) {
		    log.error("createMapping: {} pool account is full. Impossible to map {} [thread-id: {}]",
			    pAccountNamePrefix, pSubjectIdentifier, lThreadId);
		}
	    } else {
		if (PosixUtil.getFileStat(subjectIdentifierFilePath).nlink() < 2) {
		    new File(subjectIdentifierFilePath).delete();
		}
	    }
	} catch (Throwable t) {
	    log.error("createMapping: error creating mapping [thread-id: {}]", lThreadId);
	    lAccountName = null;
	} finally {
	    if (lLock != null) {
		try {
		    lLock.release();
		} catch (IOException e) {
		}
	    }
	    if (lFile != null) {
		try {
		    lFile.close();
		} catch (IOException e) {
		}
	    }
	    if (lLockFile != null) {
		lLockFile.delete();
	    }
	}

	return lAccountName;
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
    protected String buildSubjectIdentifier(final X500Principal subjectDN, final String primaryGroupName,
	    final List<String> secondaryGroupNames) {
	StringBuilder identifier = new StringBuilder();

	try {
	    String rfc2253Subject = subjectDN.getName();
	    String openSSLSubject = OpensslNameUtils.convertFromRfc2253(rfc2253Subject, false);

	    // BUG FIX: https://savannah.cern.ch/bugs/index.php?83419
	    // encode using the legacy gLExec LCAS/LCMAP algorithm
	    String encodedId = encodeSubjectIdentifier(openSSLSubject);
	    identifier.append(encodedId);
	} catch (URIException e) {
	    throw new RuntimeException("Charset required to be supported by JVM but is not available", e);
	}

	if (primaryGroupName != null) {
	    identifier.append(":").append(primaryGroupName);
	}

	// BUG FIX: https://savannah.cern.ch/bugs/?83317
	// use or not secondary groups in lease filename
	if (useSecondaryGroupNamesForMapping_ && secondaryGroupNames != null && !secondaryGroupNames.isEmpty()) {
	    for (String secondaryGroupName : secondaryGroupNames) {
		identifier.append(":").append(secondaryGroupName);
	    }
	}

	return identifier.toString();
    }

    /**
     * Alpha numeric characters set: <code>[0-9a-zA-Z]</code>
     */
    protected static final BitSet ALPHANUM = new BitSet(256);

    // Static initializer for alphanum
    static {
	for (int i = 'a'; i <= 'z'; i++) {
	    ALPHANUM.set(i);
	}
	for (int i = 'A'; i <= 'Z'; i++) {
	    ALPHANUM.set(i);
	}
	for (int i = '0'; i <= '9'; i++) {
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
     *             in case of URI encoding errors
     */
    protected String encodeSubjectIdentifier(final String unescaped) throws URIException {
	String encoded = URIUtil.encode(unescaped, ALPHANUM);
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
    protected String buildSubjectIdentifierFilePath(final String subjectIdentifier) {
	return gridMapDirectory_.getAbsolutePath() + File.separator + subjectIdentifier;
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
	    public boolean accept(final File dir, final String name) {
		Matcher nameMatcher = poolAccountNamePattern_.matcher(name);
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
	    public boolean accept(final File dir, final String name) {
		Matcher nameMatcher = poolAccountNamePattern_.matcher(name);
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
    protected void setUseSecondaryGroupNamesForMapping(final boolean useSecondaryGroupNamesForMapping) {
	this.useSecondaryGroupNamesForMapping_ = useSecondaryGroupNamesForMapping;
    }

}

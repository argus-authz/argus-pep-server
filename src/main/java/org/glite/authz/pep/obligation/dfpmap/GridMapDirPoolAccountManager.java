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
import java.io.FileNotFoundException;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.httpclient.URIException;
import org.apache.commons.httpclient.util.URIUtil;
import org.glite.authz.common.util.Strings;
import org.glite.authz.pep.obligation.ObligationProcessingException;
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

  public enum MappingResult {
    SUCCESS,
    INDETERMINATE,
    LINK_ERROR,
    POOL_ACCOUNT_BUSY
  }

  /** Class logger. */
  private Logger log = LoggerFactory
    .getLogger(GridMapDirPoolAccountManager.class);

  private final Random random = new Random();

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
   * Contains a single group match whose value is the pool account name prefix.
   * <ul>
   * <li>Bug fix: https://savannah.cern.ch/bugs/?66574
   * <li>Bug fix: https://savannah.cern.ch/bugs/?80526
   * </ul>
   */
  private final Pattern poolAccountNamePattern_ = Pattern
    .compile("^([a-zA-Z][a-zA-Z0-9._-]*?)[0-9]++$");

  /**
   * Constructor.
   * 
   * @param gridMapDir
   *          existing, readable, and writable directory where grid mappings
   *          will be recorded
   * @param useSecondaryGroupNamesForMapping
   *          if the lease filename in the gridmapDir should contains secondary
   *          group names or not
   */
  public GridMapDirPoolAccountManager(final File gridMapDir,
    final boolean useSecondaryGroupNamesForMapping) {
    if (!gridMapDir.exists()) {
      throw new IllegalArgumentException("Grid map directory "
        + gridMapDir.getAbsolutePath() + " does not exist");
    }

    if (!gridMapDir.canRead()) {
      throw new IllegalArgumentException("Grid map directory "
        + gridMapDir.getAbsolutePath() + " is not readable by this process");
    }

    if (!gridMapDir.canWrite()) {
      throw new IllegalArgumentException("Grid map directory "
        + gridMapDir.getAbsolutePath() + " is not writable by this process");
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
        if (nameMatcher.matches()
          && !poolAccountNames.contains(nameMatcher.group(1))) {
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

    return Arrays
      .asList(getAccountFileNames(Strings.safeTrimOrNullString(prefix)));
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
   *          Posix account name prefix.
   * @param subjectDN
   *          User's subject DN.
   * @param primaryGroup
   *          User's primary group.
   * @param secondaryGroups
   *          List of user's secondary groups.
   * @throws ObligationProcessingException
   *           Raised if mapping fail.
   * @return The Posix account if the operation end successfully,
   *         <code>null</code> otherwise.
   */
  public String mapToAccount(final String accountNamePrefix,
    final X500Principal subjectDN, final String primaryGroup,
    final List<String> secondaryGroups) throws ObligationProcessingException {

    String subjectIdentifier = buildSubjectIdentifier(subjectDN, primaryGroup,
      secondaryGroups);

    File subjectIdentifierFile = new File(
      buildSubjectIdentifierFilePath(subjectIdentifier));

    String accountName = null;

    try {

      log.debug(
        "Checking if there is an existing account mapping for subject {} with primary group {} and secondary groups {}",
        subjectDN.getName(), primaryGroup, secondaryGroups);

      if (!subjectIdentifierFile.exists()) {

        accountName = createMapping(accountNamePrefix, subjectIdentifier);

      } else {

        accountName = getExistingMapping(accountNamePrefix, subjectIdentifier);

      }

      if (accountName == null) {
        
        log.debug(
          "No pool account was available to which subject {} with primary group {} and secondary groups {} could be mapped",
          subjectDN.getName(), primaryGroup, secondaryGroups);
        
      } else {
        PosixUtil.touchFile(subjectIdentifierFile);
        log.debug(
          "Mapped subject {} with primary group {} and secondary groups {} to pool account {}",
          subjectDN.getName(), primaryGroup, secondaryGroups, accountName);
      }

    } catch (Exception e) {

      String msg = String.format("Error mapping account: %s", e.getMessage());
      log.error(msg, e);
      
      throw new ObligationProcessingException(e);
    }

    return accountName;
  }

  /***
   * Get account of name of already mapped subject DN.
   * 
   * @param accountNamePrefix
   *          Posix account prefix.
   * @param subjectIdentifier
   *          User subject DN
   * @return Posix account name
   * @throws ObligationProcessingException
   *           Raised if the mapping is corrupted.
   */
  protected String getExistingMapping(final String accountNamePrefix,
    final String subjectIdentifier) throws ObligationProcessingException {

    File subjectIdentifierFile = new File(
      buildSubjectIdentifierFilePath(subjectIdentifier));

    UnixFile subjectIdFile = UnixFile.from(subjectIdentifierFile);

    if (subjectIdFile.nlink() < 2) {

      log.error(
        "The subject identifier file {} has link count 1. This mapping is corrupted, cleaning it up.",
        subjectIdFile.getAbsolutePath());

      subjectIdFile.delete();

      throw new ObligationProcessingException(
        "Unable to map subject to a POSIX account: subject identifier file link count == 1");

    }

    UnixFile accountFile = lookupPoolAccountLinkedToSubject(accountNamePrefix,
      subjectIdFile);

    if (accountFile == null) {
      log.debug("No mapping found for subject {}", subjectIdentifier);
      return null;
    }

    if (accountFile.nlink() != 2) {
      log.error(
        "Pool account file {} has link count != 2 ! [inode: {}, nlink: {}]: This mapping is corrupted.",
        accountFile.getName(), accountFile.ino(), accountFile.nlink());
      throw new ObligationProcessingException(
        "Unable to map subject to a POSIX account: Corrupted pool account file link count == "
          + accountFile.nlink());
    }

    return accountFile.getName();

  }

  /**
   * Returns the first account file in a pool account whose inode is equal to
   * the subjectfile
   * 
   * @param accountNamePrefix
   *          the pool account name prefix
   * @param subjectFile
   *          the subject file
   * @return a {@link UnixFile} for the pool account whose inode matches,
   *         <code>null</code> if no account is found or the file passed as
   *         argument does not exist
   */
  private UnixFile lookupPoolAccountLinkedToSubject(String accountNamePrefix,
    UnixFile subjectFile) {

    if (!subjectFile.exists()) {
      return null;
    }

    for (File accountFile : getAccountFiles(accountNamePrefix)) {

      UnixFile accountUnixFile = UnixFile.from(accountFile);

      if (accountUnixFile.inodeEquals(subjectFile)) {
        return accountUnixFile;
      }
    }

    return null;
  }

  /**
   * Creates a mapping between a subject identifier and a pool account file.
   * 
   * It relies on {@link PosixUtil#createHardlink(String, String)}
   * 
   * @param subjectIdentifier
   *          the subject identifier
   * @param accountFile
   *          the pool account file
   * @param subjectFile
   *          the file created from the subject identifier
   * 
   * @return a {@link MappingResult} telling the outcome of the linking
   *         operation
   */
  private MappingResult linkSubjectToPoolAccount(String subjectIdentifier,
    UnixFile accountFile, UnixFile subjectFile) {

    log.debug("Linking {} -> {}", accountFile.getName(), subjectIdentifier);

    int retval = PosixUtil.createHardlink(accountFile.getFile(), subjectFile.getFile());

    if (retval != 0) {

      if (retval == Errno.EEXIST.value) {

        log.debug(
          "Subject identifier file {} already exists. "
            + "Check if is bound to pool account {}",
          subjectIdentifier, accountFile.getName());

        subjectFile.stat();

        if (subjectFile.inodeEquals(accountFile)) {
          log.debug("Pool account {} already bound to subject {}",
            accountFile.getName(), subjectIdentifier);

          return MappingResult.SUCCESS;
        }

        log.debug(
          "Pool account {} bound to different subject identifier. Backing off");
        return MappingResult.POOL_ACCOUNT_BUSY;
      }

      log.error("Link error while creating mapping {} -> {}: error code {}.",
        accountFile.getName(), subjectIdentifier, retval);

      return MappingResult.LINK_ERROR;

    } else { // retval == 0, hardlink creation successful

      accountFile.stat();

      if (accountFile.nlink() == 2) {

        log.debug("Mapping CREATED: {} -> {}", accountFile.getName(),
          subjectIdentifier);

        return MappingResult.SUCCESS;
      }

      if (accountFile.nlink() > 2) {

        log.debug("NLINK == {}! Removing just created link {} -> {}",
          accountFile.nlink(), accountFile.getName(), subjectIdentifier);

        subjectFile.delete();

        return MappingResult.POOL_ACCOUNT_BUSY;
      }

      // Should never happen
      return MappingResult.INDETERMINATE;
    }

  }

  /**
   * Returns a random integer between a specified range
   * 
   * @param lowerBound
   *          the range lower bound
   * @param upperBound
   *          the range upper bound
   * 
   * @return the random integer
   */
  private long getRandomInteger(int lowerBound, int upperBound) {

    int sleepTime = random.nextInt((upperBound - lowerBound) + 1) + lowerBound;
    return (long) sleepTime;

  }

  /**
   * Acquires a lock on a pool account file. This method will cycle and sleep
   * until a lock is acquired on a pool account file.
   * 
   * @param lockFile
   *          the lock file linked to the pool account file
   * @param accountFile
   *          the pool account file
   * @return the acquired lock
   */
  private FileLock acquireLock(RandomAccessFile lockFile, File accountFile) {

    // The following times are in msecs
    final int SLEEP_TIME_LOWER_BOUND = 10;
    final int SLEEP_TIME_UPPER_BOUND = 100;

    FileLock lock = null;

    do {
      try {

        lock = lockFile.getChannel().tryLock();

      } catch (OverlappingFileLockException e) {
        // This is normal when multiple threads in the same JVM
        // compete for a lock
      } catch (IOException e) {

        log.error("Error acquiring lock", e);
        return null;

      }

      if (lock == null) {

        try {

          long randomSleepTime = getRandomInteger(SLEEP_TIME_LOWER_BOUND,
            SLEEP_TIME_UPPER_BOUND);

          log.debug("Failed to acquire lock on account {}, sleeping {} msecs",
            accountFile.getName(), randomSleepTime);

          Thread.sleep(randomSleepTime);

        } catch (InterruptedException e) {

        }
      }
    } while (lock == null);

    return lock;
  }

  /**
   * Creates a lock file for a given account file
   * 
   * @param accountFile
   *          the pool account file for which the lock is created
   * @return a {@link RandomAccessFile} lock file
   * 
   * @throws FileNotFoundException
   *           should never happen
   */
  private RandomAccessFile createLockFile(File accountFile)
    throws FileNotFoundException {

    File lockFileName = new File(gridMapDirectory_.getAbsolutePath(),
      String.format(".lock.%s", accountFile.getName()));

    return new RandomAccessFile(lockFileName, "rw");
  }

  /**
   * Creates a mapping between an account and a subject identified by the
   * account key.
   * 
   * @param accountNamePrefix
   *          prefix of the pool account names
   * @param subjectIdentifier
   *          key identifying the subject mapped to the account
   * 
   * @return the account to which the subject was mapped or null if not account
   *         was available
   * 
   */
  protected String createMapping(final String accountNamePrefix,
    final String subjectIdentifier) {

    String subjectIdentifierFilePath = buildSubjectIdentifierFilePath(
      subjectIdentifier);

    File subjectFile = new File(subjectIdentifierFilePath);

    FileLock lock = null;
    RandomAccessFile lockFile = null;

    try {

      for (File accountFile : getAccountFiles(accountNamePrefix)) {

        log.debug(
          "Checking if grid map account {} may be linked to subject identifier {}",
          accountFile.getName(), subjectIdentifier);

        lockFile = createLockFile(accountFile);

        if (lockFile == null) {
          log.error("Error creating lock file");
          return null;
        }

        lock = acquireLock(lockFile, accountFile);

        if (lock == null) {
          log.error("Error acquiring lock");
          return null;
        }

        if (subjectFile.exists()) {

          String existingMapping = null;

          try {
            existingMapping = getExistingMapping(accountNamePrefix,
              subjectIdentifier);
          } catch (ObligationProcessingException e) {
            log.error(
              "Error resolving existing mapping for subject identifier {}",
              subjectIdentifier, e);
          }

          return existingMapping;

        }

        UnixFile accountUnixFile = UnixFile.from(accountFile);

        if (accountUnixFile.nlink() >= 2) {
          lock.release();

          if (accountUnixFile.nlink() > 2) {
            log.warn("Pool account {} currently bound to more than one subject",
              accountUnixFile.getName());

          } else {
            log.debug("Pool account {} already allocated, moving on",
              accountFile.getName());
          }

          continue;
        }
        
        MappingResult result = linkSubjectToPoolAccount(subjectIdentifier,
          accountUnixFile, 
          UnixFile.from(subjectFile));

        switch (result) {

        case POOL_ACCOUNT_BUSY:
          log.error("Pool account {} busy. Backing off for subject {}",
            accountFile.getName(), subjectIdentifier);

          lock.release();
          continue;

        case SUCCESS:
          return accountFile.getName();

        case INDETERMINATE:
          log.error(
            "Indeterminate mapping result for subject {} and pool account {}",
            subjectIdentifier, accountFile.getName());
          return null;

        case LINK_ERROR:
          log.error("Error link subject {} to pool account {}",
            subjectIdentifier, accountFile.getName());
          return null;
        }
      }

      log.error(
        "Pool account {} fully allocated. Impossible to return a mapping for subject {}",
        accountNamePrefix, subjectIdentifier);
      return null;

    } catch (IOException e) {

      log.error("Error creating lock file: {}", e.getMessage(), e);
      return null;

    } finally {

      try {

        if (lockFile != null) {
          lockFile.close();
        }

        if (lock != null) {
          lock.release();
        }
      } catch (IOException e) {
      }
    }
  }

  /**
   * Creates an identifier (lease filename) for the subject that is based on the
   * subject's DN and primary and secondary groups. The secondary groups are
   * only included in the identifier if the
   * {@link #useSecondaryGroupNamesForMapping_} is <code>true</code>.
   * <p>
   * Implements the legacy gLExec LCAS/LCMAP lease filename encoding.
   * <ul>
   * <li>BUG FIX: https://savannah.cern.ch/bugs/index.php?83419
   * <li>Bug fix: https://savannah.cern.ch/bugs/?83317
   * </ul>
   * 
   * @param subjectDN
   *          DN of the subject
   * @param primaryGroupName
   *          primary group to which the subject was assigned, may be null
   * @param secondaryGroupNames
   *          ordered list of secondary groups to which the subject assigned,
   *          may be null
   * 
   * @return the identifier for the subject
   */
  protected String buildSubjectIdentifier(final X500Principal subjectDN,
    final String primaryGroupName, final List<String> secondaryGroupNames) {

    StringBuilder identifier = new StringBuilder();

    try {
      String rfc2253Subject = subjectDN.getName();
      String openSSLSubject = OpensslNameUtils
        .convertFromRfc2253(rfc2253Subject, false);

      // BUG FIX: https://savannah.cern.ch/bugs/index.php?83419
      // encode using the legacy gLExec LCAS/LCMAP algorithm
      String encodedId = encodeSubjectIdentifier(openSSLSubject);
      identifier.append(encodedId);
    } catch (URIException e) {
      throw new RuntimeException(
        "Charset required to be supported by JVM but is not available", e);
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
   *          The unescaped user DN
   * @return encoded, escaped, user DN, compatible with gLExec
   * @throws URIException
   *           in case of URI encoding errors
   */
  protected String encodeSubjectIdentifier(final String unescaped)
    throws URIException {

    String encoded = URIUtil.encode(unescaped, ALPHANUM);
    return encoded.toLowerCase();
  }

  /**
   * Builds the absolute path to the subject identifier file.
   * 
   * @param subjectIdentifier
   *          the subject identifier
   * 
   * @return the absolute path to the subject identifier file
   */
  protected String buildSubjectIdentifierFilePath(
    final String subjectIdentifier) {

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
   *          prefix with which the file names should begin, may be null to
   *          signify all file names
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
   *          prefix with which the file names should begin, may be null to
   *          signify all file names
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
   *          the useSecondaryGroupNamesForMapping_ to set
   */
  protected void setUseSecondaryGroupNamesForMapping(
    final boolean useSecondaryGroupNamesForMapping) {

    this.useSecondaryGroupNamesForMapping_ = useSecondaryGroupNamesForMapping;
  }

}

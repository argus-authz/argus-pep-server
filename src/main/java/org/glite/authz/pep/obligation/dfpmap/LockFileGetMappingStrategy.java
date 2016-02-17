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
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LockFileGetMappingStrategy
  implements GridmapDirGetMappingStrategy {
  
  public enum MappingResult {
    SUCCESS,
    SUBJECT_ALREADY_MAPPED,
    LINK_ERROR,
    POOL_ACCOUNT_BUSY,
    INDETERMINATE
  }

  public static final Logger LOG = LoggerFactory
    .getLogger(LockFileGetMappingStrategy.class);

  private final Random random = new Random();

  private final File gridmapDirectory;

  /**
   * Regexp pattern used to identify pool account names.
   * 
   * Contains a single group match whose value is the pool account name prefix.
   * 
   */
  private final Pattern poolAccountNamePattern_ = Pattern
    .compile("^([a-zA-Z][a-zA-Z0-9._-]*?)[0-9]++$");

  public LockFileGetMappingStrategy(File gridmapDirectory) {
    this.gridmapDirectory = gridmapDirectory;
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

        LOG.error("Error acquiring lock", e);
        return null;

      }

      if (lock == null) {

        try {

          long randomSleepTime = getRandomInteger(SLEEP_TIME_LOWER_BOUND,
            SLEEP_TIME_UPPER_BOUND);

          LOG.debug("Failed to acquire lock on account {}, sleeping {} msecs",
            accountFile.getName(), randomSleepTime);

          Thread.sleep(randomSleepTime);

        } catch (InterruptedException e) {

        }
      }
    } while (lock == null);

    return lock;
  }

  private UnixFile createMapping(String accountNamePrefix,
    UnixFile subjectFile) {

    for (File accountFile : getAccountFiles(accountNamePrefix)) {

      FileLock lock = null;
      RandomAccessFile lockFile = null;

      try {

        if (subjectFile.exists()) {

          return lookupPoolAccountLinkedToSubject(accountNamePrefix,
            subjectFile);
        }

        lockFile = openLockFile(accountFile);

        if (lockFile == null) {
          LOG.error("Error creating lock file");
          return null;
        }

        lock = acquireLock(lockFile, accountFile);

        if (lock == null) {
          LOG.error("Error acquiring lock");
          return null;
        }

        UnixFile accountUnixFile = UnixFile.forExistingFile(accountFile);

        if (accountUnixFile.nlink() >= 2) {

          if (accountUnixFile.nlink() > 2) {
            // Warn about corrupted pool accounts, we cannot do more than this

            LOG.error(
              "Pool account {} corrupted and currently bound to more than one subject [inode: {}, nlinks: {}]",
              accountUnixFile.getName(), accountUnixFile.ino(),
              accountUnixFile.nlink());

          } else {

            LOG.debug("Pool account {} already allocated, moving on",
              accountFile.getName());
          }

          continue;
        }

        MappingResult result = linkSubjectToPoolAccount(accountUnixFile,
          subjectFile);

        switch (result) {

        case SUBJECT_ALREADY_MAPPED:
          LOG.warn(
            "Found mapping for subject {} while attempting mapping creation on pool account {}.",
            subjectFile.getName(), accountFile.getName());

          // Release the lock before looking for the already mapped pool account
          lock.release();

          // Let's find out which mapping was created under our nose
          UnixFile mappedAccount = lookupPoolAccountLinkedToSubject(
            accountNamePrefix, subjectFile);

          return mappedAccount;

        case POOL_ACCOUNT_BUSY:
          LOG.error("Pool account {} become busy. Backing off for subject {}",
            accountFile.getName(), subjectFile.getName());

          continue;

        case SUCCESS:
          return accountUnixFile;

        case INDETERMINATE:
          LOG.error(
            "Indeterminate mapping result for subject {} and pool account {}",
            subjectFile.getName(), accountFile.getName());
          return null;

        case LINK_ERROR:
          LOG.error("Error linking subject {} to pool account {}",
            subjectFile.getName(), accountFile.getName());
          return null;
        }
      } catch (IOException e) {

        LOG.error("Error creating lock file: {}", e.getMessage(), e);
        return null;

      } finally {

        // Closing the lock file releases the lock
        safeCloseLockFile(lockFile);

      }
    }

    LOG.error(
      "Pool account {} fully allocated. Impossible to return a mapping for subject {}",
      accountNamePrefix, subjectFile.getName());
    return null;

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

    return gridmapDirectory.listFiles(new FilenameFilter() {

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

  public UnixFile getMapping(String accountNamePrefix, X500Principal subjectDN,
    File subjectIdentifierPath) {

    UnixFile subjectFile = UnixFile.forNonExistingFile(subjectIdentifierPath);

    if (subjectFile.exists()) {
      
      subjectFile.stat();

      return lookupPoolAccountLinkedToSubject(accountNamePrefix, subjectFile);

    } else {

      return createMapping(accountNamePrefix, subjectFile);
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
  private MappingResult linkSubjectToPoolAccount(UnixFile accountFile,
    UnixFile subjectFile) {

    LOG.debug("Linking {} -> {}", accountFile.getName(), subjectFile.getName());

    int retval = PosixUtil.createHardlink(accountFile.getFile(),
      subjectFile.getFile());

    if (retval != 0) {

      if (retval == Errno.EEXIST.value) {

        LOG.debug(
          "Subject identifier file {} already exists. "
            + "Check if is bound to pool account {}",
          subjectFile.getName(), accountFile.getName());

        subjectFile.stat();

        if (subjectFile.inodeEquals(accountFile)) {
          LOG.debug("Pool account {} already bound to subject {}",
            accountFile.getName(), subjectFile.getName());

          return MappingResult.SUCCESS;
        }

        LOG.debug(
          "Subject identifier {} is now linked to a different pool account. Backing off",
          subjectFile.getName());

        return MappingResult.SUBJECT_ALREADY_MAPPED;
      }

      LOG.error("Link error while creating mapping {} -> {}: error code {}.",
        accountFile.getName(), subjectFile.getName(), retval);

      return MappingResult.LINK_ERROR;

    } else { // retval == 0, hardlink creation successful

      accountFile.stat();

      if (accountFile.nlink() == 2) {

        LOG.debug("Mapping CREATED: {} -> {}", accountFile.getName(),
          subjectFile.getName());

        return MappingResult.SUCCESS;
      }

      if (accountFile.nlink() > 2) {

        LOG.debug(
          "Pool account has become busy. NLINK == {}! Removing just created link {} -> {}",
          accountFile.nlink(), accountFile.getName(), subjectFile.getName());

        subjectFile.delete();

        return MappingResult.POOL_ACCOUNT_BUSY;
      }

      // Should never happen
      return MappingResult.INDETERMINATE;
    }

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

      UnixFile accountUnixFile = UnixFile.forExistingFile(accountFile);

      if (accountUnixFile.inodeEquals(subjectFile)) {

        if (accountUnixFile.nlink() != 2) {
          LOG.error(
            "Found mapped pool account {} for subject id {} with link count != 2. inode: {}. The corrupt mapping should be cleaned up",
            accountUnixFile.getName(), subjectFile.getName(),
            accountUnixFile.ino());

          return null;
        }

        return accountUnixFile;
      }

    }

    return null;
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
  private RandomAccessFile openLockFile(File accountFile)
    throws FileNotFoundException {

    File lockFileName = new File(gridmapDirectory.getAbsolutePath(),
      String.format(".lock.%s", accountFile.getName()));

    return new RandomAccessFile(lockFileName, "rw");
  }

  private void safeCloseLockFile(RandomAccessFile f) {

    if (f != null) {
      try {
        f.close();
      } catch (IOException e) {

      }
    }
  }
}

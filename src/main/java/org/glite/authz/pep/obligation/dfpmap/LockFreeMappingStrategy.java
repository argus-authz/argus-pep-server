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
import java.util.Random;

import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A lock free gridmap dir mapping strategy.
 */
public class LockFreeMappingStrategy implements GridmapDirGetMappingStrategy {

  private static final Logger LOG = LoggerFactory
    .getLogger(LockFreeMappingStrategy.class);

  /** Internal RNG **/
  private final Random random = new Random();

  private final PoolAccountResolver accountResolver;
  private final boolean shuffleAccounts;
  private final int maxLookupIterations;

  public static class Builder {

    File gridmapDir;
    boolean shuffleAccounts = true;
    int maxLookupIterations = 10;
    PoolAccountResolver resolver;

    private Builder(File gridmapDir) {
      this.gridmapDir = gridmapDir;
    }

    public Builder withPoolAccountResolver(PoolAccountResolver resolver) {

      this.resolver = resolver;
      return this;
    }

    public Builder withShuffleAccounts(boolean shuffleAccounts) {

      this.shuffleAccounts = shuffleAccounts;
      return this;
    }

    public Builder withMaxLookupIterations(int maxLookupIterations) {

      this.maxLookupIterations = maxLookupIterations;
      return this;
    }

    public LockFreeMappingStrategy build() {

      if (resolver == null) {
        resolver = new DefaultPoolAccountResolver(gridmapDir);
      }

      return new LockFreeMappingStrategy(resolver, shuffleAccounts,
        maxLookupIterations);
    }

  }

  public static Builder forGridmapDir(File gridmapDir) {

    return new Builder(gridmapDir);
  }

  private LockFreeMappingStrategy(PoolAccountResolver resolver,
    boolean shuffleAccounts, int maxLookupIterations) {

    this.accountResolver = resolver;
    this.shuffleAccounts = shuffleAccounts;
    this.maxLookupIterations = maxLookupIterations;
  }

  private long getRandomInteger(int lowerBound, int upperBound) {

    int sleepTime = random.nextInt((upperBound - lowerBound) + 1) + lowerBound;
    return (long) sleepTime;

  }

  private File[] shuffleAccounts(File[] a) {

    File[] accounts = new File[a.length];
    System.arraycopy(a, 0, accounts, 0, a.length);

    for (int i = accounts.length - 1; i > 0; i--) {
      int index = random.nextInt(i + 1);

      File tmp = accounts[index];
      accounts[index] = accounts[i];
      accounts[i] = tmp;
    }

    return accounts;
  }

  private File[] resolveAccounts(String accountNamePrefix) {

    File[] files = accountResolver.getAccountFiles(accountNamePrefix);

    if (shuffleAccounts) {

      return shuffleAccounts(files);

    }

    return files;

  }

  private LookupResult lookup(String accountNamePrefix, UnixFile subjectFile) {

    for (File accountFile : resolveAccounts(accountNamePrefix)) {

      UnixFile account = UnixFile.forExistingFile(accountFile);

      if (subjectFile.inodeEquals(account)) {

        if (account.nlink() != 2) {

          LOG.warn(
            "Found mapped pool account {} for subject id {} with link count != 2. inode: {}. Corrupt pool account?",
            account.getName(), subjectFile.getName(), account.ino());

          continue;

        }

        return LookupResult.success(account);
      }
    }

    return LookupResult.notFound();
  }

  private void backoff() {

    long sleepTime = getRandomInteger(10, 100);

    try {

      LOG.debug("Backing off for {} msecs", sleepTime);

      Thread.sleep(sleepTime);

    } catch (InterruptedException e) {

    }
  }

  private LookupResult create(String accountNamePrefix, UnixFile subjectFile) {

    for (File accountFile : resolveAccounts(accountNamePrefix)) {

      UnixFile account = UnixFile.forExistingFile(accountFile);

      if (account.nlink() == 1) {

        int retval = PosixUtil.createHardlink(accountFile,
          subjectFile.getFile());

        if (retval == Errno.EEXIST.value) {

          subjectFile.stat();

          if (!subjectFile.inodeEquals(account)) {
            return LookupResult.continueLookup();
          }

          if (subjectFile.nlink() == 1) {
            LOG.warn("Cleaning up stale handle {}", subjectFile.getName());
            subjectFile.delete();
            return LookupResult.continueLookup();
          }

          if (subjectFile.nlink() == 2) {
            return LookupResult.success(account);
          }

          LOG.warn(
            "Pool account {} linked to {} is currently corrupted. inode: {}. link count: {}",
            account.getName(), subjectFile.getName(), account.ino(),
            account.nlink());

          backoff();
          return LookupResult.continueLookup();
        }

        if (retval != 0) {
          LOG.error("Link error when linking {} to {}.", subjectFile.getName(),
            account.getName());

          return LookupResult.linkError();
        }

        // hardlink creation succeeded, check number of links
        account.stat();

        if (account.nlink() == 2) {
          return LookupResult.success(account);
        }

        if (account.nlink() > 2) {
          LOG.debug(
            "Conflict on account {}. link count {}. Dropping link from {} and backing off",
            account.getName(), account.nlink(), subjectFile.getName());

          subjectFile.delete();
          backoff();
          return LookupResult.continueLookup();
        }
      }
    }

    return LookupResult.notFound();
  }

  public UnixFile getMapping(String accountNamePrefix, X500Principal subjectDN,
    File subjectIdentifierPath) {

    UnixFile subjectFile = UnixFile.forNonExistingFile(subjectIdentifierPath);

    int iterations = 0;

    while (iterations++ < maxLookupIterations) {

      if (subjectFile.exists()) {

        subjectFile.stat();

        LookupResult r = lookup(accountNamePrefix, subjectFile);

        if (r.isSuccess()) {
          LOG.debug("Found mapping for {}: {} -> {}", subjectDN,
            r.account.getName(), subjectFile.getName());
          return r.account;
        }

        if (subjectFile.exists()) {
          LOG.warn(
            "Subject file {} exists but mapping NOT found. Corrupt pool account?",
            subjectFile.getName());

          continue;
        }

        return null;

      } else {

        LookupResult r = create(accountNamePrefix, subjectFile);

        if (r.isSuccess()) {
          LOG.debug("Created mapping for {}: {} -> {}", subjectDN,
            r.account.getName(), subjectFile.getName());
          return r.account;
        }

        if (r.isContinue()) {
          LOG.debug("Attempting new lookup for {}.", subjectDN);
          continue;
        }

        return null;

      }

    }

    LOG.warn("Giving up lookup after {} iterations", iterations);
    return null;

  }

}

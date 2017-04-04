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

package org.glite.authz.pep.pip.provider.authnprofilespip;

import static java.lang.String.format;
import static java.nio.file.Files.newDirectoryStream;

import java.io.File;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.DirectoryStream.Filter;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.jcip.annotations.ThreadSafe;

/**
 * 
 * Default implementation for a {@link AuthenticationProfileRepository}, which can refresh its
 * contents in a thread-safe manner.
 *
 */
@ThreadSafe
public class TrustAnchorsDirectoryAuthenticationProfileRepository
    implements AuthenticationProfileRepository {

  public static final Logger LOG =
      LoggerFactory.getLogger(TrustAnchorsDirectoryAuthenticationProfileRepository.class);

  private static final String DEFAULT_AUTHN_PROFILE_FILE_PATTERN_STRING = "policy-*.info";
  private static final Pattern AUTHN_PROFILE_FILE_PATTERN = Pattern.compile("(.*).info");

  private final String trustAnchorsDir;
  private final String authnProfileFilePattern;
  private final AuthenticationProfileFileParser authnProfileParser;

  private Map<String, AuthenticationProfile> profiles = new HashMap<>();
  private Map<String, Set<AuthenticationProfile>> dnLookupTable = new HashMap<>();

  protected final ReadWriteLock rwLock = new ReentrantReadWriteLock();

  protected final Lock readLock = rwLock.readLock();
  protected final Lock writeLock = rwLock.writeLock();

  public TrustAnchorsDirectoryAuthenticationProfileRepository(String trustAnchorsDir,
      String policyFilePattern, AuthenticationProfileFileParser policyFileParser) {
    this.trustAnchorsDir = trustAnchorsDir;
    this.authnProfileFilePattern = policyFilePattern;
    this.authnProfileParser = policyFileParser;
    loadProfiles();
  }

  public TrustAnchorsDirectoryAuthenticationProfileRepository(String trustAnchorsDir) {
    this(trustAnchorsDir, DEFAULT_AUTHN_PROFILE_FILE_PATTERN_STRING,
        new DefaultAuthenticationProfileFileParser());
  }

  public TrustAnchorsDirectoryAuthenticationProfileRepository(String trustAnchorsDir,
      String policyFilePattern) {
    this(trustAnchorsDir, policyFilePattern, new DefaultAuthenticationProfileFileParser());
  }

  @Override
  public List<AuthenticationProfile> getAuthenticationProfiles() {
    return new ArrayList<>(profiles.values());
  }

  private Filter<Path> buildAuthenticationProfileFileFilter() {

    return new DirectoryStream.Filter<Path>() {

      public boolean accept(Path path) {

        return path.getFileName()
          .toString()
          .matches(authnProfileFilePattern.replace(".", "\\.").replace("*", ".*"));
      }
    };
  }

  private void trustInfoDirSanityChecks() {

    if (trustAnchorsDir == null || trustAnchorsDir.isEmpty()) {
      throw new IllegalArgumentException("null value for property 'trustInfoDir'");
    }
    File dir = new File(trustAnchorsDir);
    if (!dir.exists()) {
      throw new IllegalArgumentException(format("Directory %s does not exist", trustAnchorsDir));
    }
    if (!dir.isDirectory()) {
      throw new IllegalArgumentException(format("The path %s is not a directory", trustAnchorsDir));
    }
    if (!dir.canRead()) {
      throw new IllegalArgumentException(
          format("The directory %s is not readable", trustAnchorsDir));
    }
  }

  private void authenticationProfileFilePatternSanityChecks() {

    if (authnProfileFilePattern == null || authnProfileFilePattern.isEmpty()) {
      throw new IllegalArgumentException("null value for property 'authnProfileFilePattern'");
    }
  }

  private void authnInfoParserSanityChecks() {

    if (authnProfileParser == null) {
      throw new IllegalArgumentException("null value for property 'authnProfileParser'");
    }
  }


  protected void loadProfiles() {

    trustInfoDirSanityChecks();
    authenticationProfileFilePatternSanityChecks();
    authnInfoParserSanityChecks();

    Map<String, AuthenticationProfile> loadedProfiles = new HashMap<>();
    Map<String, Set<AuthenticationProfile>> lookupTable = new HashMap<>();

    try {
      DirectoryStream<Path> stream =
          newDirectoryStream(Paths.get(trustAnchorsDir), buildAuthenticationProfileFileFilter());

      for (Path filepath : stream) {
        LOG.debug("Loading authentication profiles from file: {}", filepath);
        AuthenticationProfile profile = authnProfileParser.parse(filepath.toString());
        loadedProfiles.put(profile.getAlias(), profile);

        profile.getCASubjects().forEach(dn -> {
          String name = dn.getName();
          if (lookupTable.containsKey(name)) {
            lookupTable.get(name).add(profile);
          } else {
            Set<AuthenticationProfile> s = new HashSet<>();
            s.add(profile);
            lookupTable.put(name, s);
          }
          LOG.debug("Mapped CA dn '{}' to profile '{}'", name, profile.getAlias());
        });

      }
    } catch (IOException e) {
      LOG.error("Error loading authentication profile: {}", e.getMessage(), e);
      throw new IllegalArgumentException("Error loading authentication profile: " + e.getMessage(),
          e);
    }

    if (loadedProfiles.isEmpty()) {
      String errorMsg = format("The pattern [%s] doesn't match any file into directory [%s]",
          authnProfileFilePattern, trustAnchorsDir);

      LOG.error(errorMsg);
      throw new IllegalArgumentException(errorMsg);
    }

    writeLock.lock();

    try {
      profiles = loadedProfiles;
      dnLookupTable = lookupTable;
    } finally {
      writeLock.unlock();
    }

  }

  @Override
  public Optional<AuthenticationProfile> findProfileByAlias(String profile) {
    readLock.lock();
    try {
      return Optional.ofNullable(profiles.get(profile));
    } finally {
      readLock.unlock();
    }
  }

  @Override
  public Optional<AuthenticationProfile> findProfileByFilename(String filename) {

    Matcher m = AUTHN_PROFILE_FILE_PATTERN.matcher(filename);

    if (!m.matches()) {
      throw new IllegalArgumentException("Invalid authentication profile file name: " + filename);
    }

    String profileAlias = m.group(1);
    return findProfileByAlias(profileAlias);

  }

  @Override
  public Set<AuthenticationProfile> findProfilesForSubject(X500Principal principal) {

    readLock.lock();

    try {
      Set<AuthenticationProfile> result = dnLookupTable.get(principal.getName());
      if (result == null) {
        return Collections.emptySet();
      }
      return result;
    } finally {
      readLock.unlock();
    }
  }


  @Override
  public void reloadRepositoryContents() {
    loadProfiles();
  }
}

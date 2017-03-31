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

import static java.util.Objects.requireNonNull;
import static org.glite.authz.pep.pip.provider.authnprofilespip.Decision.allow;
import static org.glite.authz.pep.pip.provider.authnprofilespip.Decision.deny;

import java.io.IOException;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An implementation for {@link AuthenticationProfilePDP}. Decisions are rendered taking into
 * account the authentication profiles obtained by the {@link AuthenticationProfileRepository} and
 * the {@link AuthenticationProfilePolicySet} used to build a
 * {@link DefaultAuthenticationProfilePDP}.
 * 
 * A {@link Builder} class is provided to simplify creating this PDP.
 * 
 */
public class DefaultAuthenticationProfilePDP implements AuthenticationProfilePDP {
  
  public static final Logger LOG = LoggerFactory.getLogger(DefaultAuthenticationProfilePDP.class);

  protected final AuthenticationProfileRepository profileRepository;
  protected final AuthenticationProfilePolicySetRepository policyRepository;

  protected final long refreshIntervalInSecs;
  
  ScheduledExecutorService repositoryRefreshExecutorService;

  public DefaultAuthenticationProfilePDP(AuthenticationProfileRepository profileRepo,
      AuthenticationProfilePolicySetRepository policyRepo, long refreshIntervalInSecs) throws IOException {
    this.profileRepository = profileRepo;
    this.policyRepository = policyRepo;
    this.refreshIntervalInSecs = refreshIntervalInSecs;
  }
  
  public DefaultAuthenticationProfilePDP(AuthenticationProfileRepository profileRepo,
      AuthenticationProfilePolicySetRepository policyRepo) throws IOException {
    this(profileRepo, policyRepo, -1);
  }

  protected void boostrapRepositoryRefresh() {
    
    if (refreshIntervalInSecs <= 0) {
      LOG.info("Repositories will not be refreshed: refreshInterval <= 0");
      return;
    }

    repositoryRefreshExecutorService = Executors
      .newSingleThreadScheduledExecutor(new AuthenticationProfileRefresherThreadFactory());

    repositoryRefreshExecutorService.scheduleAtFixedRate(
        new RefreshRepositoryTask(profileRepository), 0, refreshIntervalInSecs, TimeUnit.SECONDS);
    
    repositoryRefreshExecutorService.scheduleAtFixedRate(
        new RefreshRepositoryTask(policyRepository), 0, refreshIntervalInSecs, TimeUnit.SECONDS);
  }

  private Set<AuthenticationProfile> lookupProfiles(X500Principal principal) {
    requireNonNull(principal, "Please provide a non-null principal argument");

    Set<AuthenticationProfile> profiles = profileRepository.findProfilesForSubject(principal);

    if (profiles.isEmpty()) {
      throw new AuthenticationProfileError(
          "No authentication profile found for X500 principal: " + principal.getName());
    }

    return profiles;
  }

  private Decision policyDecision(AuthenticationProfilePolicy policy, X500Principal principal,
      Set<AuthenticationProfile> profiles) {

    requireNonNull(policy);
    requireNonNull(principal);
    requireNonNull(profiles);

    Optional<AuthenticationProfile> allowedProfile = policy.supportsAtLeastOneProfile(profiles);

    if (allowedProfile.isPresent()) {
      return allow(principal, allowedProfile.get());
    }

    return deny(principal);
  }

  @Override
  public Decision isCaAllowedForVO(X500Principal principal, String voName) {

    requireNonNull(voName, "Please provide a non-null vo name");
    Set<AuthenticationProfile> principalProfiles = lookupProfiles(principal);

    AuthenticationProfilePolicy voPolicy =
        policyRepository.getAuthenticationProfilePolicySet().getVoProfilePolicies().get(voName);

    Decision decision = Decision.deny(principal);

    if (voPolicy != null) {

      decision = policyDecision(voPolicy, principal, principalProfiles);

      if (decision.isAllowed()) {
        return decision;
      }
    }

    if (policyRepository.getAuthenticationProfilePolicySet().getAnyVoProfilePolicy().isPresent()) {
      AuthenticationProfilePolicy anyVoPolicy =
          policyRepository.getAuthenticationProfilePolicySet().getAnyVoProfilePolicy().get();
      decision = policyDecision(anyVoPolicy, principal, principalProfiles);
    }

    return decision;
  }

  @Override
  public Decision isCaAllowed(X500Principal principal) {

    Set<AuthenticationProfile> principalProfiles = lookupProfiles(principal);

    if (policyRepository.getAuthenticationProfilePolicySet()
      .getAnyCertificateProfilePolicy()
      .isPresent()) {
      AuthenticationProfilePolicy anyCertPolicy = policyRepository
        .getAuthenticationProfilePolicySet().getAnyCertificateProfilePolicy().get();

      Optional<AuthenticationProfile> allowedProfile =
          anyCertPolicy.supportsAtLeastOneProfile(principalProfiles);

      if (allowedProfile.isPresent()) {
        return allow(principal, allowedProfile.get());
      }
    }

    return deny(principal);
  }


  /**
   * 
   * A builder for {@link DefaultAuthenticationProfilePDP}.
   *
   */
  public static class Builder {

    private String authenticationPolicyFile = "/etc/grid-security/vo-ca-ap-file";
    private String trustAnchorsDir = "/etc/grid-security/certificates";
    private String policyFilePattern = "policy-*.info";
    private int refreshIntervalInSecs = -1;

    public Builder authenticationPolicyFile(String f) {
      this.authenticationPolicyFile = f;
      return this;
    }

    public Builder trustAnchorsDir(String dir) {
      this.trustAnchorsDir = dir;
      return this;
    }

    public Builder policyFilePattern(String pfp) {
      this.policyFilePattern = pfp;
      return this;
    }

    public Builder refreshIntervalInSecs(int refreshInterval) {
      this.refreshIntervalInSecs = refreshInterval;
      return this;
    }

    public DefaultAuthenticationProfilePDP build() throws IOException {

      AuthenticationProfileRepository profileRepo =
          new TrustAnchorsDirectoryAuthenticationProfileRepository(trustAnchorsDir,
              policyFilePattern);

      AuthenticationProfilePolicySetBuilder parser =
          new VoCaApInfoFileParser(authenticationPolicyFile, profileRepo);

      AuthenticationProfilePolicySetRepository policySetRepo =
          new DefaultAuthenticationProfilePolicySetRepository(parser);

      return new DefaultAuthenticationProfilePDP(profileRepo, 
          policySetRepo, refreshIntervalInSecs); 
    }
  }

  static class RefreshRepositoryTask implements Runnable {
    private static final Logger LOG = LoggerFactory.getLogger(RefreshRepositoryTask.class);

    final ReloadingRepository repository;

    public RefreshRepositoryTask(ReloadingRepository repo) {
      this.repository = repo;
    }

    @Override
    public void run() {
      try {
        repository.reloadRepositoryContents();
      } catch (Throwable e) {
        LOG.error("Error reloading repository {} contents: {}",
            repository.getClass().getSimpleName(), e.getMessage(), e);
      }
    }

  }
  static class AuthenticationProfileRefresherThreadFactory implements ThreadFactory {

    public static final String THREAD_NAME = "authn-profile-refresher";

    @Override
    public Thread newThread(Runnable r) {
      return new Thread(r, THREAD_NAME);
    }
  }
  @Override
  public void start() {
    boostrapRepositoryRefresh();
  }

  @Override
  public void stop() {
   if (repositoryRefreshExecutorService != null){
     repositoryRefreshExecutorService.shutdown();
   }
  }
}

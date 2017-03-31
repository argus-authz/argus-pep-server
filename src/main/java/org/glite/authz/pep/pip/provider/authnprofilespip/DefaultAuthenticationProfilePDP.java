package org.glite.authz.pep.pip.provider.authnprofilespip;

import static java.util.Objects.requireNonNull;
import static org.glite.authz.pep.pip.provider.authnprofilespip.Decision.allow;
import static org.glite.authz.pep.pip.provider.authnprofilespip.Decision.deny;

import java.io.IOException;
import java.util.Optional;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

/**
 * An implementation for {@link AuthenticationProfilePDP}. Decisions are rendered taking into
 * account the authentication profiles obtained by the {@link AuthenticationProfileRepository} and
 * the {@link AuthenticationProfilePolicySet} used to build a
 * {@link DefaultAuthenticationProfilePDP}.
 * 
 * A {@link Builder} class is provided to simplify boostrapping the PDP.
 */
public class DefaultAuthenticationProfilePDP implements AuthenticationProfilePDP {

  final AuthenticationProfileRepository profileRepository;
  final AuthenticationProfilePolicySetRepository policyRepository;

  public DefaultAuthenticationProfilePDP(AuthenticationProfileRepository profileRepo,
      AuthenticationProfilePolicySetRepository policyRepo) throws IOException {
    this.profileRepository = profileRepo;
    this.policyRepository = policyRepo;
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

    if (policyRepository.getAuthenticationProfilePolicySet().getAnyCertificateProfilePolicy().isPresent()) {
      AuthenticationProfilePolicy anyCertPolicy =
          policyRepository.getAuthenticationProfilePolicySet().getAnyCertificateProfilePolicy().get();

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

    public DefaultAuthenticationProfilePDP build() throws IOException {
      
      AuthenticationProfileRepository profileRepo =
          new TrustAnchorsDirectoryAuthenticationProfileRepository(trustAnchorsDir,
              policyFilePattern);
      
      AuthenticationProfilePolicySetBuilder parser =
          new VoCaApInfoFileParser(authenticationPolicyFile, profileRepo);
      
      AuthenticationProfilePolicySetRepository policySetRepo =
          new DefaultAuthenticationProfilePolicySetRepository(parser);

      return new DefaultAuthenticationProfilePDP(profileRepo, policySetRepo);
    }
  }
}

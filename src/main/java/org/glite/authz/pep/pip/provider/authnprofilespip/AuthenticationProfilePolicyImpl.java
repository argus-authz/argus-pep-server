package org.glite.authz.pep.pip.provider.authnprofilespip;

import static java.util.Objects.requireNonNull;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 
 * A basic implementation for {@link AuthenticationProfilePolicy}
 *
 */
public class AuthenticationProfilePolicyImpl implements AuthenticationProfilePolicy {

  final Map<String, AuthenticationProfile> profileMap = new HashMap<>();

  public AuthenticationProfilePolicyImpl(List<AuthenticationProfile> rules) {
    requireNonNull(rules);
    rules.forEach(p -> profileMap.put(p.getAlias(), p));
  }

  @Override
  public Set<AuthenticationProfile> getSupportedProfiles() {
    return new HashSet<>(profileMap.values());
  }

  @Override
  public boolean supportsProfile(String profileAlias) {
    requireNonNull(profileAlias);
    return profileMap.containsKey(profileAlias);
  }

  @Override
  public boolean supportsProfile(AuthenticationProfile profile) {
    requireNonNull(profile);
    return supportsProfile(profile.getAlias());
  }

  @Override
  public boolean supportsAtLeastOneProfile(Set<AuthenticationProfile> profiles) {
    
    for (AuthenticationProfile p: profiles){
      if (supportsProfile(p)){
        return true;
      }
    }
    
    return false;
  }
}

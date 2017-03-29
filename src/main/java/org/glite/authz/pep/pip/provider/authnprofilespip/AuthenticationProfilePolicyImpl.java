package org.glite.authz.pep.pip.provider.authnprofilespip;

import java.util.List;

/**
 * 
 * A basic implementation for {@link AuthenticationProfilePolicy}
 *
 */
public class AuthenticationProfilePolicyImpl
    implements AuthenticationProfilePolicy {

  final List<PolicyProfileInfo> profiles;

  
  public AuthenticationProfilePolicyImpl(List<PolicyProfileInfo> rules) {
    profiles = rules;
  }

  @Override
  public List<PolicyProfileInfo> getRules() {

    return profiles;
  }

}

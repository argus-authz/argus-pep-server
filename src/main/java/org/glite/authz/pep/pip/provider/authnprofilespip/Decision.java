package org.glite.authz.pep.pip.provider.authnprofilespip;

import javax.security.auth.x500.X500Principal;

public class Decision {

  final X500Principal principal;

  final boolean allowed;

  final AuthenticationProfile profile;

  private Decision(X500Principal principal, boolean allowed, AuthenticationProfile profile) {

    this.principal = principal;
    this.allowed = allowed;
    this.profile = profile;
  }

  public X500Principal getPrincipal() {
    return principal;
  }

  public boolean isAllowed() {
    return allowed;
  }

  public AuthenticationProfile getProfile() {
    return profile;
  }

  @Override
  public String toString() {
    return "Decision [principal=" + principal + ", allowed=" + allowed + ", profile=" + profile
        + "]";
  }
  
  public static Decision allow(X500Principal principal, AuthenticationProfile profile){
    return new Decision(principal, true, profile);
  }
  
  public static Decision deny(X500Principal principal){
    return new Decision(principal, false, null);
  }
}

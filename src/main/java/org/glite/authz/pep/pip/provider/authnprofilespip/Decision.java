package org.glite.authz.pep.pip.provider.authnprofilespip;

import javax.security.auth.x500.X500Principal;
/**
 * A {@link Decision} is rendered by the {@link AuthenticationProfilePDP} after having 
 * evaluated if a principal is allowed according to the set of current 
 * {@link AuthenticationProfilePolicy}.
 */
public class Decision {

  /** The principal for which the decision is rendered **/
  final X500Principal principal;

  /** Whether the principal was was allowed or denied **/
  final boolean allowed;

  /** The authentication profile, in case access was allowed **/
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

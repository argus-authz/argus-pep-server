package org.glite.authz.pep.pip.provider.authnprofilespip;

import java.util.Set;

/**
 * 
 * An authentication profile policy is a container for a list of {@link AuthenticationProfile}
 * objects
 *
 */
public interface AuthenticationProfilePolicy {

  /**
   * Returns the set of {@link AuthenticationProfile} that compose this policy
   * 
   * @return a (possibly empty) list of {@link AuthenticationProfile} objects
   */
  Set<AuthenticationProfile> getSupportedProfiles();


  /**
   * Tells whether this policy supports a given {@link AuthenticationProfile}
   * 
   * @param profile the profile to be checked
   * @return <code>true</code> if the profile is supported, <code>false</code> otherwise
   */
  public boolean supportsProfile(AuthenticationProfile profile);

  /**
   * Tells whether this policy supports a profile given its alias
   * 
   * @param profileAlias the profile alias to be checked
   * @return <code>true</code> if the profile is supported, <code>false</code> otherwise
   */
  public boolean supportsProfile(String profileAlias);

  /**
   * Tells whether this policy supports at least one of the profiles passed as argument
   * 
   * @param profiles the {@link Set} of profiles to be checked
   * @return <code>true</code> if at least one profile in the set passed as argument is supported,
   *         <code>false</code> otherwise
   */
  public boolean supportsAtLeastOneProfile(Set<AuthenticationProfile> profiles);


}

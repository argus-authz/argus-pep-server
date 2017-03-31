package org.glite.authz.pep.pip.provider.authnprofilespip;

/**
 * 
 * An {@link AuthenticationProfilePolicySetRepository} provides access 
 * to an {@link AuthenticationProfilePolicySet}
 *
 */
public interface AuthenticationProfilePolicySetRepository {
  
  /**
   * Returns the {@link AuthenticationProfilePolicySet} stored in this
   * {@link AuthenticationProfilePolicySetRepository}
   * 
   * @return an {@link AuthenticationProfilePolicySet}
   */
  AuthenticationProfilePolicySet getAuthenticationProfilePolicySet();

}

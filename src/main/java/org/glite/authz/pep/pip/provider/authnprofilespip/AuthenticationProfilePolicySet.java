package org.glite.authz.pep.pip.provider.authnprofilespip;

import java.util.Map;
import java.util.Optional;

/**
 * 
 * An {@link AuthenticationProfilePolicySet} holds three types of
 * {@link AuthenticationProfilePolicy}
 * 
 * <ul>
 * <li>VO policies, that define the {@link AuthenticationProfilePolicy} for given VO
 * <li>the VO catchall policy, that provides an {@link AuthenticationProfilePolicy} for any VO not
 * explicitly covered by VO policies
 * <li>the any trusted certificate catchall policy, that provides an
 * {@link AuthenticationProfilePolicy} for any certificate no containing VOMS extensions
 * </ul>
 * 
 * 
 */
public interface AuthenticationProfilePolicySet {

  /**
   * Returns a map, keyed by VO name, of the authentication profile policies defined by this
   * {@link AuthenticationProfilePolicySet} object
   * 
   * @return a (possibly empty) {@link Map} of VO profile policies
   */
  Map<String, AuthenticationProfilePolicy> getVoProfilePolicies();

  /**
   * Returns the {@link AuthenticationProfilePolicy} for any trusted VO not explicitly listed in the
   * policies returned by the {@link #getVoProfilePolicies()} method, if defined for this
   * {@link AuthenticationProfilePolicySet} object.
   * 
   * @return an {@link AuthenticationProfilePolicy} defined for any trusted VO
   */
  Optional<AuthenticationProfilePolicy> getAnyVoProfilePolicy();

  /**
   * Returns the {@link AuthenticationProfilePolicy} defined for any trusted certificate, if
   * defined.
   * 
   * @return an {@link AuthenticationProfilePolicy} for any trusted certificate
   */
  Optional<AuthenticationProfilePolicy> getAnyCertificateProfilePolicy();

}

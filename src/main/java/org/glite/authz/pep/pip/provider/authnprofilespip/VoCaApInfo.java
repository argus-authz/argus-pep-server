package org.glite.authz.pep.pip.provider.authnprofilespip;

import java.util.Map;
import java.util.Optional;

/**
 * 
 * This interface summarizes the authentication profile information provided by a vo-ca-ap policy
 * file, as described in https://wiki.nikhef.nl/grid/Lcmaps-plugins-vo-ca-ap#vo-ca-ap-file
 * 
 * 
 */
public interface VoCaApInfo {

  /**
   * Returns a map, keyed by VO name, of the profile policies defined by this {@link VoCaApInfo}
   * object
   * 
   * @return a (possibly empty) {@link Map} of VO profile policies
   */
  Map<String, AuthenticationProfilePolicy> getVoProfilePolicies();

  /**
   * Returns the {@link AuthenticationProfilePolicy} for any trusted VO not explicitly listed in the
   * policies returned by the {@link #getVoProfilePolicies()} method, if defined for this
   * {@link VoCaApInfo} object.
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

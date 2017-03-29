package org.glite.authz.pep.pip.provider.authnprofilespip;

import java.util.Set;

import javax.security.auth.x500.X500Principal;

/**
 * An {@link AuthenticationProfile} represents a named grouping of CA subjects that share common
 * properties (i.e. same Level Of Assurance).
 */
public interface AuthenticationProfile {

  /**
   * Returns the alias linked to this authentication profile
   * 
   * @return the alias for the authentication profile
   */
  String getAlias();

  /**
   * Returns the set of certificate authority subjects in this authentication profile
   * 
   * @return a (possibly empty) {@link Set} of {@link X500Principal} objects representing the
   *         certificate authority subjects in this authentication profile
   */
  Set<X500Principal> getCASubjects();
}

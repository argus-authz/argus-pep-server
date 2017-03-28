package org.glite.authz.pep.pip.provider.authnprofilespip;

import java.util.List;

/**
 * 
 * An authentication profile policy is a container for a list of {@link PolicyProfileInfo}
 * objects
 *
 */
public interface AuthenticationProfilePolicy {

  /**
   * Returns the list of {@link PolicyProfileInfo} that compose this policy
   * 
   * @return a (possibly empty) list of {@link PolicyProfileInfo} objects
   */
  List<PolicyProfileInfo> getRules();

}

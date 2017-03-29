package org.glite.authz.pep.pip.provider.authnprofilespip;

import javax.security.auth.x500.X500Principal;

/**
 * 
 * An {@link AuthenticationProfilePDP} can return decisions on whether a CA certificate
 * subject should be allowed for a VO or as a plain certificate without VOMS extensions.
 */
public interface AuthenticationProfilePDP {

  /**
   * Returns a decision on whether a CA is supported by a given VO.
   * 
   * @param caSubject the CA {@link X500Principal} subject
   * @param voName the name of the VO to be checked
   * @return <code>true</code> if the CA is allowed, <code>false</code> otherwise
   */
  boolean isCaAllowedForVO(X500Principal caSubject, String voName);

  /**
   * Returns a decision on whether a CA is supported for plain certificate access.
   * 
   * @param principal the CA {@link X500Principal} subject
   * @return <code>true</code> if the CA is allowed, <code>false</code> otherwise
   */
  boolean isCaAllowed(X500Principal principal);


}

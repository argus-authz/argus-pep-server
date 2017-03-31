package org.glite.authz.pep.pip.provider.authnprofilespip;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

/**
 * 
 * An {@link AuthenticationProfileRepository} provides access and lookup functionality for
 * authentication profiles
 *
 */
public interface AuthenticationProfileRepository {

  /**
   * Returns the list of {@link AuthenticationProfile} active for this repository
   * 
   * @return a (possibly empty) list of {@link AuthenticationProfile}
   */
  List<AuthenticationProfile> getAuthenticationProfiles();

  /**
   * Finds a profile by alias
   * 
   * @param profileAlias the profile alias
   * @return an {@link Optional} containing an {@link AuthenticationProfile} that has the alias
   *         passed as argument
   */
  Optional<AuthenticationProfile> findProfileByAlias(String profileAlias);

  /**
   * Finds profile by filename
   * 
   * @param filename the filename from which the profile was loaded from
   * @return an {@link Optional} containing an {@link AuthenticationProfile} that was loaded from
   *         the filename passed as argument
   */
  Optional<AuthenticationProfile> findProfileByFilename(String filename);

  /**
   * Find profiles supporting a given {@link X500Principal} CA subject
   * 
   * @param principal a {@link X500Principal} CA subject
   * @return the (possibly empty) set of {@link AuthenticationProfile} that supports the CA subject
   *         passed as argument
   */
  Set<AuthenticationProfile> findProfilesForSubject(X500Principal principal);

}

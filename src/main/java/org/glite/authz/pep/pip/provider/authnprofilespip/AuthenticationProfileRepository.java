/*
 * Copyright (c) Members of the EGEE Collaboration. 2006-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.glite.authz.pep.pip.provider.authnprofilespip;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * 
 * An {@link AuthenticationProfileRepository} provides access and lookup functionality for
 * authentication profiles
 *
 */
public interface AuthenticationProfileRepository extends ReloadingRepository{

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
   * @param caSubject a CA subject, in RFC2253 format
   * @return the (possibly empty) set of {@link AuthenticationProfile} that supports the CA subject
   *         passed as argument
   */
  Set<AuthenticationProfile> findProfilesForSubject(String caSubject);

}

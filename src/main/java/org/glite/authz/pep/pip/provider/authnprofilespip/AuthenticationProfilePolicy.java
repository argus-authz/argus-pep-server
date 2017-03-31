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

import java.util.Optional;
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
   * @return a possibly empty {@link Optional} that contains the first supported
   *         {@link AuthenticationProfile} among those passed as arguments
   */
  public Optional<AuthenticationProfile> supportsAtLeastOneProfile(
      Set<AuthenticationProfile> profiles);


}

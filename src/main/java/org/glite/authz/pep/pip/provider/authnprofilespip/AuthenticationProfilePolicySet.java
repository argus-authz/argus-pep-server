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

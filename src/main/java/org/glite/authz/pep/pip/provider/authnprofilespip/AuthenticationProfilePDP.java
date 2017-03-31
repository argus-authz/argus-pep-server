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

import javax.security.auth.x500.X500Principal;

/**
 * 
 * An {@link AuthenticationProfilePDP} can return decisions on whether a CA certificate subject
 * should be allowed for a VO or as a plain certificate without VOMS extensions.
 */
public interface AuthenticationProfilePDP extends Lifecycle{

  /**
   * Returns a {@link Decision} on whether a CA is supported by a given VO.
   * 
   * @param caSubject the CA {@link X500Principal} subject
   * @param voName the name of the VO to be checked
   * @return a {@link Decision} stating whether a CA is supported by a given VO.
   */
  Decision isCaAllowedForVO(X500Principal caSubject, String voName);

  /**
   * Returns a {@link Decision} on whether a CA is supported for plain certificate access.
   * 
   * @param principal the CA {@link X500Principal} subject
   * @return a {@link Decision} stating whether a CA is supported for plain certificate access.
   */
  Decision isCaAllowed(X500Principal principal);
}

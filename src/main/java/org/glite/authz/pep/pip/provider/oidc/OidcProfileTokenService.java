/*
 * Copyright (c) Members of the EGEE Collaboration. 2006-2010. See http://www.eu-egee.org/partners/
 * for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package org.glite.authz.pep.pip.provider.oidc;

import java.util.Optional;

import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Subject;
import org.glite.authz.oidc.client.model.TokenInfo;

/***
 * 
 * Expose methods to manipulate OIDC profile attributes within a {@link Request}
 *
 */
public interface OidcProfileTokenService {

  /***
   * Look into request {@link Subject} and return the JWT token
   * 
   * @param request Request to process
   * @return The JWT access token if present, empty otherwise
   */
  Optional<String> extractTokenFromRequest(Request request);

  /***
   * Remove all OIDC attributes from the request
   * 
   * @param request Request to process
   */
  void removeOidcAttributesFromRequest(Request request);

  /***
   * Read OIDC information from a {@link TokenInfo} and add then into the corresponding OIDC
   * attribute
   * 
   * @param request Request to process
   * @param tokenInfo OIDC token and user information
   */
  void addOidcAttributesToRequest(Request request, TokenInfo tokenInfo);
}

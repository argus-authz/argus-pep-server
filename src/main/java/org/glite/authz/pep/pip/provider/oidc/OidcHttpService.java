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

/***
 * 
 * Utility service to connect to an OIDC client
 *
 */
public interface OidcHttpService {

  /***
   * Return the OIDC client URL specified in the configuration file
   * 
   * @return the OIDC client URL
   */
  String getOidcClientUrl();

  /***
   * Send a JWT access token to the OIDC client
   * 
   * @param accessToken JWT access token to decode
   * @return JSON string with response from the OIDC client
   */
  String inspectToken(String accessToken);
}

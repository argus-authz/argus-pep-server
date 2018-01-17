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

import static org.glite.authz.common.profile.OidcProfileConstants.ID_ATTRIBUTE_PROFILE_ID;

import java.util.Optional;

import org.glite.authz.common.model.Environment;
import org.glite.authz.common.model.Request;
import org.glite.authz.oidc.client.model.TokenInfo;
import org.glite.authz.pep.pip.PIPProcessingException;
import org.glite.authz.pep.pip.provider.AbstractPolicyInformationPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OidcProfilePIP extends AbstractPolicyInformationPoint {

  private static final Logger LOG = LoggerFactory.getLogger(OidcProfilePIP.class);

  private final OidcProfileTokenService tokenService;
  private final OidcTokenDecoder decoder;

  public OidcProfilePIP(String pipId, OidcProfileTokenService tokenService, OidcTokenDecoder decoder) {

    super(pipId);
    this.tokenService = tokenService;
    this.decoder = decoder;
  }

  protected boolean isOidcProfileRequest(Request request) {

    Environment env = request.getEnvironment();

    if (env == null) {
      return false;
    }

    return env.getAttributes().stream().anyMatch(a -> a.getId().equals(ID_ATTRIBUTE_PROFILE_ID));
  }

  @Override
  public boolean populateRequest(Request request) throws PIPProcessingException {

    if (!isOidcProfileRequest(request)) {
      LOG.info("Request doesn't match OIDC profile");
      return false;
    }
    
    tokenService.removeOidcAttributesFromRequest(request);

    Optional<String> accessToken = tokenService.extractTokenFromRequest(request);

    if (!accessToken.isPresent()) {
      LOG.error("No access token found into request '{}'", request);
      throw new PIPProcessingException("No access token found into request: " + request);
    }

    TokenInfo tokenInfo = decoder.decodeAccessToken(accessToken.get());

    if (!tokenInfo.getIntrospection().isActive()) {
      String msg = String.format("Invalid access token: '%s'", request);
      LOG.warn(msg);
      return false;
    }
    
    tokenService.addOidcAttributesToRequest(request, tokenInfo);

    return true;
  }

}

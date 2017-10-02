package org.glite.authz.pep.pip.provider.oidc;

import java.util.Optional;

import org.glite.authz.common.model.Environment;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.profile.OidcProfileConstants;
import org.glite.authz.oidc.client.model.TokenInfo;
import org.glite.authz.pep.pip.PIPProcessingException;
import org.glite.authz.pep.pip.provider.AbstractPolicyInformationPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OidcProfilePIP extends AbstractPolicyInformationPoint {

  private static final Logger LOG = LoggerFactory
    .getLogger(OidcProfilePIP.class);

  private final OidcProfileToken tokenService;
  private final TokenDecoder decoder;

  public OidcProfilePIP(String pipId, OidcProfileToken tokenService,
    TokenDecoder decoder) {

    super(pipId);
    this.tokenService = tokenService;
    this.decoder = decoder;
  }

  protected boolean isOidcProfile(Request request) {

    Environment env = request.getEnvironment();

    if (env == null) {
      return false;
    }

    return env.getAttributes()
      .stream()
      .anyMatch(a -> a.getId()
        .equals(OidcProfileConstants.ID_ATTRIBUTE_PROFILE_ID));
  }

  @Override
  public boolean populateRequest(Request request)
    throws PIPProcessingException {

    if (!isOidcProfile(request)) {
      String msg = "Request doesn't match OIDC profile";
      LOG.error(msg);
      throw new PIPProcessingException(msg);
    }

    Optional<String> accessToken = tokenService
      .extractTokenFromRequest(request);

    if (!accessToken.isPresent()) {
      LOG.error("No access token found into request '{}'", request);
      throw new PIPProcessingException(
        "No access token found into request: " + request);
    }

    TokenInfo tokenInfo = decoder.decodeAccessToken(accessToken.get());

    if (!tokenInfo.getIntrospection()
      .isActive()) {
      String msg = String.format("Request with expired access token: '%s'",
        request);
      LOG.error(msg);
      throw new PIPProcessingException(msg);
    }

    tokenService.cleanOidcAttributes(request);
    tokenService.addOidcAttributes(request, tokenInfo);

    return true;
  }

}

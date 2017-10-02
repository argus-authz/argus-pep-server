package org.glite.authz.pep.pip.provider.oidc;

import java.util.Optional;

import org.glite.authz.common.model.Request;
import org.glite.authz.oidc.client.model.TokenInfo;

public interface OidcProfileToken {

  Optional<String> extractTokenFromRequest(Request request);

  void cleanOidcAttributes(Request request);

  void addOidcAttributes(Request request, TokenInfo tokenInfo);
}

package org.glite.authz.pep.pip.provider.oidc;

import org.glite.authz.oidc.client.model.TokenInfo;

public interface TokenDecoder {

  TokenInfo decodeAccessToken(String accessToken);

}

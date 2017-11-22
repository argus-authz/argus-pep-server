package org.glite.authz.pep.pip.provider.oidc;

public interface OidcHttpService {

  String getOidcClientUrl();

  String postRequest(String accessToken);
}

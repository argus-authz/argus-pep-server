package org.glite.authz.pep.pip.provider.oidc.error;

public class TokenDecodingException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  public TokenDecodingException(String message, Throwable cause) {

    super(message, cause);
  }
}

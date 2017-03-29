package org.glite.authz.pep.pip.provider.authnprofilespip;

/**
 * 
 * An Authentication profile error class
 *
 */
public class AuthenticationProfileError extends RuntimeException {

  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  public AuthenticationProfileError() {
    super();
  }

  public AuthenticationProfileError(String message, Throwable cause) {
    super(message, cause);
  }

  public AuthenticationProfileError(String message) {
    super(message);
  }

}

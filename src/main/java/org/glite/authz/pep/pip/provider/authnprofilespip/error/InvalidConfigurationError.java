package org.glite.authz.pep.pip.provider.authnprofilespip.error;

public class InvalidConfigurationError extends RuntimeException {

  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  public InvalidConfigurationError(String message, Throwable cause) {
    super(message, cause);

  }

  public InvalidConfigurationError(String message) {
    super(message);

  }
}

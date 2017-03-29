package org.glite.authz.pep.pip.provider.authnprofilespip.error;

/**
 * 
 * 
 *
 */
public class ParseError extends RuntimeException {

  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  public ParseError(String message, Throwable cause) {
    super(message, cause);
  }

  public ParseError(String message) {
    super(message);
  }

  
}

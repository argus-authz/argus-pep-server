package org.glite.authz.pep.pip.provider.authnprofilespip;
/**
 * 
 * An {@link AuthenticationProfileParser} can parse
 * and {@link AuthenticationProfile} form a file
 *
 */
public interface AuthenticationProfileParser {

  /**
   * 
   * Parses an {@link AuthenticationProfile} from a file passed as argument
   * 
   * @param filename the file holding the {@link AuthenticationProfileParser}
   * @return the parsed {@link AuthenticationProfile}
   * @throws ParseError, when something goes wrong
   */
  AuthenticationProfile parse(String filename);
}

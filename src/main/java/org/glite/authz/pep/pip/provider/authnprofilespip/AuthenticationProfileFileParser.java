package org.glite.authz.pep.pip.provider.authnprofilespip;
/**
 * 
 * An {@link AuthenticationProfileFileParser} can parse
 * and {@link AuthenticationProfile} form a file
 *
 */
public interface AuthenticationProfileFileParser {

  /**
   * 
   * Parses an {@link AuthenticationProfile} from a file passed as argument
   * 
   * @param filename the file holding the {@link AuthenticationProfileFileParser}
   * @return the parsed {@link AuthenticationProfile}
   * @throws ParseError, when something goes wrong
   */
  AuthenticationProfile parse(String filename);
}

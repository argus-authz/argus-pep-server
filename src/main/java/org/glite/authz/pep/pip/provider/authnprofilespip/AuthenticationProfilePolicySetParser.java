package org.glite.authz.pep.pip.provider.authnprofilespip;

import java.io.IOException;

/**
 * An {@link AuthenticationProfilePolicySet} parser
 *
 */
public interface AuthenticationProfilePolicySetParser {
  AuthenticationProfilePolicySet parse() throws IOException;
}

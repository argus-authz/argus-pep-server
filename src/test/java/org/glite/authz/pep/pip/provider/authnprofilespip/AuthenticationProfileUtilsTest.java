/*
 * Copyright (c) Members of the EGEE Collaboration. 2006-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.glite.authz.pep.pip.provider.authnprofilespip;

import static org.glite.authz.pep.pip.provider.authnprofilespip.AuthenticationProfileUtils.convertCASubjects;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.util.Set;

import org.junit.Test;

public class AuthenticationProfileUtilsTest {

  @Test
  public void convertSubjectDnTest() throws IOException {

    String subjectDN = "\"/C=IT/L=Bologna/O=Policy Tester/CN=First CA\", \\"
      + "\"/C=IT/L=Bologna/O=Policy Tester/CN=Second CA\", \\"
      + "\"/C=IT/L=Bologna/O=Policy Tester/CN=Third CA\"";

    Set<String> issuer = convertCASubjects(subjectDN);

    assertNotNull(issuer);
    assertEquals(3, issuer.size());
  }

  @Test
  public void conversionWithMalformedDN() {

    String subjectDN = "\"/C=IT/L=Bologna/O=Policy Tester/CN=First CA\", \\"
      + "\"this_is_not_a_valid_dn\", \\"
      + "\"/C=IT/L=Bologna/O=Policy Tester/CN=Third CA\"";

    Set<String> issuer = null;
    try {
      issuer = convertCASubjects(subjectDN);
    } catch (IllegalArgumentException e) {
      assertThat(e, instanceOf(IllegalArgumentException.class));
      assertThat(e.getMessage(),
        containsString("is not a valid OpenSSL-encoded DN"));
    }
    assertNull(issuer);
  }

}
package org.glite.authz.pep.pip.provider.authnprofilespip;

import static org.glite.authz.pep.pip.provider.authnprofilespip.PolicyInfoFileUtils.convertCASubjects;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.junit.Test;

public class PolicyInfoFileUtilsTest {

  @Test
  public void convertSubjectDnTest() throws IOException {

    String subjectDN = "\"/C=IT/L=Bologna/O=Policy Tester/CN=First CA\", \\"
      + "\"/C=IT/L=Bologna/O=Policy Tester/CN=Second CA\", \\"
      + "\"/C=IT/L=Bologna/O=Policy Tester/CN=Third CA\"";

    Set<X500Principal> issuer = convertCASubjects(subjectDN);

    assertNotNull(issuer);
    assertEquals(3, issuer.size());
  }

  @Test
  public void conversionWithMalformedDN() {

    String subjectDN = "\"/C=IT/L=Bologna/O=Policy Tester/CN=First CA\", \\"
      + "\"this_is_not_a_valid_dn\", \\"
      + "\"/C=IT/L=Bologna/O=Policy Tester/CN=Third CA\"";

    Set<X500Principal> issuer = null;
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
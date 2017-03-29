package org.glite.authz.pep.pip.provider.authnprofilespip;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.io.IOException;

import javax.security.auth.x500.X500Principal;

import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class AuthenticationProfilePDPTests extends TestSupport {

  private AuthenticationProfileRepository repo;

  private AuthenticationProfilePDP pdp;
  private AuthenticationProfilePolicySet policies;

  @Before
  public void setup() throws IOException {
    repo = new TrustAnchorsDirectoryAuthenticationProfileRepository(TRUST_ANCHORS_DIR, ALL_POLICIES_FILTER);
    VoCaApInfoFileParser parser = new VoCaApInfoFileParser(IGTF_WLCG_VO_CA_AP_FILE, repo);
    policies = parser.parse();

    pdp = new DefaultAuthenticationProfilePDP(repo, parser);
  }

  @Test(expected = NullPointerException.class)
  public void testNullX500PrincipalFailure() {
    X500Principal principal = null;
    try {
      pdp.isCaAllowed(principal);
    } catch (NullPointerException e) {
      Assert.assertThat(e.getMessage(),
          Matchers.equalTo("Please provide a non-null principal argument"));
      throw e;
    }
  }

  @Test(expected = NullPointerException.class)
  public void testNullVoArgumentFailure() {
    X500Principal principal = opensslDnToX500Principal(CLASSIC_CA);
    try {
      pdp.isCaAllowedForVO(principal, null);
    } catch (NullPointerException e) {
      Assert.assertThat(e.getMessage(), Matchers.equalTo("Please provide a non-null vo name"));
      throw e;
    }
  }

  private void assertCaAcceptableForLhcVos(String caSubject){
    X500Principal principal = opensslDnToX500Principal(caSubject);
    for (String lhcVo : LHC_VOS) {
      Assert.assertThat(pdp.isCaAllowedForVO(principal, lhcVo), is(true));
    }
  }

  @Test
  public void testIOTACaAcceptableForLHC() {
    assertCaAcceptableForLhcVos(IOTA_CA);
  }
  
  @Test
  public void testClassicCaAcceptableForLHC() {
    assertCaAcceptableForLhcVos(CLASSIC_CA);
  }
  
  @Test
  public void testMicsCaAcceptableForLHC() {
    assertCaAcceptableForLhcVos(MICS_CA);
  }
  
  @Test
  public void testSlcsCaAcceptableForLHC() {
    assertCaAcceptableForLhcVos(SLCS_CA);
  }

  @Test
  public void testIOTACaNotAcceptableNonLHC() {
    X500Principal iotaCaPrincipal = opensslDnToX500Principal(IOTA_CA);

    assertThat(pdp.isCaAllowedForVO(iotaCaPrincipal, TEST_VO), is(false));

  }
  
  @Test
  public void testIOTACaNotAcceptableForPlainCertificateAccess() {
    X500Principal iotaCaPrincipal = opensslDnToX500Principal(IOTA_CA);

    assertThat(pdp.isCaAllowed(iotaCaPrincipal), is(false));

  }
  
  @Test(expected=AuthenticationProfileError.class)
  public void testUnaccreditedCa() {
    X500Principal unaccreditedCA  = opensslDnToX500Principal(UNACCREDITED_CA);
    pdp.isCaAllowedForVO(unaccreditedCA, "atlas");
  }
}

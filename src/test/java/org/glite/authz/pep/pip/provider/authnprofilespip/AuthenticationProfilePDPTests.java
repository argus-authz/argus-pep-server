package org.glite.authz.pep.pip.provider.authnprofilespip;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
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

  @Before
  public void setup() throws IOException {
    repo = new TrustAnchorsDirectoryAuthenticationProfileRepository(TRUST_ANCHORS_DIR,
        ALL_POLICIES_FILTER);
    
    VoCaApInfoFileParser parser = new VoCaApInfoFileParser(IGTF_WLCG_VO_CA_AP_FILE, repo);
    
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
      assertThat(e.getMessage(), equalTo("Please provide a non-null vo name"));
      throw e;
    }
  }

  private void assertCaAcceptableForLhcVos(String caSubject, String profile) {
    X500Principal principal = opensslDnToX500Principal(caSubject);
    for (String lhcVo : LHC_VOS) {
      assertEquals(pdp.isCaAllowedForVO(principal, lhcVo).isAllowed(), true);
      assertEquals(pdp.isCaAllowedForVO(principal, lhcVo).getProfile().getAlias(), profile);
    }
  }

  @Test
  public void testIOTACaAcceptableForLHC() {
    assertCaAcceptableForLhcVos(IOTA_CA, IGTF_IOTA);
  }

  @Test
  public void testClassicCaAcceptableForLHC() {
    assertCaAcceptableForLhcVos(CLASSIC_CA, IGTF_CLASSIC);
  }

  @Test
  public void testMicsCaAcceptableForLHC() {
    assertCaAcceptableForLhcVos(MICS_CA, IGTF_MICS);
  }

  @Test
  public void testSlcsCaAcceptableForLHC() {
    assertCaAcceptableForLhcVos(SLCS_CA, IGTF_SLCS);
  }

  @Test
  public void testIOTACaNotAcceptableNonLHC() {
    X500Principal iotaCaPrincipal = opensslDnToX500Principal(IOTA_CA);

    assertEquals(pdp.isCaAllowedForVO(iotaCaPrincipal, TEST_VO).isAllowed(), false);

  }

  @Test
  public void testIOTACaNotAcceptableForPlainCertificateAccess() {
    X500Principal iotaCaPrincipal = opensslDnToX500Principal(IOTA_CA);

    assertEquals(pdp.isCaAllowed(iotaCaPrincipal).isAllowed(), false);

  }

  @Test(expected = AuthenticationProfileError.class)
  public void testUnaccreditedCa() {
    X500Principal unaccreditedCA = opensslDnToX500Principal(UNACCREDITED_CA);
    pdp.isCaAllowedForVO(unaccreditedCA, "atlas");
  }
}

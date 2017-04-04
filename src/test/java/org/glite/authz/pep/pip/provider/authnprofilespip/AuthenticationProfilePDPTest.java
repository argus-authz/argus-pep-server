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

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

import java.io.IOException;

import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class AuthenticationProfilePDPTest extends TestSupport {

  private AuthenticationProfileRepository repo;

  private AuthenticationProfilePDP pdp;

  @Before
  public void setup() throws IOException {
    repo = new TrustAnchorsDirectoryAuthenticationProfileRepository(TRUST_ANCHORS_DIR,
        ALL_POLICIES_FILTER);

    VoCaApInfoFileParser parser = new VoCaApInfoFileParser(IGTF_WLCG_VO_CA_AP_FILE, repo);
    AuthenticationProfilePolicySetRepository policySetRepo =
        new DefaultAuthenticationProfilePolicySetRepository(parser);
    
    pdp = new DefaultAuthenticationProfilePDP(repo, policySetRepo);
  }

  @Test(expected = NullPointerException.class)
  public void testNullX500PrincipalFailure() {
    String principal = null;
    try {
      pdp.isCaAllowed(principal);
    } catch (NullPointerException e) {
      Assert.assertThat(e.getMessage(),
          Matchers.equalTo("Please provide a non-null caSubject argument"));
      throw e;
    }
  }

  @Test(expected = NullPointerException.class)
  public void testNullVoArgumentFailure() {
    String principal = opensslDnToRFC2253(CLASSIC_CA);
    try {
      pdp.isCaAllowedForVO(principal, null);
    } catch (NullPointerException e) {
      assertThat(e.getMessage(), equalTo("Please provide a non-null vo name"));
      throw e;
    }
  }

  public void assertCaAcceptableForLhcVos(String caSubject, String profile) {
    String principal = opensslDnToRFC2253(caSubject);
    for (String lhcVo : LHC_VOS) {
      Decision d = pdp.isCaAllowedForVO(principal, lhcVo);
      assertThat(d.isAllowed(), equalTo(true));
      assertThat(d.getPrincipal(), equalTo(principal));
      assertThat(d.getProfile().getAlias(), equalTo(profile));
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
    String iotaCaPrincipal = opensslDnToRFC2253(IOTA_CA);

    assertEquals(pdp.isCaAllowedForVO(iotaCaPrincipal, TEST_VO).isAllowed(), false);

  }

  @Test
  public void testIOTACaNotAcceptableForPlainCertificateAccess() {
    String iotaCaPrincipal = opensslDnToRFC2253(IOTA_CA);

    assertEquals(pdp.isCaAllowed(iotaCaPrincipal).isAllowed(), false);
    
  }

  @Test(expected = AuthenticationProfileError.class)
  public void testUnaccreditedCa() {
    String unaccreditedCA = opensslDnToRFC2253(UNACCREDITED_CA);
    pdp.isCaAllowedForVO(unaccreditedCA, "atlas");
  }
}

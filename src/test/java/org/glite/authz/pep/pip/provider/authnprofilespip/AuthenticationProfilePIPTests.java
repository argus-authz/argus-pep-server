package org.glite.authz.pep.pip.provider.authnprofilespip;

import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

import java.util.Set;

import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Request;
import org.glite.authz.pep.pip.PIPProcessingException;
import org.glite.authz.pep.pip.PolicyInformationPoint;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class AuthenticationProfilePIPTests extends TestSupport
    implements AuthenticationProfilePIPConstants {

  private PolicyInformationPoint pip;

  @Before
  public void setup() throws Exception {

    AuthenticationProfilePDP pdp = new DefaultAuthenticationProfilePDP.Builder()
      .authenticationPolicyFile(IGTF_WLCG_VO_CA_AP_FILE)
      .trustAnchorsDir(TRUST_ANCHORS_DIR)
      .policyFilePattern(IGTF_PROFILES_FILTER)
      .build();

    pip = new AuthenticationProfilePIP(pdp);
    pip.start();
  }

  @After
  public void teardown() throws Exception {

    if (pip != null) {
      pip.stop();
    }
  }

  @Test
  public void testVOWithSupportedProfile() throws PIPProcessingException {

    Request request = createRequest(CLASSIC_DN, CLASSIC_CA, "atlas");
    assertEquals(pip.populateRequest(request), true);
    assertThat(requestSubjectAttributes(request), containsAuthnProfileAttr(IGTF_CLASSIC));

  }
 

  @Test
  public void testVOWithNotSupportedProfile() throws PIPProcessingException {

    Request request = createRequest(IOTA_DN, IOTA_CA, TEST_VO);
    assertEquals(pip.populateRequest(request), true);

    Set<Attribute> subjectAttributes = requestSubjectAttributes(request);

    assertThat(subjectAttributes, not(containsVoAttrs()));
    assertThat(subjectAttributes, not(containsSubjectAttrs()));
  }
  
  @Test
   public void testPlainCertWithSupportedProfile() throws PIPProcessingException, IllegalStateException {
     Request request = createRequest(CLASSIC_DN, CLASSIC_CA);
     assertEquals(pip.populateRequest(request), true);
     assertThat(requestSubjectAttributes(request), containsAuthnProfileAttr(IGTF_CLASSIC));
   }
  
  
  @Test
  public void testRequestWithoutXACMLSubject() throws PIPProcessingException, IllegalStateException {
    Request request = new Request();
    assertEquals(pip.populateRequest(request), false);
  }

}

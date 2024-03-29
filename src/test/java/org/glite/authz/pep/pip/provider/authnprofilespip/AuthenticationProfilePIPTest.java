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

public class AuthenticationProfilePIPTest extends TestSupport
    implements AuthenticationProfilePIPConstants {

  private PolicyInformationPoint pip;

  @Before
  public void setup() throws Exception {

    AuthenticationProfilePDP pdp = new DefaultAuthenticationProfilePDP.Builder()
      .authenticationPolicyFile(IGTF_WLCG_VO_CA_AP_FILE)
      .trustAnchorsDir(TRUST_ANCHORS_DIR)
      .policyFilePattern(IGTF_PROFILES_FILTER)
      .build();

    pip = new AuthenticationProfilePIP("test",pdp);
    pip.start();
  }

  @After
  public void teardown() throws Exception {

    if (pip != null) {
      pip.stop();
    }
  }

  @Test
  public void testDciSecVOWithSupportedProfile() throws PIPProcessingException {

    Request request = createDciSecRequest(CLASSIC_DN, CLASSIC_CA, "atlas");
    assertEquals(pip.populateRequest(request), true);
    assertThat(requestSubjectAttributes(request), containsAuthnProfileAttr(IGTF_CLASSIC));

  }
  
  @Test
  public void testGliteVOWithSupportedProfile() throws PIPProcessingException {

    Request request = createGliteRequest(CLASSIC_DN, CLASSIC_CA, "atlas");
    assertEquals(pip.populateRequest(request), true);
    assertThat(requestSubjectAttributes(request), containsAuthnProfileAttr(IGTF_CLASSIC));

  }
 

  @Test
  public void testDciSecVOWithUnsupportedProfile() throws PIPProcessingException {

    Request request = createDciSecRequest(IOTA_DN, IOTA_CA, TEST_VO);
    assertEquals(pip.populateRequest(request), true);

    Set<Attribute> subjectAttributes = requestSubjectAttributes(request);

    assertThat(subjectAttributes, not(containsVoAttrs()));
    assertThat(subjectAttributes, not(containsSubjectAttrs()));
  }
  
  @Test
  public void testGliteVOWithUnsupportedProfile() throws PIPProcessingException {

    Request request = createGliteRequest(IOTA_DN, IOTA_CA, TEST_VO);
    assertEquals(pip.populateRequest(request), true);

    Set<Attribute> subjectAttributes = requestSubjectAttributes(request);

    assertThat(subjectAttributes, not(containsVoAttrs()));
    assertThat(subjectAttributes, not(containsSubjectAttrs()));
  }
  
  @Test
   public void testDciSecPlainCertWithSupportedProfile() throws PIPProcessingException, IllegalStateException {
     Request request = createDciSecRequest(CLASSIC_DN, CLASSIC_CA);
     assertEquals(pip.populateRequest(request), true);
     assertThat(requestSubjectAttributes(request), containsAuthnProfileAttr(IGTF_CLASSIC));
   }
  
  @Test
  public void testGlitePlainCertWithSupportedProfile() throws PIPProcessingException, IllegalStateException {
    Request request = createGliteRequest(CLASSIC_DN, CLASSIC_CA);
    assertEquals(pip.populateRequest(request), true);
    assertThat(requestSubjectAttributes(request), containsAuthnProfileAttr(IGTF_CLASSIC));
  }
  
  
  @Test
  public void testRequestWithoutXACMLSubject() throws PIPProcessingException, IllegalStateException {
    Request request = new Request();
    assertEquals(pip.populateRequest(request), false);
  }

  @Test
  public void testRequestWithNullEnvironment() throws PIPProcessingException, IllegalStateException {
    Request request = createRequestWithNullEnvironment(CLASSIC_DN, CLASSIC_CA);
    assertEquals(pip.populateRequest(request), true);
    assertThat(requestSubjectAttributes(request), containsAuthnProfileAttr(IGTF_CLASSIC));
  }
  
  @Test
  public void testRequestWithUnknownProfileAndGliteAttrs() throws PIPProcessingException, IllegalStateException {
    Request request = createUnknownProfileWithGliteAttrsRequest(CLASSIC_DN, CLASSIC_CA, TEST_VO);
    assertEquals(pip.populateRequest(request), true);
    assertThat(requestSubjectAttributes(request), containsAuthnProfileAttr(IGTF_CLASSIC));
  }
}

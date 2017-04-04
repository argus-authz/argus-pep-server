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

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;

public class AuthenticationProfilePolicyReloadTest extends TestSupport {

  private AuthenticationProfileRepository profileRepo;
  private AuthenticationProfilePolicySetRepository policySetRepo;

  private AuthenticationProfilePDP pdp;

  private Path tempVoCaApFile;
  private Path tempTrustAnchorsDir;

  @Before
  public void setup() throws IOException {

    tempVoCaApFile = Files.createTempFile("temp-vo-ca-ap", null);
    tempTrustAnchorsDir = Files.createTempDirectory("temp-trust-anchors-dir");

    Files.copy(Paths.get(IGTF_WLCG_VO_CA_AP_FILE), tempVoCaApFile, REPLACE_EXISTING);
    
    for (String f : AUTHN_PROFILE_IGTF_FILES) {
      
      Path sourceFile = Paths.get(f);
      
      Files.copy(Paths.get(f), tempTrustAnchorsDir.resolve(sourceFile.getFileName()));
    }

    profileRepo = new TrustAnchorsDirectoryAuthenticationProfileRepository(
        tempTrustAnchorsDir.toString(), ALL_POLICIES_FILTER);

    VoCaApInfoFileParser parser = new VoCaApInfoFileParser(tempVoCaApFile.toString(), profileRepo);

    policySetRepo = new DefaultAuthenticationProfilePolicySetRepository(parser);

    pdp = new DefaultAuthenticationProfilePDP(profileRepo, policySetRepo);
  }

  @Test
  public void testVoCaApPolicyChangesAreVisible() throws IOException {

    Decision d = pdp.isCaAllowedForVO(opensslDnToRFC2253(IOTA_CA), "atlas");
    assertThat(d.isAllowed(), equalTo(true));

    Files.copy(Paths.get(IGTF_WLCG_VO_CA_AP_NO_IOTA_FILE), tempVoCaApFile, REPLACE_EXISTING);

    policySetRepo.reloadRepositoryContents();
    d = pdp.isCaAllowedForVO(opensslDnToRFC2253(IOTA_CA), "atlas");
    assertThat(d.isAllowed(), equalTo(false));
  }
  
  @Test(expected=AuthenticationProfileError.class)
  public void testAuthnProfilePolicyChangesAreVisible() throws IOException {

    
    Decision d = pdp.isCaAllowedForVO(opensslDnToRFC2253(IOTA_CA), "atlas");
    assertThat(d.isAllowed(), equalTo(true));
    
    Path newIotaProfile = Paths.get(AUTHN_PROFILE_IOTA_NO_CERN_FILE);
    Files.copy(newIotaProfile, tempTrustAnchorsDir.resolve(newIotaProfile.getFileName()), 
        REPLACE_EXISTING);
    
    profileRepo.reloadRepositoryContents();
    
    try{
      d = pdp.isCaAllowedForVO(opensslDnToRFC2253(IOTA_CA), "atlas");
    }catch (AuthenticationProfileError e) {
      assertThat(e.getMessage(), Matchers.startsWith("No authentication profile found"));
      throw e;
    }
    
  }
}

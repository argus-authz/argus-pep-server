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

import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

import org.glite.authz.pep.pip.provider.authnprofilespip.error.InvalidConfigurationError;
import org.glite.authz.pep.pip.provider.authnprofilespip.error.ParseError;
import org.junit.Before;
import org.junit.Test;



public class VoCaApParserTest extends TestSupport {

  private AuthenticationProfileRepository repo;

  @Before
  public void setup() {
    repo = new TrustAnchorsDirectoryAuthenticationProfileRepository(TRUST_ANCHORS_DIR, "policy-igtf-*.info");
  }

  @Test(expected = IllegalArgumentException.class)
  public void testParsingNonExistingFileRaisesException() {
    String filename = "/this/should/never/exist";

    VoCaApInfoFileParser parser = new VoCaApInfoFileParser(filename, repo);

    try {
      parser.build();
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), endsWith("does not exist"));
      throw e;
    }

    fail("Expected illegal argument exception not raised");
  }

  @Test(expected = IllegalArgumentException.class)
  public void testParsingDirectoryRaisesException() {
    String filename = "/tmp";
    VoCaApInfoFileParser parser = new VoCaApInfoFileParser(filename, repo);
    try {
      parser.build();
    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), endsWith("is not a regular file"));
      throw e;
    }
  }
  
  @Test(expected=InvalidConfigurationError.class)
  public void testInvalidFileEntryThrowsError(){
    VoCaApInfoFileParser parser = new VoCaApInfoFileParser(INVALID_FILE_ENTRY_FILE, 
        repo);
    try{
      parser.build();
    }catch(InvalidConfigurationError e){
      assertThat(e.getMessage(), startsWith("Authentication profile file not found"));
      throw e;
    }
    
  }

  @Test(expected=ParseError.class)
  public void testInvalidVoEntryFileThrowsError() {
    
    VoCaApInfoFileParser parser = new VoCaApInfoFileParser(INVALID_VO_KEY_FILE, 
        repo);
    try{
      parser.build();
    }catch(ParseError e){
      assertThat(e.getMessage(), startsWith("Unsupported key"));
      throw e;
    }
  }
  
  @Test(expected=IllegalArgumentException.class)
  public void testReadingUnreadableFileThrowsError() throws IOException {
    
    Path unreadablePath = createUnreadableTempFile();
    
    String unreadableFileName = unreadablePath.toString();
    
    VoCaApInfoFileParser parser = new VoCaApInfoFileParser(unreadableFileName, repo);
    try{
      parser.build();
    }catch(IllegalArgumentException e){
      assertThat(e.getMessage(), endsWith("not readable"));
      throw e;
    }
  }
  
  
  @Test
  public void testEmptyFileReturnsEmtpyInfo() throws IOException {

    VoCaApInfoFileParser parser = new VoCaApInfoFileParser(EMPTY_FILE, repo);

    AuthenticationProfilePolicySet info = parser.build();

    assertThat(info.getVoProfilePolicies().entrySet(), hasSize(0));
    assertFalse(info.getAnyVoProfilePolicy().isPresent());
    assertFalse(info.getAnyCertificateProfilePolicy().isPresent());
  }

  @Test
  public void testIgtfWlcgFileParsing() throws IOException {

    VoCaApInfoFileParser parser =
        new VoCaApInfoFileParser(IGTF_WLCG_VO_CA_AP_FILE, repo);

    AuthenticationProfilePolicySet info = parser.build();

    assertThat(info.getVoProfilePolicies().entrySet(), hasSize(4));
    assertTrue(info.getAnyVoProfilePolicy().isPresent());
    assertTrue(info.getAnyCertificateProfilePolicy().isPresent());

    String[] voNames = {"alice", "atlas", "cms", "lhcb"};

    for (String vo : voNames) {
      AuthenticationProfilePolicy policy = info.getVoProfilePolicies().get(vo);
      assertNotNull("Policy for vo " + vo + " was null!", policy);
      assertThat(policy.getSupportedProfiles(), hasSize(4));

      List<String> profileNames = profilesToAliases(policy.getSupportedProfiles());
      
      assertThat(profileNames, hasItems(IGTF_CLASSIC, IGTF_IOTA,
          IGTF_MICS, IGTF_SLCS));
    }

    AuthenticationProfilePolicy anyVo = info.getAnyVoProfilePolicy()
      .orElseThrow(() -> new AssertionError("Any VO policy expected but not found"));

    assertThat(anyVo.getSupportedProfiles(), hasSize(3));
    List<String> profileNames = profilesToAliases(anyVo.getSupportedProfiles());
    assertThat(profileNames,
        hasItems(IGTF_CLASSIC, IGTF_MICS, IGTF_SLCS));

    AuthenticationProfilePolicy anyCert = info.getAnyCertificateProfilePolicy()
      .orElseThrow(() -> new AssertionError("Any cert policy expected but not found"));

    assertThat(anyCert.getSupportedProfiles(), hasSize(3));
    profileNames = profilesToAliases(anyCert.getSupportedProfiles());
    assertThat(profileNames,
        hasItems(IGTF_CLASSIC, IGTF_MICS, IGTF_SLCS));

  }

  @Test(expected = ParseError.class)
  public void testParsingFileWithDnEntryFails() throws IOException {
    VoCaApInfoFileParser parser =
        new VoCaApInfoFileParser(UNSUPPORTED_DN_ENTRY_FILE, repo);

    try {
      parser.build();
    } catch (ParseError e) {
      assertThat(e.getMessage(), startsWith("Unrecognized VO-CA-AP policy"));
      throw e;
    }
  }
  
  
}

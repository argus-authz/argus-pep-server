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
import java.util.List;

import org.glite.authz.pep.pip.provider.authnprofilespip.error.ParseError;
import org.junit.Before;
import org.junit.Test;



public class VoCaApParserTests extends VoCaApParserTestSupport {


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
    fail("Expected illegal argument exception not raised");
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
      
      assertThat(profileNames, hasItems(IGTF_CLASSIC_PROFILE_NAME, IGTF_IOTA_PROFILE_NAME,
          IGTF_MICS_PROFILE_NAME, IGTF_SLCS_PROFILE_NAME));
    }

    AuthenticationProfilePolicy anyVo = info.getAnyVoProfilePolicy()
      .orElseThrow(() -> new AssertionError("Any VO policy expected but not found"));

    assertThat(anyVo.getSupportedProfiles(), hasSize(3));
    List<String> profileNames = profilesToAliases(anyVo.getSupportedProfiles());
    assertThat(profileNames,
        hasItems(IGTF_CLASSIC_PROFILE_NAME, IGTF_MICS_PROFILE_NAME, IGTF_SLCS_PROFILE_NAME));

    AuthenticationProfilePolicy anyCert = info.getAnyCertificateProfilePolicy()
      .orElseThrow(() -> new AssertionError("Any cert policy expected but not found"));

    assertThat(anyCert.getSupportedProfiles(), hasSize(3));
    profileNames = profilesToAliases(anyCert.getSupportedProfiles());
    assertThat(profileNames,
        hasItems(IGTF_CLASSIC_PROFILE_NAME, IGTF_MICS_PROFILE_NAME, IGTF_SLCS_PROFILE_NAME));

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

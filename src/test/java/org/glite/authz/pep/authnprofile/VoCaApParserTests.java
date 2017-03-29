package org.glite.authz.pep.authnprofile;

import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.List;
import java.util.regex.Matcher;

import org.glite.authz.pep.pip.provider.authnprofilespip.AuthenticationProfilePolicy;
import org.glite.authz.pep.pip.provider.authnprofilespip.PolicyInfoParser;
import org.glite.authz.pep.pip.provider.authnprofilespip.PolicyProfileInfo;
import org.glite.authz.pep.pip.provider.authnprofilespip.VoCaApInfo;
import org.glite.authz.pep.pip.provider.authnprofilespip.VoCaApInfoFileParser;
import org.junit.Before;
import org.junit.Test;



public class VoCaApParserTests extends VoCaApParserTestSupport {

  private PolicyInfoParser policyInfoParser;



  @Before
  public void setup() {
    policyInfoParser = mock(PolicyInfoParser.class);

    PolicyProfileInfo classic = igtfClassicProfile();
    when(policyInfoParser.parse("policy-igtf-classic.info")).thenReturn(classic);

    PolicyProfileInfo slcs = igtfSlcsProfile();

    when(policyInfoParser.parse("policy-igtf-slcs.info")).thenReturn(slcs);

    PolicyProfileInfo mics = igtfMicsProfile();

    when(policyInfoParser.parse("policy-igtf-mics.info")).thenReturn(mics);

    PolicyProfileInfo iota = igtfIotaProfile();

    when(policyInfoParser.parse("policy-igtf-iota.info")).thenReturn(iota);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testParsingNonExistingFileRaisesException() {
    String filename = "/this/should/never/exist";

    VoCaApInfoFileParser parser = new VoCaApInfoFileParser(filename, policyInfoParser);

    try {
      parser.parse();
    } catch (IOException e) {
      fail("Unexpected IOException raised: " + e.getMessage());

    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), endsWith("does not exist"));
      throw e;
    }

    fail("Expected illegal argument exception not raised");
  }

  @Test(expected = IllegalArgumentException.class)
  public void testParsingDirectoryRaisesException() {
    String filename = "/tmp";
    VoCaApInfoFileParser parser = new VoCaApInfoFileParser(filename, policyInfoParser);
    try {
      parser.parse();
    } catch (IOException e) {
      fail("Unexpected IOException raised: " + e.getMessage());

    } catch (IllegalArgumentException e) {
      assertThat(e.getMessage(), endsWith("is not a regular file"));
      throw e;
    }
    fail("Expected illegal argument exception not raised");
  }

  @Test
  public void testEmptyFileReturnsEmtpyInfo() throws IOException {

    VoCaApInfoFileParser parser = new VoCaApInfoFileParser(EMPTY_FILE, policyInfoParser);

    VoCaApInfo info = parser.parse();

    assertThat(info.getVoProfilePolicies().entrySet(), hasSize(0));
    assertFalse(info.getAnyVoProfilePolicy().isPresent());
    assertFalse(info.getAnyCertificateProfilePolicy().isPresent());
  }

  @Test
  public void testIgtfWlcgFileParsing() throws IOException {

    VoCaApInfoFileParser parser =
        new VoCaApInfoFileParser(IGTF_WLCG_VO_CA_AP_FILE, policyInfoParser);

    VoCaApInfo info = parser.parse();

    assertThat(info.getVoProfilePolicies().entrySet(), hasSize(4));
    assertTrue(info.getAnyVoProfilePolicy().isPresent());
    assertTrue(info.getAnyCertificateProfilePolicy().isPresent());

    String[] voNames = {"alice", "atlas", "cms", "lhcb"};

    for (String vo : voNames) {
      AuthenticationProfilePolicy policy = info.getVoProfilePolicies().get(vo);
      assertNotNull("Policy for vo " + vo + " was null!", policy);
      assertThat(policy.getRules(), hasSize(4));

      List<String> profileNames = profilesToAliases(policy.getRules());

      assertThat(profileNames, hasItems(IGTF_CLASSIC_PROFILE_NAME, IGTF_IOTA_PROFILE_NAME,
          IGTF_MICS_PROFILE_NAME, IGTF_SLCS_PROFILE_NAME));
    }

    AuthenticationProfilePolicy anyVo = info.getAnyVoProfilePolicy()
      .orElseThrow(() -> new AssertionError("Any VO policy expected but not found"));

    assertThat(anyVo.getRules(), hasSize(3));
    List<String> profileNames = profilesToAliases(anyVo.getRules());
    assertThat(profileNames,
        hasItems(IGTF_CLASSIC_PROFILE_NAME, IGTF_MICS_PROFILE_NAME, IGTF_SLCS_PROFILE_NAME));
    
    AuthenticationProfilePolicy anyCert = info.getAnyCertificateProfilePolicy()
        .orElseThrow(() -> new AssertionError("Any cert policy expected but not found"));
    
    assertThat(anyCert.getRules(), hasSize(3));
    profileNames = profilesToAliases(anyCert.getRules());
    assertThat(profileNames,
        hasItems(IGTF_CLASSIC_PROFILE_NAME, IGTF_MICS_PROFILE_NAME, IGTF_SLCS_PROFILE_NAME));

  }

  public void testRulePattern() {

    String[] validLines =
        {"   file:policy-egi-core.info, file:policy-egi-cam.info,file:policy-ciccio.info",
            "file:ciccio.info", "file:porenghi.info,file:camaghe.info,file:ciccio.info",
            "file:porenghi.info,\\", "file:porenghi.info,   \\"};

    String[] invalidLines = {"", "file:", "file:, file:caio.info", "file:porenghi.info \\"};

    for (String l : validLines) {
      Matcher m = VoCaApInfoFileParser.FILE_RULE_PATTERN.matcher(l);
      assertTrue(String.format("%s was not matched!", l), m.matches());

      for (int i = 0; i < m.groupCount(); i++) {
        System.out.format("%d: %s\n", i, m.group(i));
      }

    }

    for (String l : invalidLines) {
      Matcher m = VoCaApInfoFileParser.FILE_RULE_PATTERN.matcher(l);
      assertFalse(String.format("%s was matched!", l), m.matches());
    }
  }

}

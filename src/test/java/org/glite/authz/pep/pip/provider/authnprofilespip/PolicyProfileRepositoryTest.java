package org.glite.authz.pep.pip.provider.authnprofilespip;

import static eu.emi.security.authn.x509.impl.OpensslNameUtils.opensslToRfc2253;
import static java.lang.String.format;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.glite.authz.pep.pip.provider.authnprofilespip.DefaultPolicyInfoParser;
import org.glite.authz.pep.pip.provider.authnprofilespip.PolicyInfoParser;
import org.glite.authz.pep.pip.provider.authnprofilespip.PolicyProfileInfo;
import org.glite.authz.pep.pip.provider.authnprofilespip.PolicyProfileRepository;
import org.glite.authz.pep.pip.provider.authnprofilespip.TrustAnchorsPolicyProfileRepository;
import org.junit.Test;

public class PolicyProfileRepositoryTest {

  private static final String trustInfoDir = "src/test/resources/certificates";

  private PolicyInfoParser policyFileParser = new DefaultPolicyInfoParser();

  @Test
  public void readFromTrustInfoDirTest() throws IOException {

    PolicyProfileRepository repo = new TrustAnchorsPolicyProfileRepository(
      trustInfoDir);
    assertNotNull(repo);

    List<PolicyProfileInfo> profileList = repo.getPolicyProfiles();
    assertNotNull(profileList);
    assertEquals(5, profileList.size());
  }

  @Test
  public void readFromTrustInfoWithWrongPatternDirTest() throws IOException {

    String pattern = "wrong-*.txt";

    PolicyProfileRepository repo = new TrustAnchorsPolicyProfileRepository(
      trustInfoDir, pattern, policyFileParser);
    assertNotNull(repo);

    try {
      repo.getPolicyProfiles();
    } catch (Exception e) {
      assertThat(e, instanceOf(IllegalArgumentException.class));
      assertEquals(
        format("The pattern [%s] doesn't match any file into directory [%s]",
          pattern, trustInfoDir),
        e.getMessage());
    }
  }

  @Test
  public void readFromNotExistingDirTest() throws IOException {

    String wrongDir = "src/test/resources/wrong_directory";

    PolicyProfileRepository repo = new TrustAnchorsPolicyProfileRepository(
      wrongDir);
    assertNotNull(repo);

    try {
      repo.getPolicyProfiles();
    } catch (Exception e) {
      assertThat(e, instanceOf(IllegalArgumentException.class));
      assertEquals(format("Directory %s does not exist", wrongDir),
        e.getMessage());
    }
  }

  @Test
  public void readFromNotReadableDirTest() throws IOException {

    File temp = Files.createTempDirectory("temp-policy-profile")
      .toFile();
    temp.setReadable(false);

    PolicyProfileRepository repo = new TrustAnchorsPolicyProfileRepository(
      temp.getAbsolutePath());
    assertNotNull(repo);

    try {
      repo.getPolicyProfiles();
    } catch (Exception e) {
      assertThat(e, instanceOf(IllegalArgumentException.class));
      assertEquals(
        format("The directory %s is not readable", temp.getAbsolutePath()),
        e.getMessage());
    }
    temp.delete();
  }

  @Test
  public void readFromFileTest() throws IOException {

    File temp = Files.createTempFile("tempfile", ".txt")
      .toFile();

    PolicyProfileRepository repo = new TrustAnchorsPolicyProfileRepository(
      temp.getAbsolutePath());
    assertNotNull(repo);

    try {
      repo.getPolicyProfiles();
    } catch (Exception e) {
      assertThat(e, instanceOf(IllegalArgumentException.class));
      assertEquals(
        format("The path %s is not a directory", temp.getAbsolutePath()),
        e.getMessage());
    }
  }

  @Test
  public void readWithNullDirectory() throws IOException {

    PolicyProfileRepository repo = new TrustAnchorsPolicyProfileRepository(
      null);
    assertNotNull(repo);

    try {
      repo.getPolicyProfiles();
    } catch (Exception e) {
      assertThat(e, instanceOf(IllegalArgumentException.class));
      assertEquals("null value for property 'trustInfoDir'", e.getMessage());
    }
  }

  @Test
  public void readWithEmptyPattern() throws IOException {

    PolicyProfileRepository repo = new TrustAnchorsPolicyProfileRepository(
      trustInfoDir, "", null);
    assertNotNull(repo);

    try {
      repo.getPolicyProfiles();
    } catch (Exception e) {
      assertThat(e, instanceOf(IllegalArgumentException.class));
      assertEquals("null value for property 'policyFilePattern'",
        e.getMessage());
    }
  }

  @Test
  public void readWithNullParser() throws IOException {

    PolicyProfileRepository repo = new TrustAnchorsPolicyProfileRepository(
      trustInfoDir, "policy-*.info", null);
    assertNotNull(repo);

    try {
      repo.getPolicyProfiles();
    } catch (Exception e) {
      assertThat(e, instanceOf(IllegalArgumentException.class));
      assertEquals("null value for property 'policyFileParser'",
        e.getMessage());
    }
  }

  @Test
  @SuppressWarnings("deprecation")
  public void readSinglePolicyFileTest() throws IOException {

    String policyAlias = "policy-igtf-mics";
    String policyFile = policyAlias.concat(".info");

    PolicyProfileRepository repo = new TrustAnchorsPolicyProfileRepository(
      trustInfoDir, policyFile, policyFileParser);
    assertNotNull(repo);

    List<PolicyProfileInfo> profileList = repo.getPolicyProfiles();
    assertNotNull(profileList);
    assertEquals(1, profileList.size());

    PolicyProfileInfo profile = profileList.get(0);
    assertEquals(policyAlias, profile.getAlias());
    assertEquals(7, profile.getCASubjects()
      .size());

    X500Principal principal = new X500Principal(
      opensslToRfc2253("/C=JP/O=NII/OU=HPCI/CN=HPCI CA"));

    assertThat(profile.getCASubjects(), hasItem(principal));
  }

  @Test
  @SuppressWarnings("deprecation")
  public void readSinglePolicyFileWithDuplicateCATest() throws IOException {

    String policyAlias = "test-policy-double-ca";
    String policyFile = policyAlias.concat(".info");

    PolicyProfileRepository repo = new TrustAnchorsPolicyProfileRepository(
      trustInfoDir, policyFile, policyFileParser);
    assertNotNull(repo);

    List<PolicyProfileInfo> profileList = repo.getPolicyProfiles();
    assertNotNull(profileList);
    assertEquals(1, profileList.size());

    PolicyProfileInfo profile = profileList.get(0);
    assertEquals(policyAlias, profile.getAlias());
    assertEquals(2, profile.getCASubjects()
      .size());

    X500Principal firstCa = new X500Principal(
      opensslToRfc2253("/C=IT/L=Bologna/O=Policy Tester/CN=First CA"));
    assertThat(profile.getCASubjects(), hasItem(firstCa));

    X500Principal secondCa = new X500Principal(
      opensslToRfc2253("/C=IT/L=Bologna/O=Policy Tester/CN=Second CA"));
    assertThat(profile.getCASubjects(), hasItem(secondCa));
  }
}
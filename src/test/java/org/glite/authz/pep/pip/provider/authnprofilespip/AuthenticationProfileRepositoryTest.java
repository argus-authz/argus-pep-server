package org.glite.authz.pep.pip.provider.authnprofilespip;

import static eu.emi.security.authn.x509.impl.OpensslNameUtils.opensslToRfc2253;
import static java.lang.String.format;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.junit.Test;

public class AuthenticationProfileRepositoryTest {

  private static final String trustInfoDir = "src/test/resources/certificates";

  private AuthenticationProfileParser policyFileParser = new DefaultAuthenticationProfileParser();

  @Test
  public void readFromTrustInfoDirTest() throws IOException {

    AuthenticationProfileRepository repo = new TrustAnchorsDirectoryAuthenticationProfileRepository(trustInfoDir);
    assertNotNull(repo);

    List<AuthenticationProfile> profileList = repo.getAuthenticationProfiles();
    assertNotNull(profileList);
    assertEquals(6, profileList.size());
  }

  @Test(expected = IllegalArgumentException.class)
  public void readFromTrustInfoWithWrongPatternDirTest() throws IOException {

    String pattern = "wrong-*.txt";

    AuthenticationProfileRepository repo =
        new TrustAnchorsDirectoryAuthenticationProfileRepository(trustInfoDir, pattern, policyFileParser);
    assertNotNull(repo);

    try {
      repo.getAuthenticationProfiles();
    } catch (IllegalArgumentException e) {
      assertEquals(format("The pattern [%s] doesn't match any file into directory [%s]", pattern,
          trustInfoDir), e.getMessage());
      throw e;
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void readFromNotExistingDirTest() throws IOException {

    String wrongDir = "src/test/resources/wrong_directory";

    AuthenticationProfileRepository repo = new TrustAnchorsDirectoryAuthenticationProfileRepository(wrongDir);
    assertNotNull(repo);

    try {
      repo.getAuthenticationProfiles();
    } catch (IllegalArgumentException e) {

      assertEquals(format("Directory %s does not exist", wrongDir), e.getMessage());
      throw e;
    }
  }

  @Test(expected=IllegalArgumentException.class)
  public void readFromNotReadableDirTest() throws IOException {

    File temp = Files.createTempDirectory("temp-policy-profile").toFile();
    temp.setReadable(false);

    AuthenticationProfileRepository repo = new TrustAnchorsDirectoryAuthenticationProfileRepository(temp.getAbsolutePath());
    assertNotNull(repo);

    try {
      repo.getAuthenticationProfiles();
    } catch (Exception e) {
      
      assertEquals(format("The directory %s is not readable", temp.getAbsolutePath()),
          e.getMessage());
      throw e;
    }
    temp.delete();
  }

  @Test(expected = IllegalArgumentException.class)
  public void readFromFileTest() throws IOException {

    File temp = Files.createTempFile("tempfile", ".txt").toFile();

    AuthenticationProfileRepository repo = new TrustAnchorsDirectoryAuthenticationProfileRepository(temp.getAbsolutePath());
    assertNotNull(repo);

    try {
      repo.getAuthenticationProfiles();
    } catch (IllegalArgumentException e) {

      assertEquals(format("The path %s is not a directory", temp.getAbsolutePath()),
          e.getMessage());
      throw e;
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void readWithNullDirectory() throws IOException {

    AuthenticationProfileRepository repo = new TrustAnchorsDirectoryAuthenticationProfileRepository(null);
    assertNotNull(repo);

    try {
      repo.getAuthenticationProfiles();
    } catch (IllegalArgumentException e) {
      
      assertEquals("null value for property 'trustInfoDir'", e.getMessage());
      throw e;
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void readWithEmptyPattern() throws IOException {

    AuthenticationProfileRepository repo = new TrustAnchorsDirectoryAuthenticationProfileRepository(trustInfoDir, "", null);
    assertNotNull(repo);

    try {
      repo.getAuthenticationProfiles();
    } catch (IllegalArgumentException e) {
      assertEquals("null value for property 'policyFilePattern'", e.getMessage());
      throw e;
    }
  }

  @Test(expected=IllegalArgumentException.class)
  public void readWithNullParser() throws IOException {

    AuthenticationProfileRepository repo =
        new TrustAnchorsDirectoryAuthenticationProfileRepository(trustInfoDir, "policy-*.info", null);
    assertNotNull(repo);

    try {
      repo.getAuthenticationProfiles();
    } catch (IllegalArgumentException e) {
      
      assertEquals("null value for property 'policyFileParser'", e.getMessage());
      throw e;
    }
  }

  @Test
  @SuppressWarnings("deprecation")
  public void readSinglePolicyFileTest() throws IOException {

    String policyAlias = "policy-igtf-mics";
    String policyFile = policyAlias.concat(".info");

    AuthenticationProfileRepository repo =
        new TrustAnchorsDirectoryAuthenticationProfileRepository(trustInfoDir, policyFile, policyFileParser);
    assertNotNull(repo);

    List<AuthenticationProfile> profileList = repo.getAuthenticationProfiles();
    assertNotNull(profileList);
    assertEquals(1, profileList.size());

    AuthenticationProfile profile = profileList.get(0);
    assertEquals(policyAlias, profile.getAlias());
    assertEquals(7, profile.getCASubjects().size());

    X500Principal principal = new X500Principal(opensslToRfc2253("/C=JP/O=NII/OU=HPCI/CN=HPCI CA"));

    assertThat(profile.getCASubjects(), hasItem(principal));
  }

  @Test
  @SuppressWarnings("deprecation")
  public void readSinglePolicyFileWithDuplicateCATest() throws IOException {

    String policyAlias = "test-policy-double-ca";
    String policyFile = policyAlias.concat(".info");

    AuthenticationProfileRepository repo =
        new TrustAnchorsDirectoryAuthenticationProfileRepository(trustInfoDir, policyFile, policyFileParser);
    assertNotNull(repo);

    List<AuthenticationProfile> profileList = repo.getAuthenticationProfiles();
    assertNotNull(profileList);
    assertEquals(1, profileList.size());

    AuthenticationProfile profile = profileList.get(0);
    assertEquals(policyAlias, profile.getAlias());
    assertEquals(2, profile.getCASubjects().size());

    X500Principal firstCa =
        new X500Principal(opensslToRfc2253("/C=IT/L=Bologna/O=Policy Tester/CN=First CA"));
    assertThat(profile.getCASubjects(), hasItem(firstCa));

    X500Principal secondCa =
        new X500Principal(opensslToRfc2253("/C=IT/L=Bologna/O=Policy Tester/CN=Second CA"));
    assertThat(profile.getCASubjects(), hasItem(secondCa));
  }
}

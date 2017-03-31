package org.glite.authz.pep.pip.provider.authnprofilespip;

import static java.lang.String.format;
import static java.nio.file.Files.createTempFile;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

import java.io.File;
import java.nio.file.Files;

import org.glite.authz.pep.pip.provider.authnprofilespip.error.ParseError;
import org.junit.Test;

public class AuthenticationInfoParserTest {

  private static final String trustInfoDir = "src/test/resources/certificates";
  private AuthenticationProfileFileParser parser = new DefaultAuthenticationProfileFileParser();

  @Test
  public void parseRegularPolicyFile() {

    String filename = format("%s/%s", trustInfoDir, "policy-igtf-mics.info");

    AuthenticationProfile profile = parser.parse(filename);
    assertNotNull(profile);
    assertEquals("policy-igtf-mics", profile.getAlias());
  }

  @Test
  public void parseWithNotExistingPolicyFile() {

    String filename = format("%s/%s", trustInfoDir,
      "not-existing-policy-file.info");

    try {
      parser.parse(filename);
    } catch (Exception e) {
      assertThat(e, instanceOf(IllegalArgumentException.class));
      assertEquals(format("File %s does not exist", filename), e.getMessage());
    }
  }

  @Test
  public void parseWithNullPolicyFile() {

    String filename = null;

    try {
      parser.parse(filename);
    } catch (Exception e) {
      assertThat(e, instanceOf(IllegalArgumentException.class));
      assertEquals("null value for input file", e.getMessage());
    }
  }

  @Test
  public void parseWithNotRegularFilePolicyFile() throws Exception {

    File temp = Files.createTempDirectory("temp-policy-dir")
      .toFile();

    try {
      parser.parse(temp.getAbsolutePath());
    } catch (Exception e) {
      assertThat(e, instanceOf(IllegalArgumentException.class));
      assertEquals(
        format("File %s is not a regular file", temp.getAbsolutePath()),
        e.getMessage());
    }
  }

  @Test
  public void parseWithNotReadablePolicyFile() throws Exception {

    File temp = createTempFile("temp-policy", ".info").toFile();
    temp.setReadable(false);

    try {
      parser.parse(temp.getAbsolutePath());
    } catch (Exception e) {
      assertThat(e, instanceOf(IllegalArgumentException.class));
      assertEquals(format("File %s is not readable", temp.getAbsolutePath()),
        e.getMessage());
    }

    temp.delete();
  }

  @Test
  public void parsePolicyFileWithMissingAlias() {

    String filename = format("%s/%s", trustInfoDir,
      "bad-policy-missing-alias.info");

    try {
      parser.parse(filename);
    } catch (Exception e) {
      assertThat(e, instanceOf(ParseError.class));
      assertEquals("Missing value for 'alias' property", e.getMessage());
    }
  }

  @Test
  public void parsePolicyFileWithEmptyAlias() {

    String filename = format("%s/%s", trustInfoDir,
      "bad-policy-empty-alias.info");

    try {
      parser.parse(filename);
    } catch (Exception e) {
      assertThat(e, instanceOf(ParseError.class));
      assertEquals("Missing value for 'alias' property", e.getMessage());
    }
  }

  @Test
  public void parsePolicyFileWithMissingSubjectDn() {

    String filename = format("%s/%s", trustInfoDir,
      "bad-policy-missing-subjectdn.info");

    try {
      parser.parse(filename);
    } catch (Exception e) {
      assertThat(e, instanceOf(ParseError.class));
      assertEquals("Missing value for 'subjectdn' property", e.getMessage());
    }
  }

  @Test
  public void parsePolicyFileWithEmptySubjectDn() {

    String filename = format("%s/%s", trustInfoDir,
      "bad-policy-empty-subjectdn.info");

    try {
      parser.parse(filename);
    } catch (Exception e) {
      assertThat(e, instanceOf(ParseError.class));
      assertEquals("Missing value for 'subjectdn' property", e.getMessage());
    }
  }

}
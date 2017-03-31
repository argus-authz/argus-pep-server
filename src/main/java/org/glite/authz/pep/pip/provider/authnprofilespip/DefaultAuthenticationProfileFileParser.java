package org.glite.authz.pep.pip.provider.authnprofilespip;

import static java.lang.String.format;
import static org.glite.authz.pep.pip.provider.authnprofilespip.AuthenticationProfileUtils.convertCASubjects;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.glite.authz.pep.pip.provider.authnprofilespip.error.ParseError;

public class DefaultAuthenticationProfileFileParser implements AuthenticationProfileFileParser {

  public AuthenticationProfile parse(String policyFileName) {

    inputFileSanityChecks(policyFileName);

    Properties infoFile = new Properties();

    try {
      infoFile.load(new FileInputStream(policyFileName));
    } catch (IOException e) {
      throw new ParseError("Error reading policy file: " + e.getMessage(), e);
    }

    String alias = infoFile.getProperty("alias");

    if (alias == null || alias.isEmpty()) {
      throw new ParseError("Missing value for 'alias' property");
    }

    String subjectdn = infoFile.getProperty("subjectdn");

    if (subjectdn == null || subjectdn.isEmpty()) {
      throw new ParseError("Missing value for 'subjectdn' property");
    }

    Set<X500Principal> caSubjects = convertCASubjects(subjectdn);

    return new AuthenticationProfileImpl(alias, caSubjects);
  }

  private void inputFileSanityChecks(String inputFileName) {

    if (inputFileName == null || inputFileName.isEmpty()) {
      throw new IllegalArgumentException("null value for input file");
    }
    File input = new File(inputFileName);
    if (!input.exists()) {
      throw new IllegalArgumentException(
        format("File %s does not exist", inputFileName));
    }
    if (!input.isFile()) {
      throw new IllegalArgumentException(
        format("File %s is not a regular file", inputFileName));
    }
    if (!input.canRead()) {
      throw new IllegalArgumentException(
        format("File %s is not readable", inputFileName));
    }
  }
}
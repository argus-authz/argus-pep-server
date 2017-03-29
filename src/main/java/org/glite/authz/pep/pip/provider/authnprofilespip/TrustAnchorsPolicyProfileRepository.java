package org.glite.authz.pep.pip.provider.authnprofilespip;

import static java.lang.String.format;
import static java.nio.file.Files.newDirectoryStream;

import java.io.File;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.DirectoryStream.Filter;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class TrustAnchorsPolicyProfileRepository
  implements PolicyProfileRepository {

  private static final String DEFAULT_POLICY_FILE_PATTERN = "policy-*.info";

  private final String trustAnchorsDir;
  private final String policyFilePattern;
  private final PolicyInfoParser policyFileParser;

  public TrustAnchorsPolicyProfileRepository(String trustAnchorsDir,
    String policyFilePattern, PolicyInfoParser policyFileParser) {
    this.trustAnchorsDir = trustAnchorsDir;
    this.policyFilePattern = policyFilePattern;
    this.policyFileParser = policyFileParser;
  }

  public TrustAnchorsPolicyProfileRepository(String trustAnchorsDir) {
    this(trustAnchorsDir, DEFAULT_POLICY_FILE_PATTERN,
      new DefaultPolicyInfoParser());
  }

  public List<PolicyProfileInfo> getPolicyProfiles() {

    trustInfoDirSanityChecks();
    policyFilePatternSanityChecks();
    policyInfoParserSanityChecks();

    List<PolicyProfileInfo> list = new ArrayList<>();

    try {
      DirectoryStream<Path> stream = newDirectoryStream(
        Paths.get(trustAnchorsDir), getPolicyFileFilter());

      for (Path filepath : stream) {
        PolicyProfileInfo profile = policyFileParser.parse(filepath.toString());
        list.add(profile);
      }
    } catch (IOException e) {
      throw new IllegalArgumentException(
        "Error reading policy files: " + e.getMessage(), e);
    }

    if (list.isEmpty()) {
      throw new IllegalArgumentException(
        format("The pattern [%s] doesn't match any file into directory [%s]",
          policyFilePattern, trustAnchorsDir));
    }

    return list;
  }

  private Filter<Path> getPolicyFileFilter() {

    return new DirectoryStream.Filter<Path>() {

      public boolean accept(Path path) {

        return path.getFileName()
          .toString()
          .matches(policyFilePattern.replace(".", "\\.")
            .replace("*", ".*"));
      }
    };
  }

  private void trustInfoDirSanityChecks() {

    if (trustAnchorsDir == null || trustAnchorsDir.isEmpty()) {
      throw new IllegalArgumentException(
        "null value for property 'trustInfoDir'");
    }
    File dir = new File(trustAnchorsDir);
    if (!dir.exists()) {
      throw new IllegalArgumentException(
        format("Directory %s does not exist", trustAnchorsDir));
    }
    if (!dir.isDirectory()) {
      throw new IllegalArgumentException(
        format("The path %s is not a directory", trustAnchorsDir));
    }
    if (!dir.canRead()) {
      throw new IllegalArgumentException(
        format("The directory %s is not readable", trustAnchorsDir));
    }
  }

  private void policyFilePatternSanityChecks() {

    if (policyFilePattern == null || policyFilePattern.isEmpty()) {
      throw new IllegalArgumentException(
        "null value for property 'policyFilePattern'");
    }
  }

  private void policyInfoParserSanityChecks() {

    if (policyFileParser == null) {
      throw new IllegalArgumentException(
        "null value for property 'policyFileParser'");
    }
  }
}

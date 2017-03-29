package org.glite.authz.pep.pip.provider.authnprofilespip;

import static java.util.Objects.requireNonNull;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * 
 * 
 *
 */
public class VoCaApInfoFileParser implements VoCaApInfoParser {

  private static final Logger LOG = LoggerFactory.getLogger(VoCaApInfoFileParser.class);

  static final String ANY_CERT_STRING = "\"-\"";
  static final String ANY_VO_STRING = "/*";

  static final String VO_NAME_PATTERN_STRING = "^/([\\w][\\w.-]+)";
  public static final Pattern VO_NAME_PATTERN = Pattern.compile(VO_NAME_PATTERN_STRING);

  static final String FILE_RULE_PATTERN_STRING = "file:(([\\w-]+).info)";
  static final String DN_RULE_PATTERN_STRING = "\"([^\"]+)\"";

  public static final Pattern FILE_RULE_PATTERN = Pattern.compile(FILE_RULE_PATTERN_STRING);
  public static final Pattern DN_RULE_PATTERN = Pattern.compile(DN_RULE_PATTERN_STRING);

  final String filename;
  final PolicyInfoParser policyInfoParser;

  private VoCaApInfoImpl.Builder builder;
  private Properties properties;

  public VoCaApInfoFileParser(String filename, PolicyInfoParser policyInfoParser) {

    requireNonNull(policyInfoParser, "Please set a non-null policyInfoParser");
    requireNonNull(filename, "Please set a non-null filename");
    
    this.filename = filename;
    this.policyInfoParser = policyInfoParser;
  }

  void parseLine(String line) {

  }

  void fileSanityChecks(String filename) {
    Path p = Paths.get(filename);
    if (!Files.exists(p)) {
      throw new IllegalArgumentException(String.format("File '%s' does not exist", p));
    }
    if (!Files.isRegularFile(p)) {
      throw new IllegalArgumentException(String.format("File '%s' is not a regular file", p));
    }
    if (!Files.isReadable(p)) {
      throw new IllegalArgumentException(String.format("File '%s' is not readable", p));
    }
  }


  private Properties parseAsProperties() {
    Properties props = new Properties();

    try {
      FileInputStream fis = new FileInputStream(filename);
      props.load(fis);
      return props;
    } catch (FileNotFoundException e) {
      throw new IllegalArgumentException(e);

    } catch (IOException e) {

      String errorMsg = String.format("Error parsing '%s: %s", filename, e.getCause());
      LOG.error(errorMsg, e);

      throw new ParseError(errorMsg, e);
    }
  }

  private void keySanityCheck(String key) {

    if (!key.equals(ANY_CERT_STRING) && !key.equals(ANY_VO_STRING)) {
      Matcher voNameMacher = VO_NAME_PATTERN.matcher(key);
      if (!voNameMacher.matches()) {
        throw new ParseError("Unsupported key in VO-CA-AP file: " + key);
      }
    }
  }


  private List<String> parseInfoFileNames(String key) {

    List<String> infoFileNames = new ArrayList<>();

    String entry = properties.getProperty(key);
    String[] entries = entry.split("\\s*,\\s*");

    for (String e : entries) {
      Matcher m = FILE_RULE_PATTERN.matcher(e);
      if (m.matches()) {
        String infoFileName = m.group(1);
        infoFileNames.add(infoFileName);

      } else {
        throw new ParseError("Unrecognized VO-CA-AP policy: " + entry);
      }
    }

    return infoFileNames;
  }

  private PolicyProfileInfo parseInfoFile(String policyProfileInfoFile) {
    return policyInfoParser.parse(policyProfileInfoFile);
  }

  private void buildAnyCertPolicy() {

    List<PolicyProfileInfo> rules = parsePoliciesFromFiles(parseInfoFileNames(ANY_CERT_STRING));

    AuthenticationProfilePolicy policy = new AuthenticationProfilePolicyImpl(rules);

    builder.anyCertificatePolicy(policy);
  }

  private void buildAnyVoPolicy() {

    List<PolicyProfileInfo> rules = parsePoliciesFromFiles(parseInfoFileNames(ANY_VO_STRING));

    AuthenticationProfilePolicy policy = new AuthenticationProfilePolicyImpl(rules);

    builder.anyVoPolicy(policy);
  }


  private List<PolicyProfileInfo> parsePoliciesFromFiles(List<String> policyFileNames) {
    List<PolicyProfileInfo> policies = new ArrayList<>();
    for (String f : policyFileNames) {
      PolicyProfileInfo p = parseInfoFile(f);
      policies.add(p);
    }
    return policies;
  }

  
  private void buildNamedVoPolicy(String voKey) {

    List<PolicyProfileInfo> rules = parsePoliciesFromFiles(parseInfoFileNames(voKey));

    AuthenticationProfilePolicy policy = new AuthenticationProfilePolicyImpl(rules);

    builder.addVoPolicy(voKey.substring(1), policy);

  }


  @Override
  public VoCaApInfo parse() throws IOException {

    fileSanityChecks(filename);
    properties = parseAsProperties();
    builder = new VoCaApInfoImpl.Builder();

    boolean anyCertPolicySeen = false;
    boolean anyVoPolicySeen = false;

    for (String key : properties.stringPropertyNames()) {
      keySanityCheck(key);

      if (key.equals(ANY_CERT_STRING)) {
        if (anyCertPolicySeen) {
          throw new ParseError(String.format(
              "%s contains more than one rule targeting " + "any trusted certificate", filename));
        }
        buildAnyCertPolicy();
        anyCertPolicySeen = true;
      } else if (key.equals(ANY_VO_STRING)) {
        if (anyVoPolicySeen) {
          throw new ParseError(String
            .format("%s contains more than one rule targeting " + "any trusted vo", filename));
        }
        buildAnyVoPolicy();
        anyVoPolicySeen = true;
      } else {
        buildNamedVoPolicy(key);
      }
    }

    return builder.build();
  }
}

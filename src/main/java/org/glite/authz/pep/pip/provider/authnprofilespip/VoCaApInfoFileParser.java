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

import org.glite.authz.pep.pip.provider.authnprofilespip.error.InvalidConfigurationError;
import org.glite.authz.pep.pip.provider.authnprofilespip.error.ParseError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * 
 * An {@link AuthenticationProfilePolicySetParser} that can parse the vo-ca-ap syntax,
 * as defined in https://wiki.nikhef.nl/grid/Lcmaps-plugins-vo-ca-ap#vo-ca-ap-file.
 * 
 * This parser only supports "file:filename.info" entries, i.e. the syntax that allows
 * to specify CA DNs directly in the file is not supported.
 * 
 */
public class VoCaApInfoFileParser implements AuthenticationProfilePolicySetParser {

  private static final Logger LOG = LoggerFactory.getLogger(VoCaApInfoFileParser.class);

  static final String ANY_CERT_STRING = "\"-\"";
  static final String ANY_VO_STRING = "/*";

  static final String VO_NAME_PATTERN_STRING = "^/([\\w][\\w.-]+)";
  public static final Pattern VO_NAME_PATTERN = Pattern.compile(VO_NAME_PATTERN_STRING);

  static final String FILE_RULE_PATTERN_STRING = "file:(([\\w-]+).info)";
  static final String DN_RULE_PATTERN_STRING = "\"([^\"]+)\"";

  public static final Pattern FILE_RULE_PATTERN = Pattern.compile(FILE_RULE_PATTERN_STRING);

  final String filename;
  final AuthenticationProfileRepository repo;

  private AuthenticationProfilePolicySetImpl.Builder builder;
  private Properties properties;

  public VoCaApInfoFileParser(String filename, AuthenticationProfileRepository repo) {

    requireNonNull(repo, "Please set a non-null policy repository");
    requireNonNull(filename, "Please set a non-null filename");

    this.filename = filename;
    this.repo = repo;
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

  private void buildAnyCertPolicy() {

    List<AuthenticationProfile> rules = parseRulesFromFiles(parseInfoFileNames(ANY_CERT_STRING));

    AuthenticationProfilePolicy policy = new AuthenticationProfilePolicyImpl(rules);

    builder.anyCertificatePolicy(policy);
  }

  private void buildAnyVoPolicy() {

    List<AuthenticationProfile> rules = parseRulesFromFiles(parseInfoFileNames(ANY_VO_STRING));

    AuthenticationProfilePolicy policy = new AuthenticationProfilePolicyImpl(rules);

    builder.anyVoPolicy(policy);
  }


  private List<AuthenticationProfile> parseRulesFromFiles(List<String> policyFileNames) {
    List<AuthenticationProfile> rules = new ArrayList<>();
    
    for (String f : policyFileNames) {
      AuthenticationProfile p = repo.findProfileByFilename(f).orElseThrow(
          () -> new InvalidConfigurationError("Policy file not found: " + f));
      rules.add(p);
    }
    return rules;
  }


  private void buildNamedVoPolicy(String voKey) {

    List<AuthenticationProfile> rules = parseRulesFromFiles(parseInfoFileNames(voKey));

    AuthenticationProfilePolicy policy = new AuthenticationProfilePolicyImpl(rules);

    builder.addVoPolicy(voKey.substring(1), policy);

  }


  @Override
  public AuthenticationProfilePolicySet parse() throws IOException {

    fileSanityChecks(filename);
    properties = parseAsProperties();
    builder = new AuthenticationProfilePolicySetImpl.Builder();

    boolean anyCertPolicySeen = false;
    boolean anyVoPolicySeen = false;

    for (String key : properties.stringPropertyNames()) {
      keySanityCheck(key);

      if (key.equals(ANY_CERT_STRING)) {
        if (anyCertPolicySeen) {
          throw new ParseError(String
            .format("%s contains more than one rule targeting any trusted certificate", filename));
        }
        buildAnyCertPolicy();
        anyCertPolicySeen = true;
      } else if (key.equals(ANY_VO_STRING)) {
        if (anyVoPolicySeen) {
          throw new ParseError(
              String.format("%s contains more than one rule targeting any trusted vo", filename));
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

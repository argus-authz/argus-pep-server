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
 * An {@link AuthenticationProfilePolicySetBuilder} that can parse the vo-ca-ap syntax,
 * as defined in https://wiki.nikhef.nl/grid/Lcmaps-plugins-vo-ca-ap#vo-ca-ap-file.
 * 
 * This parser only supports "file:filename.info" entries, i.e. the syntax that allows
 * to specify CA DNs directly in the file is not supported.
 * 
 */
public class VoCaApInfoFileParser implements AuthenticationProfilePolicySetBuilder {

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

  private AuthenticationProfilePolicySetImpl.Builder policySetBuilder;
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

    policySetBuilder.anyCertificatePolicy(policy);
    
    LOG.debug("\"-\" -> {}", policy);
    
  }

  private void buildAnyVoPolicy() {

    List<AuthenticationProfile> rules = parseRulesFromFiles(parseInfoFileNames(ANY_VO_STRING));

    AuthenticationProfilePolicy policy = new AuthenticationProfilePolicyImpl(rules);

    policySetBuilder.anyVoPolicy(policy);
    
    LOG.debug("/* -> {}", policy);
  }


  private List<AuthenticationProfile> parseRulesFromFiles(List<String> policyFileNames) {
    List<AuthenticationProfile> rules = new ArrayList<>();
    
    for (String f : policyFileNames) {
      AuthenticationProfile p = repo.findProfileByFilename(f).orElseThrow(
          () -> new InvalidConfigurationError("Authentication profile file not found: " + f));
      rules.add(p);
    }
    return rules;
  }


  private void buildNamedVoPolicy(String voKey) {

    List<AuthenticationProfile> rules = parseRulesFromFiles(parseInfoFileNames(voKey));

    AuthenticationProfilePolicy policy = new AuthenticationProfilePolicyImpl(rules);

    policySetBuilder.addVoPolicy(voKey.substring(1), policy);
    
    LOG.debug("{} -> {}", voKey, policy);

  }


  @Override
  public AuthenticationProfilePolicySet build() {

    LOG.info("Loading vo-ca-ap policies from: {}", filename);
    fileSanityChecks(filename);
    properties = parseAsProperties();
    policySetBuilder = new AuthenticationProfilePolicySetImpl.Builder();

    for (String key : properties.stringPropertyNames()) {
      keySanityCheck(key);

      if (key.equals(ANY_CERT_STRING)) {    
        buildAnyCertPolicy();
      } else if (key.equals(ANY_VO_STRING)) {
        buildAnyVoPolicy();
      } else {
        buildNamedVoPolicy(key);
      }
    }

    return policySetBuilder.build();
  }
}

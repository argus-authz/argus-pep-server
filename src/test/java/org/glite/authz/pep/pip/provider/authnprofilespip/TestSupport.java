/*
 * Copyright (c) Members of the EGEE Collaboration. 2006-2010. See http://www.eu-egee.org/partners/
 * for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package org.glite.authz.pep.pip.provider.authnprofilespip;

import static eu.emi.security.authn.x509.impl.OpensslNameUtils.opensslToRfc2253;
import static java.util.Arrays.asList;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.DATATYPE_STRING;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.DATATYPE_X500_NAME;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_SUBJECT_ID;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_VIRTUAL_ORGANIZATION;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_X509_SUBJECT_ISSUER;
import static org.glite.authz.common.profile.GLiteAuthorizationProfileConstants.DATATYPE_FQAN;
import static org.glite.authz.common.profile.GLiteAuthorizationProfileConstants.GRID_CE_AUTHZ_V1_PROFILE_ID;
import static org.glite.authz.common.profile.GLiteAuthorizationProfileConstants.GRID_WN_AUTHZ_V1_PROFILE_ID;
import static org.glite.authz.common.profile.GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_FQAN;
import static org.glite.authz.common.profile.GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_PRIMARY_FQAN;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Environment;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants;
import org.glite.authz.common.profile.GLiteAuthorizationProfileConstants;
import org.glite.authz.pep.pip.provider.authnprofilespip.utils.ContainsAuthnProfileAttr;
import org.glite.authz.pep.pip.provider.authnprofilespip.utils.ContainsSubjectAttrs;
import org.glite.authz.pep.pip.provider.authnprofilespip.utils.ContainsVoAttrs;

import eu.emi.security.authn.x509.impl.OpensslNameUtils;

public abstract class TestSupport {

  public static final String TRUST_ANCHORS_DIR = "src/test/resources/certificates";

  public static final String IGTF_WLCG_VO_CA_AP_FILE =
      "src/test/resources/vo-ca-ap/igtf-wlcg-vo-ca-ap";

  public static final String IGTF_WLCG_VO_CA_AP_NO_IOTA_FILE =
      "src/test/resources/vo-ca-ap/igtf-wlcg-vo-ca-ap-no-iota";

  public static final String[] LHC_VOS = {"alice", "atlas", "cms", "lhcb"};

  public static final String TEST_VO = "test";

  public static final String IGTF_PROFILES_FILTER = "policy-igtf-*.info";
  public static final String ALL_POLICIES_FILTER = "policy-*.info";

  public static final String[] AUTHN_PROFILE_IGTF_FILES = {
      "src/test/resources/certificates/policy-igtf-classic.info",
      "src/test/resources/certificates/policy-igtf-iota.info",
      "src/test/resources/certificates/policy-igtf-mics.info",
      "src/test/resources/certificates/policy-igtf-slcs.info"
  };
  
  public static final String AUTHN_PROFILE_IOTA_NO_CERN_FILE =
      "src/test/resources/authn-profiles-iota-no-cern/policy-igtf-iota.info";

  public static final String IGTF_CLASSIC = "policy-igtf-classic";
  public static final String IGTF_MICS = "policy-igtf-mics";
  public static final String IGTF_SLCS = "policy-igtf-slcs";
  public static final String IGTF_IOTA = "policy-igtf-iota";

  public static final String CLASSIC_CA = "/C=IT/O=INFN/CN=INFN Certification Authority";
  public static final String CLASSIC_DN = "/C=IT/O=INFN/OU=Personal Certificate/CN=Test user";

  public static final String IOTA_CA = "/DC=ch/DC=cern/CN=CERN LCG IOTA Certification Authority";
  public static final String IOTA_DN = "/DC=ch/DC=cern/CN=Test user";

  public static final String SLCS_CA = "/C=DE/O=DFN-Verein/OU=DFN-PKI/CN=DFN SLCS-CA";
  public static final String SLCS_DN = "/C=DE/O=DFN-Verein/OU=DFN-PKI/CN=Test user";

  public static final String MICS_CA = "/C=NL/O=TERENA/CN=TERENA eScience Personal CA";
  public static final String MICS_DN = "/C=NL/O=TERENA/CN=Test user";

  public static final String UNACCREDITED_CA = "/C=IT/O=Whatever/CN=Lonesome CA";
  public static final String UNACCREDITED_DN = "/C=IT/O=Whatever/CN=Test user";

  public static final String EMPTY_FILE = "src/test/resources/vo-ca-ap/emptyFile";

  public static final String INVALID_FILE_ENTRY_FILE =
      "src/test/resources/vo-ca-ap/invalidFileEntryFile";

  public static final String INVALID_VO_KEY_FILE = "src/test/resources/vo-ca-ap/invalidVoKeyFile";

  public static final String UNSUPPORTED_DN_ENTRY_FILE =
      "src/test/resources/vo-ca-ap/unsupportedDnEntryFile";

  public static final String DUPLICATE_ANY_VO_RULE_FILE =
      "src/test/resources/vo-ca-ap/multipleAnyVoRuleFile";

  public static final String DUPLICATE_ANY_CERT_RULE_FILE =
      "src/test/resources/vo-ca-ap/multipleAnyCertRuleFile";

  public static final String UNKNOWN_PROFILE_ATTRIBUTE_ID = "unknown-profile-attribute-id";
  public static final String UNKNOWN_PROFILE_ID = "unknown-profile-1.0";

  protected List<String> profilesToAliases(Set<AuthenticationProfile> profiles) {
    List<String> profileNames =
        profiles.stream().map(p -> p.getAlias()).collect(Collectors.toList());
    return profileNames;
  }

  @SuppressWarnings("deprecation")
  public String opensslDnToRFC2253(String dn) {

    String rfc2253Dn = OpensslNameUtils.opensslToRfc2253(dn);
    return rfc2253Dn;
  }

  public Request createDciSecRequest(String subjectDn, String issuerDn) {
    return createDciSecRequest(subjectDn, issuerDn, null);
  }

  public void addUnknownProfileIdToRequest(Request request) {
    Attribute profileIdAttr = createSingleStringValueAttribute(UNKNOWN_PROFILE_ATTRIBUTE_ID,
        DATATYPE_STRING, UNKNOWN_PROFILE_ID);

    request.getEnvironment().getAttributes().add(profileIdAttr);
  }

  public void addGliteCEProfileIdToRequest(Request request) {

    Attribute profileIdAttr =
        createSingleStringValueAttribute(GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_PROFILE_ID,
            DATATYPE_STRING, GRID_CE_AUTHZ_V1_PROFILE_ID);

    request.getEnvironment().getAttributes().add(profileIdAttr);
  }

  public void addGliteWNProfileIdToRequest(Request request) {

    Attribute profileIdAttr =
        createSingleStringValueAttribute(GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_PROFILE_ID,
            DATATYPE_STRING, GRID_WN_AUTHZ_V1_PROFILE_ID);

    request.getEnvironment().getAttributes().add(profileIdAttr);
  }

  public void addDciSecProfileIdToRequest(Request request) {
    Attribute profileIdAttr = createSingleStringValueAttribute(
        CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_PROFILE_ID, DATATYPE_STRING,
        CommonXACMLAuthorizationProfileConstants.COMMON_XACML_AUTHZ_V1_1_PROFILE_ID);

    request.getEnvironment().getAttributes().add(profileIdAttr);
  }

  public Request createGliteRequest(String subjectDn, String issuerDn) {
    return createGliteRequest(subjectDn, issuerDn, null);
  }

  public Request createRequestWithNullEnvironment(String subjectDn, String issuerDn) {
    Request request = new Request();
    Subject subject = new Subject();

    Attribute subjectAttr = createGliteSubjectAttribute(subjectDn);
    subject.getAttributes().add(subjectAttr);
    Attribute issuerAttr = createGliteIssuerAttribute(issuerDn);
    subject.getAttributes().add(issuerAttr);

    request.getSubjects().add(subject);
    return request;
  }

  public Request createUnknownProfileWithGliteAttrsRequest(String subjectDn, String issuerDn,
      String voName) {
    Request request = new Request();

    Environment env = new Environment();
    request.setEnvironment(env);
    addUnknownProfileIdToRequest(request);

    Subject subject = new Subject();

    Attribute subjectAttr = createGliteSubjectAttribute(subjectDn);
    subject.getAttributes().add(subjectAttr);

    Attribute issuerAttr = createGliteIssuerAttribute(issuerDn);
    subject.getAttributes().add(issuerAttr);

    if (voName != null) {
      Attribute voAttr = createGliteVoAttribute(voName);
      Attribute pfqan = createGlitePrimaryFqanAttribute(voName);
      Attribute fqan = createGliteFqanAttribute(voName);

      subject.getAttributes().addAll(asList(voAttr, pfqan, fqan));
    }

    request.getSubjects().add(subject);
    return request;
  }

  public Request createGliteRequest(String subjectDn, String issuerDn, String voName) {
    Request request = new Request();

    Environment env = new Environment();
    request.setEnvironment(env);
    addGliteWNProfileIdToRequest(request);
    Subject subject = new Subject();

    Attribute subjectAttr = createGliteSubjectAttribute(subjectDn);
    subject.getAttributes().add(subjectAttr);

    Attribute issuerAttr = createGliteIssuerAttribute(issuerDn);
    subject.getAttributes().add(issuerAttr);

    if (voName != null) {
      Attribute voAttr = createGliteVoAttribute(voName);
      Attribute pfqan = createGlitePrimaryFqanAttribute(voName);
      Attribute fqan = createGliteFqanAttribute(voName);

      subject.getAttributes().addAll(asList(voAttr, pfqan, fqan));
    }

    request.getSubjects().add(subject);
    return request;
  }

  public Request createDciSecRequest(String subjectDn, String issuerDn, String voName) {

    Request request = new Request();

    Environment env = new Environment();
    request.setEnvironment(env);
    addDciSecProfileIdToRequest(request);

    Subject subject = new Subject();
    Attribute subjectAttr = createDciSecSubjectAttribute(subjectDn);
    subject.getAttributes().add(subjectAttr);

    Attribute issuerAttr = createDciSecIssuerAttribute(issuerDn);
    subject.getAttributes().add(issuerAttr);

    if (voName != null) {
      Attribute voAttr = createDciSecVoAttribute(voName);
      Attribute primaryGroupAttr = createDciSecPrimaryGroupAttribute(voName);
      Attribute groupAttr = createDciSecGroupAttribute(voName);

      subject.getAttributes().addAll(asList(voAttr, primaryGroupAttr, groupAttr));

    }

    request.getSubjects().add(subject);

    return request;
  }

  Attribute createDciSecVoAttribute(String voName) {

    return createSingleStringValueAttribute(ID_ATTRIBUTE_VIRTUAL_ORGANIZATION, DATATYPE_STRING,
        voName);
  }

  Attribute createGliteVoAttribute(String voName) {

    return createSingleStringValueAttribute(
        GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_VIRTUAL_ORGANIZATION, DATATYPE_STRING,
        voName);
  }

  Attribute createDciSecGroupAttribute(String voName) {

    return createSingleStringValueAttribute(
        CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_GROUP, DATATYPE_STRING, "/voName");
  }


  Attribute createDciSecPrimaryGroupAttribute(String voName) {

    return createSingleStringValueAttribute(
        CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_PRIMARY_GROUP, DATATYPE_STRING,
        "/voName");
  }

  Attribute createGlitePrimaryFqanAttribute(String voName) {

    return createSingleStringValueAttribute(ID_ATTRIBUTE_PRIMARY_FQAN, DATATYPE_FQAN, "/" + voName);
  }

  Attribute createGliteFqanAttribute(String voName) {

    return createSingleStringValueAttribute(ID_ATTRIBUTE_FQAN, DATATYPE_FQAN, "/" + voName);
  }


  @SuppressWarnings("deprecation")
  Attribute createDciSecIssuerAttribute(String issuer) {

    return createSingleStringValueAttribute(ID_ATTRIBUTE_X509_SUBJECT_ISSUER, DATATYPE_X500_NAME,
        opensslToRfc2253(issuer));
  }

  @SuppressWarnings("deprecation")
  Attribute createGliteIssuerAttribute(String issuer) {

    return createSingleStringValueAttribute(
        GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_X509_SUBJECT_ISSUER, DATATYPE_X500_NAME,
        opensslToRfc2253(issuer));
  }

  @SuppressWarnings("deprecation")
  Attribute createGliteSubjectAttribute(String subject) {
    return createSingleStringValueAttribute(
        GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_SUBJECT_ID, DATATYPE_X500_NAME,
        opensslToRfc2253(subject));
  }

  @SuppressWarnings("deprecation")
  Attribute createDciSecSubjectAttribute(String subject) {

    return createSingleStringValueAttribute(ID_ATTRIBUTE_SUBJECT_ID, DATATYPE_X500_NAME,
        opensslToRfc2253(subject));
  }


  Attribute createSingleStringValueAttribute(String id, String datatype, String value) {
    Attribute attr = new Attribute(id, datatype);
    attr.getValues().add(value);
    return attr;
  }

  Set<Attribute> requestSubjectAttributes(Request r) {
    return r.getSubjects().iterator().next().getAttributes();
  }

  public ContainsVoAttrs containsVoAttrs() {
    return new ContainsVoAttrs();
  }

  public ContainsSubjectAttrs containsSubjectAttrs() {
    return new ContainsSubjectAttrs();
  }

  public ContainsAuthnProfileAttr containsAuthnProfileAttr() {
    return new ContainsAuthnProfileAttr();
  }

  public ContainsAuthnProfileAttr containsAuthnProfileAttr(String value) {
    return new ContainsAuthnProfileAttr(value);
  }

  Path createUnreadableTempFile() throws IOException {
    Set<PosixFilePermission> perms = new HashSet<>();

    Path tempFilePath = Files.createTempFile("unreadable", null);

    Files.setPosixFilePermissions(tempFilePath, perms);

    return tempFilePath;
  }


}

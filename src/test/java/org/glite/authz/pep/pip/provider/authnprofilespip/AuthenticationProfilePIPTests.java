package org.glite.authz.pep.pip.provider.authnprofilespip;

import static eu.emi.security.authn.x509.impl.OpensslNameUtils.opensslToRfc2253;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.DATATYPE_STRING;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.DATATYPE_X500_NAME;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_SUBJECT_ID;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_VIRTUAL_ORGANIZATION;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_X509_SUBJECT_ISSUER;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;

import java.util.Set;

import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Subject;
import org.glite.authz.pep.pip.PIPProcessingException;
import org.glite.authz.pep.pip.PolicyInformationPoint;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class AuthenticationProfilePIPTests extends TestSupport
  implements AuthenticationProfilePIPConstants {

  private PolicyInformationPoint pip;

  @Before
  public void setup() throws Exception {

    AuthenticationProfilePDP pdp = new DefaultAuthenticationProfilePDP.Builder()
      .authenticationPolicyFile(IGTF_WLCG_VO_CA_AP_FILE)
      .trustAnchorsDir(TRUST_ANCHORS_DIR)
      .policyFilePattern(IGTF_PROFILES_FILTER)
      .build();

    pip = new AuthenticationProfilePIP(pdp);
    pip.start();
  }

  @After
  public void teardown() throws Exception {

    if (pip != null) {
      pip.stop();
    }
  }

  @Test
  public void testVOWithSupportedProfile() throws PIPProcessingException {

    Request request = createRequest(CLASSIC_DN, CLASSIC_CA, "atlas");

    boolean result = pip.populateRequest(request);
    assertThat(result, is(false));
  }

  @Test
  public void testVOWithNotSupportedProfile() throws PIPProcessingException {

    Request request = createRequest(CLASSIC_DN, IOTA_CA, TEST_VO);

    boolean result = pip.populateRequest(request);
    assertThat(result, is(true));

    Set<Attribute> attributes = request.getSubjects()
      .iterator()
      .next()
      .getAttributes();

    assertThat(attributes, not(hasItem(createVoAttribute(TEST_VO))));
    assertThat(attributes, hasItem(createIssuerAttribute(IOTA_CA)));
  }

  //
  // @Test
  // public void testPlainCertWithSupportedProfile() {
  //
  // }
  //
  // @Test
  // public void testPlainCertWithNotSupportedProfile() {
  //
  // }
  //
  // @Test
  // public void testRequestWithoutSubject() {
  //
  // }
  //
  // @Test
  // public void testRequestWithoutIssuer() {
  //
  // }

  private Request createRequest(String subjectDn, String issuerDn,
    String voName) {

    Request request = new Request();

    Subject subject = new Subject();
    Attribute subjectAttr = createSubjectAttribute(subjectDn);
    subject.getAttributes()
      .add(subjectAttr);

    Attribute issuerAttr = createIssuerAttribute(issuerDn);
    subject.getAttributes()
      .add(issuerAttr);

    Attribute voAttr = createVoAttribute(voName);
    subject.getAttributes()
      .add(voAttr);

    request.getSubjects()
      .add(subject);

    return request;
  }

  private Attribute createVoAttribute(String voName) {

    Attribute attr = new Attribute(ID_ATTRIBUTE_VIRTUAL_ORGANIZATION,
      DATATYPE_STRING);
    attr.getValues()
      .add(voName);

    return attr;
  }

  @SuppressWarnings("deprecation")
  private Attribute createIssuerAttribute(String issuer) {

    Attribute attr = new Attribute(ID_ATTRIBUTE_X509_SUBJECT_ISSUER,
      DATATYPE_X500_NAME);
    attr.getValues()
      .add(opensslToRfc2253(issuer));

    return attr;
  }

  @SuppressWarnings("deprecation")
  private Attribute createSubjectAttribute(String subject) {

    Attribute attr = new Attribute(ID_ATTRIBUTE_SUBJECT_ID, DATATYPE_X500_NAME);
    attr.getValues()
      .add(opensslToRfc2253(subject));

    return attr;
  }

}

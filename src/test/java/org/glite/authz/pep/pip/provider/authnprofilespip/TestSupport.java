package org.glite.authz.pep.pip.provider.authnprofilespip;

import static eu.emi.security.authn.x509.impl.OpensslNameUtils.opensslToRfc2253;
import static java.util.Arrays.asList;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.DATATYPE_STRING;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.DATATYPE_X500_NAME;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_SUBJECT_ID;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_VIRTUAL_ORGANIZATION;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_X509_SUBJECT_ISSUER;
import static org.glite.authz.common.profile.GLiteAuthorizationProfileConstants.DATATYPE_FQAN;
import static org.glite.authz.common.profile.GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_FQAN;
import static org.glite.authz.common.profile.GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_PRIMARY_FQAN;

import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Subject;
import org.glite.authz.pep.pip.provider.authnprofilespip.utils.ContainsAuthnProfileAttr;
import org.glite.authz.pep.pip.provider.authnprofilespip.utils.ContainsSubjectAttrs;
import org.glite.authz.pep.pip.provider.authnprofilespip.utils.ContainsVoAttrs;

import eu.emi.security.authn.x509.impl.OpensslNameUtils;

public abstract class TestSupport {

  public static final String TRUST_ANCHORS_DIR = "src/test/resources/certificates";
  public static final String IGTF_WLCG_VO_CA_AP_FILE =
      "src/test/resources/vo-ca-ap/igtf-wlcg-vo-ca-ap";

  public static final String[] LHC_VOS = {"alice", "atlas", "cms", "lhcb"};

  public static final String TEST_VO = "test";

  public static final String IGTF_PROFILES_FILTER = "policy-igtf-*.info";
  public static final String ALL_POLICIES_FILTER = "policy-*.info";

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

  public X500Principal opensslDnToX500Principal(String dn) {

    String rfc2253Dn = OpensslNameUtils.opensslToRfc2253(dn);
    X500Principal principal = new X500Principal(rfc2253Dn);
    return principal;
  }

  public Request createRequest(String subjectDn, String issuerDn) {
    return createRequest(subjectDn, issuerDn, null);
  }



  public Request createRequest(String subjectDn, String issuerDn, String voName) {

    Request request = new Request();

    Subject subject = new Subject();
    Attribute subjectAttr = createSubjectAttribute(subjectDn);
    subject.getAttributes().add(subjectAttr);

    Attribute issuerAttr = createIssuerAttribute(issuerDn);
    subject.getAttributes().add(issuerAttr);

    if (voName != null) {
      Attribute voAttr = createVoAttribute(voName);
      Attribute fqanAttr = createFqanAttribute(voName);
      Attribute pfqanAttr = createPrimaryFqanAttribute(voName);

      subject.getAttributes().addAll(asList(voAttr, fqanAttr, pfqanAttr));

    }

    request.getSubjects().add(subject);

    return request;
  }



  Attribute createVoAttribute(String voName) {

    return createSingleStringValueAttribute(ID_ATTRIBUTE_VIRTUAL_ORGANIZATION, DATATYPE_STRING,
        voName);
  }

  Attribute createPrimaryFqanAttribute(String voName) {

    return createSingleStringValueAttribute(ID_ATTRIBUTE_PRIMARY_FQAN, DATATYPE_FQAN, "/" + voName);
  }

  Attribute createFqanAttribute(String voName) {

    return createSingleStringValueAttribute(ID_ATTRIBUTE_FQAN, DATATYPE_FQAN, "/" + voName);
  }


  @SuppressWarnings("deprecation")
  Attribute createIssuerAttribute(String issuer) {

    return createSingleStringValueAttribute(ID_ATTRIBUTE_X509_SUBJECT_ISSUER, DATATYPE_X500_NAME,
        opensslToRfc2253(issuer));
  }


  @SuppressWarnings("deprecation")
  Attribute createSubjectAttribute(String subject) {

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

}

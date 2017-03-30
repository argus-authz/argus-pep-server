package org.glite.authz.pep.pip.provider.authnprofilespip;

import javax.security.auth.x500.X500Principal;

import eu.emi.security.authn.x509.impl.OpensslNameUtils;

public abstract class TestSupport {

  public static final String TRUST_ANCHORS_DIR = "src/test/resources/certificates";
  public static final String IGTF_WLCG_VO_CA_AP_FILE = "src/test/resources/vo-ca-ap/igtf-wlcg-vo-ca-ap";

  public static final String[] LHC_VOS = { "alice", "atlas", "cms", "lhcb" };

  public static final String TEST_VO = "test";

  public static final String IGTF_PROFILES_FILTER = "policy-igtf-*.info";
  public static final String ALL_POLICIES_FILTER = "policy-*.info";
  
  public static final String IGTF_CLASSIC = "policy-igtf-classic";
  public static final String IGTF_MICS = "policy-igtf-mics";
  public static final String IGTF_SLCS = "policy-igtf-slcs";
  public static final String IGTF_IOTA = "policy-igtf-iota";
  

  public static final String CLASSIC_CA = "/C=IT/O=INFN/CN=INFN Certification Authority";
  public static final String CLASSIC_DN = "/C=IT/O=INFN/OU=Personal Certificate/CN=User Tester";

  public static final String IOTA_CA = "/DC=ch/DC=cern/CN=CERN LCG IOTA Certification Authority";
  public static final String SLCS_CA = "/C=DE/O=DFN-Verein/OU=DFN-PKI/CN=DFN SLCS-CA";
  public static final String MICS_CA = "/C=NL/O=TERENA/CN=TERENA eScience Personal CA";

  public static final String UNACCREDITED_CA = "/C=IT/O=Whatever/CN=Lonesome CA";

  public X500Principal opensslDnToX500Principal(String dn) {

    String rfc2253Dn = OpensslNameUtils.opensslToRfc2253(dn);
    X500Principal principal = new X500Principal(rfc2253Dn);
    return principal;
  }
}

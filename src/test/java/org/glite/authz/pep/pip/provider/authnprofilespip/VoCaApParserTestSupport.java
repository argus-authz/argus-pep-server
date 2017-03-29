package org.glite.authz.pep.pip.provider.authnprofilespip;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.security.auth.x500.X500Principal;

import org.glite.authz.pep.pip.provider.authnprofilespip.AuthenticationProfile;

import eu.emi.security.authn.x509.impl.OpensslNameUtils;

public class VoCaApParserTestSupport {

  public static final String IGTF_CLASSIC_PROFILE_NAME = "policy-igtf-classic";
  public static final String IGTF_MICS_PROFILE_NAME = "policy-igtf-mics";
  public static final String IGTF_SLCS_PROFILE_NAME = "policy-igtf-slcs";
  public static final String IGTF_IOTA_PROFILE_NAME = "policy-igtf-iota";

  public static final String EMPTY_FILE = "src/test/resources/vo-ca-ap/emptyFile";
  public static final String TRUST_ANCHORS_DIR = "src/test/resources/certificates";
  
  public static final String IGTF_WLCG_VO_CA_AP_FILE =
      "src/test/resources/vo-ca-ap/igtf-wlcg-vo-ca-ap";
  
  public static final String UNSUPPORTED_DN_ENTRY_FILE =
      "src/test/resources/vo-ca-ap/unsupportedDnEntryFile";

  public static final String[] SOME_CLASSIC_DNS = {"/C=FR/O=CNRS/CN=GRID2-FR",
      "/DC=ORG/DC=SEE-GRID/CN=SEE-GRID CA 2013", "/C=RU/O=RDIG/CN=Russian Data-Intensive Grid CA",
      "/DC=cz/DC=cesnet-ca/O=CESNET CA/CN=CESNET CA Root",
      "/C=UK/O=eScienceCA/OU=Authority/CN=UK e-Science CA 2B", "/C=HR/O=edu/OU=srce/CN=SRCE CA",
      "/C=IR/O=IPM/O=IRAN-GRID/CN=IRAN-GRID CA",
      "/C=BM/O=QuoVadis Limited/OU=Issuing Certification Authority/CN=QuoVadis Grid ICA",
      "/C=PK/O=NCP/CN=PK-GRID-CA", "/C=BR/O=ANSP/OU=ANSPGrid CA/CN=ANSPGrid CA",
      "/C=TH/O=NECTEC/OU=GOC/CN=NECTEC GOC CA",
      "/DC=MY/DC=UPM/DC=MYIFAM/C=MY/O=MYIFAM/CN=Malaysian Identity Federation and Access Management",
      "/C=FR/O=CNRS/CN=CNRS2-Projets", "/C=MA/O=MaGrid/CN=MaGrid CA"};

  public static final String[] SOME_MICS_DNS =
      {"/C=GB/ST=Greater Manchester/L=Salford/O=Comodo CA Limited/CN=AAA Certificate Services",
          "/DC=org/DC=cilogon/C=US/O=CILogon/CN=CILogon Silver CA 1",
          "/C=NL/O=TERENA/CN=TERENA eScience Personal CA",
          "/C=NL/ST=Noord-Holland/L=Amsterdam/O=TERENA/CN=TERENA eScience Personal CA 2",
          "/C=US/ST=UT/L=Salt Lake City/O=The USERTRUST Network/OU=http://www.usertrust.com/CN=UTN-USERFirst-Client Authentication and Email",
          "/C=NL/ST=Noord-Holland/L=Amsterdam/O=TERENA/CN=TERENA eScience Personal CA 3",
          "/C=JP/O=NII/OU=HPCI/CN=HPCI CA"};

  public static final String[] SOME_SLCS_DNS =
      {"/C=US/O=National Center for Supercomputing Applications/OU=Certificate Authorities/CN=MyProxy CA 2013",
          "/C=DE/O=DFN-Verein/OU=DFN-PKI/CN=DFN SLCS-CA",
          "/C=US/O=Pittsburgh Supercomputing Center/CN=PSC MyProxy CA",
          "/DC=gov/DC=fnal/O=Fermilab/OU=Certificate Authorities/CN=Kerberized CA HSM",
          "/C=US/O=National Center for Supercomputing Applications/OU=Certificate Authorities/CN=Two Factor CA 2013",
          "/DC=net/DC=ES/OU=Certificate Authorities/CN=NERSC Online CA"};

  public static final String[] SOME_IOTA_DNS =
      {"/DC=eu/DC=rcauth/O=Certification Authorities/CN=Research and Collaboration Authentication Pilot G1 CA",
          "/DC=org/DC=cilogon/C=US/O=CILogon/CN=CILogon Basic CA 1",
          "/DC=ch/DC=cern/CN=CERN LCG IOTA Certification Authority"};

  private X500Principal opensslDnToX500Principal(String dn) {
    String rfc2253Dn = OpensslNameUtils.opensslToRfc2253(dn);
    X500Principal principal = new X500Principal(rfc2253Dn);
    return principal;
  }

  protected AuthenticationProfile buildProfile(String alias, String[] dns) {
    AuthenticationProfile profile = mock(AuthenticationProfile.class);

    Set<X500Principal> caDns = new HashSet<>();

    for (String dn : dns) {
      caDns.add(opensslDnToX500Principal(dn));
    }

    when(profile.getAlias()).thenReturn(alias);
    when(profile.getCASubjects()).thenReturn(caDns);

    return profile;
  }


  protected AuthenticationProfile igtfClassicProfile() {
    return buildProfile(IGTF_CLASSIC_PROFILE_NAME, SOME_CLASSIC_DNS);
  }

  protected AuthenticationProfile igtfMicsProfile() {
    return buildProfile(IGTF_MICS_PROFILE_NAME, SOME_MICS_DNS);
  }

  protected AuthenticationProfile igtfSlcsProfile() {
    return buildProfile(IGTF_SLCS_PROFILE_NAME, SOME_SLCS_DNS);
  }

  protected AuthenticationProfile igtfIotaProfile() {
    return buildProfile(IGTF_IOTA_PROFILE_NAME, SOME_IOTA_DNS);
  }

  protected List<String> profilesToAliases(Set<AuthenticationProfile> profiles){
    List<String> profileNames =
        profiles.stream().map(p -> p.getAlias()).collect(Collectors.toList());
    return profileNames;
  }
}

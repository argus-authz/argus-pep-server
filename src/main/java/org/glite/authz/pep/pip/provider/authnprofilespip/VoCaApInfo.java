package org.glite.authz.pep.pip.provider.authnprofilespip;

import java.util.List;

public interface VoCaApInfo {

  List<VomsApMapping> getVoMappings();
  PlainCertificateApMapping getPlainCertificateMapping();
  
}

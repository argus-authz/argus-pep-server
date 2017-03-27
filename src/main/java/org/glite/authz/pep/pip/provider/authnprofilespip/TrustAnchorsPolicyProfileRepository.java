package org.glite.authz.pep.pip.provider.authnprofilespip;

import java.util.List;

public class TrustAnchorsPolicyProfileRepository implements PolicyProfileRepository {

  private final String trustAnchorsDir;
  
  public TrustAnchorsPolicyProfileRepository(String trustAnchorsDir) {
    this.trustAnchorsDir = trustAnchorsDir;
  }
  
  public List<PolicyProfileInfo> getPolicyProfiles() {
    
    return null;
  }

}

package org.glite.authz.pep.pip.provider.authnprofilespip;

import java.util.List;

public interface PolicyProfileRepository {
  
  List<PolicyProfileInfo> getPolicyProfiles();

}

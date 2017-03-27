package org.glite.authz.pep.pip.provider.authnprofilespip;

import javax.security.auth.x500.X500Principal;

public interface PolicyProfileResolver {
  
  PolicyProfileInfo getPolicyProfile(X500Principal certificateSubject);
  
}

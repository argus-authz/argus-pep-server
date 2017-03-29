package org.glite.authz.pep.pip.provider.authnprofilespip;

import java.util.Optional;

import javax.security.auth.x500.X500Principal;

public interface PolicyProfileResolver {
  
  Optional<PolicyProfileInfo> getPolicyProfile(X500Principal certificateSubject);
  
}

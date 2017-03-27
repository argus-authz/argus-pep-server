package org.glite.authz.pep.pip.provider.authnprofilespip;

import java.util.Set;

import javax.security.auth.x500.X500Principal;

public interface PolicyProfileInfo {

  String getAlias();
  Set<X500Principal> getCASubjects();
  
}

package org.glite.authz.pep.pip.provider.authnprofilespip;

import java.util.Set;

import javax.security.auth.x500.X500Principal;

public class PolicyProfileInfoImpl implements PolicyProfileInfo {

  private final String alias;
  private final Set<X500Principal> caSubjects;

  public PolicyProfileInfoImpl(String alias, Set<X500Principal> caSubects) {
    this.alias = alias;
    this.caSubjects = caSubects;
  }

  public String getAlias() {

    return this.alias;
  }

  public Set<X500Principal> getCASubjects() {

    return this.caSubjects;
  }

}
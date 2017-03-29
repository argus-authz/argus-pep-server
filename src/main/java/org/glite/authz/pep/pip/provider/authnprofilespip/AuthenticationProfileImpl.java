package org.glite.authz.pep.pip.provider.authnprofilespip;

import java.util.Set;

import javax.security.auth.x500.X500Principal;

/**
 * 
 * A basic implementation for the {@link AuthenticationProfile} abstraction
 *
 */
public class AuthenticationProfileImpl implements AuthenticationProfile {

  private final String alias;
  private final Set<X500Principal> caSubjects;

  public AuthenticationProfileImpl(String alias, Set<X500Principal> caSubects) {
    this.alias = alias;
    this.caSubjects = caSubects;
  }

  public String getAlias() {

    return alias;
  }

  public Set<X500Principal> getCASubjects() {

    return caSubjects;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((alias == null) ? 0 : alias.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    AuthenticationProfileImpl other = (AuthenticationProfileImpl) obj;
    if (alias == null) {
      if (other.alias != null)
        return false;
    } else if (!alias.equals(other.alias))
      return false;
    return true;
  }
}

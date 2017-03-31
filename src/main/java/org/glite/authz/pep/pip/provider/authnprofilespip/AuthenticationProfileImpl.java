/*
 * Copyright (c) Members of the EGEE Collaboration. 2006-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

  @Override
  public String toString() {
    return "AuthenticationProfileImpl [alias=" + alias + "]";
  }
  
}

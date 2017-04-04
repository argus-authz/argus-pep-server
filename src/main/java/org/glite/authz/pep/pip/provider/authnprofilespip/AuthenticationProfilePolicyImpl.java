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

import static java.util.Objects.requireNonNull;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * 
 * A basic implementation for {@link AuthenticationProfilePolicy}
 *
 */
public class AuthenticationProfilePolicyImpl implements AuthenticationProfilePolicy {

  final Map<String, AuthenticationProfile> profileMap = new HashMap<>();

  public AuthenticationProfilePolicyImpl(List<AuthenticationProfile> rules) {
    requireNonNull(rules);
    rules.forEach(p -> profileMap.put(p.getAlias(), p));
  }

  @Override
  public Set<AuthenticationProfile> getSupportedProfiles() {
    return new HashSet<>(profileMap.values());
  }

  @Override
  public boolean supportsProfile(String profileAlias) {
    requireNonNull(profileAlias);
    return profileMap.containsKey(profileAlias);
  }

  @Override
  public boolean supportsProfile(AuthenticationProfile profile) {
    requireNonNull(profile);
    return supportsProfile(profile.getAlias());
  }

  @Override
  public Optional<AuthenticationProfile> supportsAtLeastOneProfile(
      Set<AuthenticationProfile> profiles) {

    return profiles.stream().filter(p -> supportsProfile(p)).findFirst();
    
  }

  @Override
  public String toString() {
    return profileMap.keySet().toString();
  }
  
}

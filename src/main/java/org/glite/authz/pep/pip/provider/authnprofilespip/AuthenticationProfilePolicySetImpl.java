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

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

public class AuthenticationProfilePolicySetImpl
    implements AuthenticationProfilePolicySet {

  private final Map<String, AuthenticationProfilePolicy> voProfilePolicies;

  private final AuthenticationProfilePolicy anyVoProfilePolicy;

  private final AuthenticationProfilePolicy anyCertificateProfilePolicy;

  private AuthenticationProfilePolicySetImpl(Builder builder) {
    voProfilePolicies = builder.voProfilePolicies;
    anyVoProfilePolicy = builder.anyVoProfilePolicy;
    anyCertificateProfilePolicy = builder.anyCertificateProfilePolicy;
  }


  @Override
  public Map<String, AuthenticationProfilePolicy> getVoProfilePolicies() {
    return voProfilePolicies;
  }

  @Override
  public Optional<AuthenticationProfilePolicy> getAnyVoProfilePolicy() {

    return Optional.ofNullable(anyVoProfilePolicy);

  }

  @Override
  public Optional<AuthenticationProfilePolicy> getAnyCertificateProfilePolicy() {
    return Optional.ofNullable(anyCertificateProfilePolicy);
  }

  public static class Builder {
    private Map<String, AuthenticationProfilePolicy> voProfilePolicies;
    private AuthenticationProfilePolicy anyVoProfilePolicy;
    private AuthenticationProfilePolicy anyCertificateProfilePolicy;

    public Builder() {
      voProfilePolicies = new LinkedHashMap<>();
    }

    public Builder addVoPolicy(String voName, AuthenticationProfilePolicy policy) {
      voProfilePolicies.put(voName, policy);
      return this;
    }

    public Builder anyVoPolicy(AuthenticationProfilePolicy policy) {
      this.anyVoProfilePolicy = policy;
      return this;
    }

    public Builder anyCertificatePolicy(AuthenticationProfilePolicy policy) {
      this.anyCertificateProfilePolicy = policy;
      return this;
    }

    public AuthenticationProfilePolicySet build() {
      return new AuthenticationProfilePolicySetImpl(this);
    }
  }
}

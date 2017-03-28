package org.glite.authz.pep.pip.provider.authnprofilespip;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

public class VoCaApInfoImpl implements VoCaApInfo {

  private final Map<String, AuthenticationProfilePolicy> voProfilePolicies;

  private final AuthenticationProfilePolicy anyVoProfilePolicy;

  private final AuthenticationProfilePolicy anyCertificateProfilePolicy;


  private VoCaApInfoImpl(Builder builder) {
    voProfilePolicies = builder.voProfilePolicies;
    anyVoProfilePolicy = builder.anyVoProfilePolicy;
    anyCertificateProfilePolicy = builder.anyCertificateProfilePolicy;
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

    public VoCaApInfo build() {
      return new VoCaApInfoImpl(this);
    }
  }


  @Override
  public Map<String, AuthenticationProfilePolicy> getVoProfilePolicies() {

    return voProfilePolicies;
  }

}

package org.glite.authz.pep.pip.provider.authnprofilespip;

import java.util.List;
import java.util.Optional;

import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DefaultPolicyProfileResolver implements PolicyProfileResolver {
  
  public static final Logger LOG = LoggerFactory.getLogger(DefaultPolicyProfileResolver.class);

  final PolicyProfileRepository repository;
  
  public DefaultPolicyProfileResolver(PolicyProfileRepository repo) {
    this.repository = repo;
  }
  
  public Optional<PolicyProfileInfo> getPolicyProfile(X500Principal certificateSubject) {
    
    List<PolicyProfileInfo> profiles = repository.getPolicyProfiles();
    
    for (PolicyProfileInfo p: profiles){
      if (p.getCASubjects().contains(certificateSubject)){
        return Optional.of(p);
      }
    }
    
    return Optional.empty();
  }

}

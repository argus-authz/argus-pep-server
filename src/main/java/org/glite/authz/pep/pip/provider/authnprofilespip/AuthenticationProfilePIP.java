package org.glite.authz.pep.pip.provider.authnprofilespip;

import javax.security.auth.x500.X500Principal;

import org.glite.authz.common.model.Request;
import org.glite.authz.pep.pip.PIPProcessingException;
import org.glite.authz.pep.pip.provider.AbstractPolicyInformationPoint;

public class AuthenticationProfilePIP extends AbstractPolicyInformationPoint{
  
  private final AuthenticationProfilePDP pdp;
  
  
  
  public AuthenticationProfilePIP(AuthenticationProfilePDP pdp) {
    this.pdp = pdp;
  }
  
  
  private X500Principal resolveSubjectIssuer(Request request){
    return null;
  }
  
  private String resolveVoName(Request request){
    
    return null;
  }
  
  private boolean enforceCertificateAuthenticationProfile(X500Principal principal){
    return false;
  }
  
  private boolean enforceVoAuthenticationProfile(X500Principal principal, String voName){
    return false;
  }
  
  
  @Override
  public boolean populateRequest(Request request)
      throws PIPProcessingException, IllegalStateException {
    
    X500Principal issuerPrincipal = resolveSubjectIssuer(request);
    
    if (issuerPrincipal == null){
      return false;
    }
    
    String voName = resolveVoName(request);
    
    boolean pipModifiedRequest = false;
    
    if (voName == null){
      pipModifiedRequest = enforceVoAuthenticationProfile(issuerPrincipal, voName);
    }
    
    if (pipModifiedRequest){
      enforceCertificateAuthenticationProfile(issuerPrincipal);
    }
    
    return pipModifiedRequest;
  }

}

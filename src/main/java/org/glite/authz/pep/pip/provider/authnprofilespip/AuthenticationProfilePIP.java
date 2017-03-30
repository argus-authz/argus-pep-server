package org.glite.authz.pep.pip.provider.authnprofilespip;

import static java.util.stream.Collectors.toList;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.util.Strings;
import org.glite.authz.pep.pip.PIPProcessingException;
import org.glite.authz.pep.pip.provider.AbstractPolicyInformationPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthenticationProfilePIP extends AbstractPolicyInformationPoint
    implements AuthenticationProfilePIPConstants {

  Attribute x509SubjectAttr = X509_SUBJECT;
  Attribute x509IssuerAttr = X509_ISSUER;
  Attribute voAttr = VIRTUAL_ORGANIZATION;
  Attribute x509AuthProfileAttr = X509_AUTHN_PROFILE;

  public static final Logger LOG = LoggerFactory.getLogger(AuthenticationProfilePIP.class);

  private final AuthenticationProfilePDP pdp;

  public AuthenticationProfilePIP(AuthenticationProfilePDP pdp) {
    this.pdp = pdp;
  }

  private boolean removeVoAttributesFromRequestSubject(Request r) {
    return removeAttributesFromRequestSubject(r, VO_ATTRS_IDS);
  }

  private boolean removeSubjectAttributesFromRequestSubject(Request r) {
    return removeAttributesFromRequestSubject(r, X509_SUBJECT_ATTRS_IDS);
  }


  private Attribute buildFromTemplate(Attribute attr, String value) {
    Attribute a = new Attribute();
    a.setId(attr.getId());
    a.setDataType(attr.getDataType());
    a.getValues().add(value);
    return a;
  }


  private void setAuthenticationProfileAttribute(Request request, Decision decision) {
    Attribute x509AuthnProfileAttr =
        buildFromTemplate(x509AuthProfileAttr, decision.getProfile().getAlias());

    LOG.debug("Setting authn profile attribute: {}", x509AuthnProfileAttr);
    
    request.getSubjects().iterator().next().getAttributes().add(x509AuthnProfileAttr);
  }



  private boolean removeAttributesFromRequestSubject(Request r, Set<String> toBeRemovedIds) {

    boolean requestModified = false;

    for (Subject s : r.getSubjects()) {
      List<Attribute> toBeRemoved = s.getAttributes()
        .stream()
        .filter(a -> toBeRemovedIds.contains(a.getId()))
        .collect(toList());

      if (!toBeRemoved.isEmpty()) {
        LOG.debug("Removing attributes from request subject: {}", toBeRemoved);
        requestModified = s.getAttributes().removeAll(toBeRemoved);
      }
    }

    return requestModified;
  }

  private Optional<Attribute> lookupAttribute(Set<Attribute> attr, Attribute template) {
    return attr.stream()
      .filter(a -> Strings.safeEquals(a.getId(), template.getId())
          && Strings.safeEquals(a.getDataType(), template.getDataType()))
      .findFirst();
  }

  private Optional<Attribute> findFirstSubjectAttribute(Request request, Attribute template) {

    Optional<Attribute> result = Optional.empty();

    for (Subject s : request.getSubjects()) {
      result = lookupAttribute(s.getAttributes(), template);

      if (result.isPresent()) {
        break;
      }
    }

    return result;
  }

  private Optional<X500Principal> resolveSubjectIssuer(Request request) {
    return findFirstSubjectAttribute(request, x509IssuerAttr).map(this::extractFirstValueAsString)
      .map(X500Principal::new);
  }


  private String extractFirstValueAsString(Attribute a) {
    if (a == null) {
      return null;
    }

    if (a.getValues().isEmpty()) {
      return null;
    }

    return (String) a.getValues().iterator().next();
  }

  private Optional<String> resolveVoName(Request request) {

    return findFirstSubjectAttribute(request, voAttr).map(this::extractFirstValueAsString);
  }


  private Decision enforceCertificateAuthenticationProfile(Request request,
      X500Principal principal) {

    Decision decision = pdp.isCaAllowed(principal);
    
    if (!decision.isAllowed()) {
      LOG.warn("CA '{}' does not belong to any allowed authentication profile", principal);
      removeSubjectAttributesFromRequestSubject(request);
    } else {
      LOG.debug("CA '{}' belongs to an allowed authentication profile: {}",
          principal, decision.getProfile().getAlias());
      setAuthenticationProfileAttribute(request, decision);
    }
    
    return decision;
  }

  private Decision enforceVoAuthenticationProfile(Request request, X500Principal principal,
      String voName) {

    Decision decision = pdp.isCaAllowedForVO(principal, voName);

    if (!decision.isAllowed()) {
      LOG.warn(
          "CA '{}' does not belong to any allowed authentication profiles for VO '{}'. VO attributes will be "
              + "removed from request",
          principal, voName);
      removeVoAttributesFromRequestSubject(request);

    } else {

      LOG.debug("CA '{}' belongs to a supported authentication profile for VO '{}': {}", principal,
          voName, decision.getProfile().getAlias());

      setAuthenticationProfileAttribute(request, decision);
    }
    
    return decision;
  }


  @Override
  public boolean populateRequest(Request request)
      throws PIPProcessingException, IllegalStateException {

    Optional<X500Principal> issuerPrincipal = resolveSubjectIssuer(request);

    if (!issuerPrincipal.isPresent()) {
      LOG.debug(
          "X509 issuer principal attribute '{}' NOT found in request. This PIP will leave the request "
              + "unmodified",
          x509IssuerAttr.getId());
      return false;
    }

    Optional<String> voName = resolveVoName(request);

    Decision decision = Decision.deny(issuerPrincipal.get());

    if (voName.isPresent()) {
      decision = enforceVoAuthenticationProfile(request, issuerPrincipal.get(), voName.get());
    } else {
      LOG.debug("Virtual organization name attribute '{}' NOT found in request",
          voAttr.getId());
    }

    // Do not fallback to plain certificate checks if we already have a permit
    if (decision.isAllowed()) {
      return true;
    }

    enforceCertificateAuthenticationProfile(request, issuerPrincipal.get());
    return true;
  }

}

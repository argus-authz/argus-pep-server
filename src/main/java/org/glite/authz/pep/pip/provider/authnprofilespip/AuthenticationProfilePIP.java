package org.glite.authz.pep.pip.provider.authnprofilespip;

import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.DATATYPE_STRING;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.DATATYPE_X500_NAME;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_SUBJECT_ID;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_VIRTUAL_ORGANIZATION;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_X509_SUBJECT_ISSUER;

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

public class AuthenticationProfilePIP extends AbstractPolicyInformationPoint {

  static final Attribute X509_SUBJECT = new Attribute(ID_ATTRIBUTE_SUBJECT_ID, DATATYPE_X500_NAME);

  static final Attribute X509_ISSUER =
      new Attribute(ID_ATTRIBUTE_X509_SUBJECT_ISSUER, DATATYPE_X500_NAME);

  static final Attribute VIRTUAL_ORGANIZATION =
      new Attribute(ID_ATTRIBUTE_VIRTUAL_ORGANIZATION, DATATYPE_STRING);

  Attribute x509SubjectAttr = X509_SUBJECT;
  Attribute x509IssuerAttr = X509_ISSUER;
  Attribute voAttr = VIRTUAL_ORGANIZATION;

  public static final Logger LOG = LoggerFactory.getLogger(AuthenticationProfilePIP.class);

  private final AuthenticationProfilePDP pdp;

  public AuthenticationProfilePIP(AuthenticationProfilePDP pdp) {
    this.pdp = pdp;
  }

  private Optional<Attribute> lookupAttribute(Set<Attribute> attr, Attribute template) {
    return attr.stream()
      .filter(a -> Strings.safeEquals(a.getId(), template.getId())
          && Strings.safeEquals(a.getDataType(), template.getDataType()))
      .findFirst();
  }

  private Optional<Attribute> findFirstSubjectAttribute(Request request, Attribute template) {

    Optional<Attribute> result;

    for (Subject s : request.getSubjects()) {
      result = lookupAttribute(s.getAttributes(), template);

      if (result.isPresent()) {
        return result;
      }
    }

    return Optional.empty();
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


  private boolean enforceCertificateAuthenticationProfile(X500Principal principal) {
    return false;
  }

  private boolean enforceVoAuthenticationProfile(X500Principal principal, String voName) {
    return false;
  }


  @Override
  public boolean populateRequest(Request request)
      throws PIPProcessingException, IllegalStateException {

    Optional<X500Principal> issuerPrincipal = resolveSubjectIssuer(request);

    if (!issuerPrincipal.isPresent()) {
      LOG.debug(
          "X509 issuer principal attribute {} not found in request. This PIP will leave the request unmodified",
          x509IssuerAttr);
      return false;
    }

    Optional<String> voName = resolveVoName(request);

    boolean pipModifiedRequest = false;

    if (voName.isPresent()) {
      pipModifiedRequest = enforceVoAuthenticationProfile(issuerPrincipal.get(), voName.get());
    }

    if (pipModifiedRequest) {
      enforceCertificateAuthenticationProfile(issuerPrincipal.get());
    }

    return pipModifiedRequest;
  }

}

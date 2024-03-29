/*
 * Copyright (c) Members of the EGEE Collaboration. 2006-2010. See http://www.eu-egee.org/partners/
 * for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package org.glite.authz.pep.pip.provider.authnprofilespip;

import static java.util.stream.Collectors.toList;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Environment;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants;
import org.glite.authz.common.profile.GLiteAuthorizationProfileConstants;
import org.glite.authz.common.util.Strings;
import org.glite.authz.pep.pip.PIPException;
import org.glite.authz.pep.pip.PIPProcessingException;
import org.glite.authz.pep.pip.provider.AbstractPolicyInformationPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This PIP must be configured to run after
 * {@link org.glite.authz.pep.pip.provider.CommonXACMLAuthorizationProfilePIP} or
 * {@link org.glite.authz.pep.pip.provider.GLiteAuthorizationProfilePIP}, as it expects certificate
 * and VOMS related attributes to be present in the request.
 * 
 * This PIP looks in the request subject attributes for the attribute containing subject of the CA
 * that issued the EEC contained in the request, and the attribute containing the VO name linked to
 * the request. This PIP supports the gLite and Common XACML authentication profiles, and their way
 * to encode the VO name and the subject issuer in the request.
 * 
 * If no attribute is found holding the CA subject, the PIP returns without modifying the request.
 * 
 * Otherwise, this PIP checks whether the included certificate subject and VOMS attributes are
 * allowed by local authentication profile policies via calls to an
 * {@link AuthenticationProfilePDP}.
 * 
 * If the policies are NOT met, subject and VOMS attributes are removed from the request.
 * 
 * If the policies are met, the
 * {@link org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants#ID_ATTRIBUTE_X509_AUTHN_PROFILE}
 * or
 * {@link org.glite.authz.common.profile.GLiteAuthorizationProfileConstants#ID_ATTRIBUTE_X509_AUTHN_PROFILE}
 * attribute is set, depending on the XACML profile of the request, is set containing the
 * authentication profile resolved for the request.
 * 
 */
public class AuthenticationProfilePIP extends AbstractPolicyInformationPoint
    implements AuthenticationProfilePIPConstants {

  public static final Logger LOG = LoggerFactory.getLogger(AuthenticationProfilePIP.class);

  private final AuthenticationProfilePDP pdp;

  enum XacmlProfile {
    UNKNOWN,
    GLITE_PROFILE,
    DCI_SEC_PROFILE
  }

  public AuthenticationProfilePIP(String pipId, AuthenticationProfilePDP pdp) {
    super(pipId);
    this.pdp = pdp;
  }

  private boolean removeVoAttributesFromRequestSubject(Request r) {
    return removeAttributesFromRequestSubject(r, VO_ATTRS_IDS);
  }

  private boolean removeSubjectAttributesFromRequestSubject(Request r) {
    return removeAttributesFromRequestSubject(r, X509_SUBJECT_ATTRS_IDS);
  }

  private Attribute buildAttributeFromTemplate(Attribute attr, String value) {
    Attribute a = new Attribute();
    a.setId(attr.getId());
    a.setDataType(attr.getDataType());
    a.getValues().add(value);
    return a;
  }

  protected XacmlProfile resolveXacmlProfile(Request request) {

    Environment env = request.getEnvironment();

    if (env == null) {
      return XacmlProfile.UNKNOWN;
    }

    if (env.getAttributes().stream().anyMatch(
        a -> a.getId().equals(CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_PROFILE_ID))) {
      return XacmlProfile.DCI_SEC_PROFILE;
    }

    if (env.getAttributes().stream().anyMatch(
        a -> a.getId().equals(GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_PROFILE_ID))) {
      return XacmlProfile.GLITE_PROFILE;
    }

    return XacmlProfile.UNKNOWN;

  }

  private void setAuthenticationProfileAttribute(Request request, Decision decision) {
    XacmlProfile profile = resolveXacmlProfile(request);

    Set<Attribute> toBeAdded = new HashSet<>();

    if (profile.equals(XacmlProfile.DCI_SEC_PROFILE)) {
      toBeAdded.add(
          buildAttributeFromTemplate(DCI_SEC_X509_AUTHN_PROFILE, decision.getProfile().getAlias()));
    } else if (profile.equals(XacmlProfile.GLITE_PROFILE)) {
      toBeAdded.add(
          buildAttributeFromTemplate(GLITE_X509_AUTHN_PROFILE, decision.getProfile().getAlias()));
    } else if (profile.equals(XacmlProfile.UNKNOWN)) {
      toBeAdded.add(
          buildAttributeFromTemplate(DCI_SEC_X509_AUTHN_PROFILE, decision.getProfile().getAlias()));
      toBeAdded.add(
          buildAttributeFromTemplate(GLITE_X509_AUTHN_PROFILE, decision.getProfile().getAlias()));
    }

    LOG.debug("Adding authentication profile attribute to request subject attributes: {}",
        toBeAdded);

    request.getSubjects().iterator().next().getAttributes().addAll(toBeAdded);
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

  private Optional<String> findSubjectVoName(Request request) {

    Optional<String> result = Optional.empty();
    for (Attribute attr : VO_NAME_ATTRS) {
      result = findFirstSubjectAttribute(request, attr).map(this::extractFirstValueAsString);
      if (result.isPresent()) {
        break;
      }
    }

    return result;
  }

  private Optional<String> findSubjectCertificateIssuer(Request request) {

    Optional<String> result = Optional.empty();

    for (Attribute attr : X509_ISSUER_ATTRS) {
      result = findFirstSubjectAttribute(request, attr).map(this::extractFirstValueAsString);

      if (result.isPresent()) {
        break;
      }
    }

    return result;
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



  private Decision enforceCertificateAuthenticationProfile(Request request, String caSubject) {

    Decision decision = pdp.isCaAllowed(caSubject);

    if (!decision.isAllowed()) {
      LOG.warn(
          "CA '{}' does not belong to any allowed authentication profile. X.509 subject attributes will be removed from request",
          caSubject);
      removeSubjectAttributesFromRequestSubject(request);
    } else {
      LOG.debug("CA '{}' belongs to an allowed authentication profile: {}", caSubject,
          decision.getProfile().getAlias());
      setAuthenticationProfileAttribute(request, decision);
    }

    return decision;
  }

  private Decision enforceVoAuthenticationProfile(Request request, String caSubject,
      String voName) {

    Decision decision = pdp.isCaAllowedForVO(caSubject, voName);

    if (!decision.isAllowed()) {
      LOG.warn(
          "CA '{}' does not belong to any allowed authentication profiles for VO '{}'. VO attributes will be "
              + "removed from request",
          caSubject, voName);
      removeVoAttributesFromRequestSubject(request);

    } else {

      LOG.debug("CA '{}' belongs to a supported authentication profile for VO '{}': {}", caSubject,
          voName, decision.getProfile().getAlias());

      setAuthenticationProfileAttribute(request, decision);
    }

    return decision;
  }


  @Override
  public boolean populateRequest(Request request)
      throws PIPProcessingException, IllegalStateException {

    Optional<String> issuerPrincipal = findSubjectCertificateIssuer(request);

    if (!issuerPrincipal.isPresent()) {
      LOG.debug("X509 issuer principal attribute in '{}' NOT found in request. This PIP will leave "
          + "the request unmodified", X509_ISSUER_ATTRS_IDS);
      return false;
    }

    Optional<String> voName = findSubjectVoName(request);

    Decision decision = Decision.deny(issuerPrincipal.get());

    if (voName.isPresent()) {
      decision = enforceVoAuthenticationProfile(request, issuerPrincipal.get(), voName.get());

      if (decision.isAllowed()) {
        return true;
      }
    } else {
      LOG.debug("Virtual organization name attribute in '{}' NOT found in request",
          VO_NAME_ATTRS_ID);
    }

    // If we reach this point, no VOMS-related attribute has been found in the request,
    // or the attributes have been removed due to a deny decision against VO policies
    enforceCertificateAuthenticationProfile(request, issuerPrincipal.get());
    return true;
  }


  @Override
  public void start() throws PIPException {
    pdp.start();
  }

  @Override
  public void stop() throws PIPException {
    pdp.stop();
  }

}

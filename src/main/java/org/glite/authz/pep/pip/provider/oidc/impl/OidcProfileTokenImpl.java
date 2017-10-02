package org.glite.authz.pep.pip.provider.oidc.impl;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.profile.OidcProfileConstants;
import org.glite.authz.oidc.client.model.TokenInfo;
import org.glite.authz.pep.pip.provider.oidc.OidcProfileToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OidcProfileTokenImpl implements OidcProfileToken {

  private static final Logger LOG = LoggerFactory
    .getLogger(OidcProfileTokenImpl.class);

  private final Set<String> oidcAttributes;

  public OidcProfileTokenImpl() {

    oidcAttributes = new LinkedHashSet<>();
    oidcAttributes.add(OidcProfileConstants.ID_ATTRIBUTE_OIDC_ISSUER);
    oidcAttributes.add(OidcProfileConstants.ID_ATTRIBUTE_OIDC_SUBJECT);
    oidcAttributes.add(OidcProfileConstants.ID_ATTRIBUTE_OIDC_ORGANISATION);
    oidcAttributes.add(OidcProfileConstants.ID_ATTRIBUTE_OIDC_CLIENTID);
    oidcAttributes.add(OidcProfileConstants.ID_ATTRIBUTE_OIDC_USER_ID);
    oidcAttributes.add(OidcProfileConstants.ID_ATTRIBUTE_OIDC_USER_NAME);
    oidcAttributes.add(OidcProfileConstants.ID_ATTRIBUTE_OIDC_GROUPS);
  }

  @Override
  public Optional<String> extractTokenFromRequest(Request request) {

    Optional<String> accessToken = Optional.empty();
    for (Subject sub : request.getSubjects()) {
      for (Attribute attr : sub.getAttributes()) {
        if (OidcProfileConstants.ID_ATTRIBUTE_OIDC_ACCESS_TOKEN
          .equals(attr.getId())) {
          Set<Object> values = attr.getValues();
          accessToken = Optional.of(values.iterator()
            .next()
            .toString());
        }
      }
    }
    return accessToken;
  }

  @Override
  public void cleanOidcAttributes(Request request) {

    for (Subject subj : request.getSubjects()) {
      List<Attribute> attributesToRemove = subj.getAttributes()
        .stream()
        .filter(a -> oidcAttributes.contains(a.getId()))
        .collect(Collectors.toList());

      if (!attributesToRemove.isEmpty()) {
        LOG.debug("Remove attributes from request subject: {}",
          attributesToRemove);
        subj.getAttributes()
          .removeAll(attributesToRemove);
      }
    }
  }

  @Override
  public void addOidcAttributes(Request request, TokenInfo tokenInfo) {

    Set<Attribute> attributesToAdd = new LinkedHashSet<>();

    Attribute oidcIssuer = new Attribute(
      OidcProfileConstants.ID_ATTRIBUTE_OIDC_ISSUER);
    oidcIssuer.getValues()
      .add(tokenInfo.getAccessToken()
        .getIssuer());

    Attribute oidcSubject = new Attribute(
      OidcProfileConstants.ID_ATTRIBUTE_OIDC_SUBJECT);
    oidcSubject.getValues()
      .add(tokenInfo.getIntrospection()
        .getSub());

    Attribute oidcUserId = new Attribute(
      OidcProfileConstants.ID_ATTRIBUTE_OIDC_USER_ID);
    oidcUserId.getValues()
      .add(tokenInfo.getIntrospection()
        .getUserId());

    attributesToAdd.add(oidcIssuer);
    attributesToAdd.add(oidcSubject);
    attributesToAdd.add(oidcUserId);

    if (tokenInfo.getUserinfo() == null) {
      LOG.warn("No user info data into access token.");
    } else {
      Attribute oidcUserName = new Attribute(
        OidcProfileConstants.ID_ATTRIBUTE_OIDC_USER_NAME);
      oidcUserName.getValues()
        .add(tokenInfo.getUserinfo()
          .getName());

      Attribute oidcOrganisation = new Attribute(
        OidcProfileConstants.ID_ATTRIBUTE_OIDC_ORGANISATION);
      oidcOrganisation.getValues()
        .add(tokenInfo.getIntrospection()
          .getOrganisationName());

      Attribute oidcGroups = new Attribute(
        OidcProfileConstants.ID_ATTRIBUTE_OIDC_GROUPS);
      oidcGroups.getValues()
        .addAll(Arrays.asList(tokenInfo.getIntrospection()
          .getGroups()));

      attributesToAdd.add(oidcUserName);
      attributesToAdd.add(oidcOrganisation);
      attributesToAdd.add(oidcGroups);
    }

    LOG.debug("Adding OIDC attributes to request subject: {}", attributesToAdd);

    request.getSubjects()
      .iterator()
      .next()
      .getAttributes()
      .addAll(attributesToAdd);
  }

}

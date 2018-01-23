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

package org.glite.authz.pep.pip.provider.oidc.impl;

import static org.glite.authz.common.profile.OidcProfileConstants.ID_ATTRIBUTE_OIDC_ACCESS_TOKEN;
import static org.glite.authz.common.profile.OidcProfileConstants.ID_ATTRIBUTE_OIDC_CLIENTID;
import static org.glite.authz.common.profile.OidcProfileConstants.ID_ATTRIBUTE_OIDC_GROUP;
import static org.glite.authz.common.profile.OidcProfileConstants.ID_ATTRIBUTE_OIDC_ISSUER;
import static org.glite.authz.common.profile.OidcProfileConstants.ID_ATTRIBUTE_OIDC_ORGANISATION;
import static org.glite.authz.common.profile.OidcProfileConstants.ID_ATTRIBUTE_OIDC_SCOPE;
import static org.glite.authz.common.profile.OidcProfileConstants.ID_ATTRIBUTE_OIDC_SUBJECT;
import static org.glite.authz.common.profile.OidcProfileConstants.ID_ATTRIBUTE_OIDC_USER_ID;
import static org.glite.authz.common.profile.OidcProfileConstants.ID_ATTRIBUTE_OIDC_USER_NAME;

import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Subject;
import org.glite.authz.oidc.client.model.TokenInfo;
import org.glite.authz.pep.pip.provider.oidc.OidcProfileTokenService;
import org.glite.authz.pep.pip.provider.oidc.error.TokenError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OidcProfileTokenServiceImpl implements OidcProfileTokenService {

  private static final Logger LOG = LoggerFactory.getLogger(OidcProfileTokenServiceImpl.class);
  private static final String SCOPE_SEPARATOR = " ";

  private final Set<String> oidcAttributes;

  public OidcProfileTokenServiceImpl() {

    oidcAttributes = new LinkedHashSet<>();
    oidcAttributes.add(ID_ATTRIBUTE_OIDC_ISSUER);
    oidcAttributes.add(ID_ATTRIBUTE_OIDC_SUBJECT);
    oidcAttributes.add(ID_ATTRIBUTE_OIDC_ORGANISATION);
    oidcAttributes.add(ID_ATTRIBUTE_OIDC_CLIENTID);
    oidcAttributes.add(ID_ATTRIBUTE_OIDC_USER_ID);
    oidcAttributes.add(ID_ATTRIBUTE_OIDC_USER_NAME);
    oidcAttributes.add(ID_ATTRIBUTE_OIDC_GROUP);
    oidcAttributes.add(ID_ATTRIBUTE_OIDC_SCOPE);
  }

  @Override
  public Optional<String> extractTokenFromRequest(Request request) {

    Optional<String> accessToken = Optional.empty();
    for (Subject sub : request.getSubjects()) {

      Optional<Attribute> attr = sub.getAttributes()
        .stream()
        .filter(a -> ID_ATTRIBUTE_OIDC_ACCESS_TOKEN.equals(a.getId()))
        .findFirst();

      if (attr.isPresent()) {
        Set<Object> values = attr.get().getValues();
        Iterator<Object> it = values.iterator();
        if (it.hasNext()) {
          accessToken = Optional.of(it.next().toString());
        }
      }
    }
    return accessToken;
  }

  @Override
  public void removeOidcAttributesFromRequest(Request request) {

    for (Subject subj : request.getSubjects()) {
      List<Attribute> attributesToRemove =
          subj.getAttributes().stream().filter(a -> oidcAttributes.contains(a.getId())).collect(
              Collectors.toList());

      if (!attributesToRemove.isEmpty()) {
        LOG.debug("Remove attributes from request subject: {}", attributesToRemove);
        subj.getAttributes().removeAll(attributesToRemove);
      }
    }
  }

  @Override
  public void addOidcAttributesToRequest(Request request, TokenInfo tokenInfo) {

    Set<Attribute> attributesToAdd = new LinkedHashSet<>();

    Attribute oidcIssuer = new Attribute(ID_ATTRIBUTE_OIDC_ISSUER);
    oidcIssuer.getValues().add(tokenInfo.getAccessToken().getIssuer());

    Attribute oidcSubject = new Attribute(ID_ATTRIBUTE_OIDC_SUBJECT);
    oidcSubject.getValues().add(tokenInfo.getAccessToken().getSubject());

    attributesToAdd.add(oidcIssuer);
    attributesToAdd.add(oidcSubject);

    String token = extractTokenFromRequest(request).orElseThrow(
        () -> new TokenError(String.format("Missing access token into request: %s ", request)));

    if (tokenInfo.getIntrospection() == null) {
      LOG.warn("No introspection data returned by token service for access token : {}", token);
    } else {
      Attribute oidcClientId = new Attribute(ID_ATTRIBUTE_OIDC_CLIENTID);
      oidcClientId.getValues().add(tokenInfo.getIntrospection().getClientId());

      Attribute oidcScopes = new Attribute(ID_ATTRIBUTE_OIDC_SCOPE);
      oidcScopes.getValues().addAll(convertScopeToList(tokenInfo.getIntrospection().getScope()));

      attributesToAdd.add(oidcClientId);
      attributesToAdd.add(oidcScopes);
    }

    if (tokenInfo.getUserinfo() == null) {
      LOG.warn("No userinfo data returned by token service for access token : {}", token);
    } else {
      Attribute oidcUserId = new Attribute(ID_ATTRIBUTE_OIDC_USER_ID);
      oidcUserId.getValues().add(tokenInfo.getUserinfo().getPreferredUsername());

      Attribute oidcUserName = new Attribute(ID_ATTRIBUTE_OIDC_USER_NAME);
      oidcUserName.getValues().add(tokenInfo.getUserinfo().getName());

      Attribute oidcOrganisation = new Attribute(ID_ATTRIBUTE_OIDC_ORGANISATION);
      oidcOrganisation.getValues().add(tokenInfo.getIntrospection().getOrganisationName());

      if (tokenInfo.getIntrospection().getGroups() != null) {
        Attribute oidcGroups = new Attribute(ID_ATTRIBUTE_OIDC_GROUP);
        oidcGroups.getValues().addAll(Arrays.asList(tokenInfo.getIntrospection().getGroups()));
        attributesToAdd.add(oidcGroups);
      }

      attributesToAdd.add(oidcUserId);
      attributesToAdd.add(oidcUserName);
      attributesToAdd.add(oidcOrganisation);
    }

    LOG.debug("Adding OIDC attributes to request subject: {}", attributesToAdd);

    request.getSubjects().iterator().next().getAttributes().addAll(attributesToAdd);
  }

  private List<String> convertScopeToList(String value) {
    return Arrays.asList(value.split(SCOPE_SEPARATOR));
  }

}

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

package org.glite.authz.pep.pip.provider.oidc;

import java.util.Optional;

import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Environment;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.profile.OidcProfileConstants;
import org.glite.authz.oidc.client.model.AccessToken;
import org.glite.authz.oidc.client.model.IamIntrospection;
import org.glite.authz.oidc.client.model.IamUser;
import org.glite.authz.oidc.client.model.TokenInfo;

public abstract class OidcTestUtils {

  protected final static String TEST_OIDC_CLIENT = "http://localhost";

  protected final static String VALID_ACCESS_TOKEN_STRING = "test.valid.access-token";
  protected final static String EXPIRED_ACCESS_TOKEN_STRING = "test.expired.access-token";
  protected final static String CLIENT_CRED_TOKEN_STRING = "test.client-cred.access-token";
  protected final static String DECODE_ERR_TOKEN_STRING = "test.decoding-error.access-token";
  protected final static String HTTP_ERR_TOKEN_STRING = "test.http-connection-error.access-token";

  protected final static String SUBJECT = "73f16d93-2441-4a50-88ff-85360d78c6b5";
  protected final static String ISSUER = "https://iam.local.io";
  protected final static String USER_ID = "admin";
  protected final static String USER_NAME = "Admin User";
  protected final static String ORGANIZATION = "indigo-dc";
  protected final static String[] GROUPS = new String[] {"Production", "Analysis"};
  protected final static String SCOPE = "openid profile email address";

  protected final static String PASSWD_GRANT_CLIENT_ID = "password-grant";
  protected final static String CLIENT_CRED_CLIENT_ID = "client-cred";

  protected final static AccessToken VALID_ACCESS_TOKEN =
      new AccessToken("RS256", SUBJECT, ISSUER, 1L, 3601L, "test-id");

  protected final static AccessToken CLIENT_CRED_ACCESS_TOKEN =
      new AccessToken("RS256", CLIENT_CRED_CLIENT_ID, ISSUER, 1L, 3601L, "test-id");

  protected final static IamIntrospection VALID_INTROSPECTION = IamIntrospection.getBuilder()
    .isActive(true)
    .scope(SCOPE)
    .expiresAt("2017-09-04T16:09:03+0200")
    .exp(1504534143L)
    .sub(SUBJECT)
    .userId(USER_ID)
    .clientId(PASSWD_GRANT_CLIENT_ID)
    .tokenType("Bearer")
    .groups(GROUPS)
    .preferredUsername(USER_ID)
    .organisationName(ORGANIZATION)
    .build();

  protected final static IamUser VALID_USERINFO = IamUser.getBuilder()
    .sub(SUBJECT)
    .name(USER_NAME)
    .preferredUsername(USER_ID)
    .givenName("Admin")
    .familyName("User")
    .gender("M")
    .updatedAt("Mon Sep 04 15:08:36 CEST 2017")
    .groups(GROUPS)
    .organisationName(ORGANIZATION)
    .build();

  protected final static IamIntrospection EXPIRED_INTROSPECTION =
      IamIntrospection.getBuilder().isActive(false).build();

  protected final static IamIntrospection CLIENT_CRED_INTROSPECTION = IamIntrospection.getBuilder()
    .isActive(true)
    .scope("read-tasks write-tasks")
    .expiresAt("2017-09-05T15:57:22+0200")
    .exp(1504619842L)
    .sub(CLIENT_CRED_CLIENT_ID)
    .userId(CLIENT_CRED_CLIENT_ID)
    .clientId(CLIENT_CRED_CLIENT_ID)
    .tokenType("Bearer")
    .build();

  protected final static TokenInfo VALID_TOKEN_INFO =
      new TokenInfo(VALID_ACCESS_TOKEN, VALID_INTROSPECTION, VALID_USERINFO);

  protected final static TokenInfo EXPIRED_TOKEN_INFO =
      new TokenInfo(null, EXPIRED_INTROSPECTION, null);

  protected final static TokenInfo CLIENT_CRED_TOKEN_INFO =
      new TokenInfo(CLIENT_CRED_ACCESS_TOKEN, CLIENT_CRED_INTROSPECTION, null);

  protected Attribute createOidcProfileIdAttribute() {

    Attribute attr = new Attribute(OidcProfileConstants.ID_ATTRIBUTE_PROFILE_ID);
    attr.getValues().add(OidcProfileConstants.OIDC_XACML_AUTHZ_V1_0_PROFILE_ID);
    return attr;
  }

  protected Attribute createOidcAccessTokenAttribute(String accessToken) {

    return createAttribute(OidcProfileConstants.ID_ATTRIBUTE_OIDC_ACCESS_TOKEN, accessToken);
  }

  protected Attribute createAttribute(String id, String value) {

    Attribute attr = new Attribute(id);
    attr.getValues().add(value);
    return attr;
  }

  protected Request createOidcRequestWithoutEnv(String accessToken) {

    Request request = new Request();
    Subject subj = new Subject();
    subj.getAttributes().add(createOidcAccessTokenAttribute(accessToken));
    request.getSubjects().add(subj);
    return request;
  }

  protected Request createOidcRequestWithoutAccessToken() {

    Request request = new Request();
    Environment env = new Environment();
    env.getAttributes().add(createOidcProfileIdAttribute());
    request.setEnvironment(env);
    Subject subj = new Subject();
    request.getSubjects().add(subj);
    return request;
  }

  protected Request createOidcRequest(String accessToken) {
    Request request = new Request();
    Environment env = new Environment();
    env.getAttributes().add(createOidcProfileIdAttribute());
    request.setEnvironment(env);
    Subject subj = new Subject();
    subj.getAttributes().add(createOidcAccessTokenAttribute(accessToken));
    request.getSubjects().add(subj);
    return request;
  }

  protected Optional<Attribute> getAttributeValuesById(Request request, String attributeId) {

    return request.getSubjects()
      .iterator()
      .next()
      .getAttributes()
      .stream()
      .filter(a -> a.getId().equals(attributeId))
      .findAny();
  }
}

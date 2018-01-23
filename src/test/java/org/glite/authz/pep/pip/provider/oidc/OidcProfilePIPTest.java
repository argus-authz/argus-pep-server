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

import static org.glite.authz.common.profile.OidcProfileConstants.ID_ATTRIBUTE_OIDC_CLIENTID;
import static org.glite.authz.common.profile.OidcProfileConstants.ID_ATTRIBUTE_OIDC_GROUP;
import static org.glite.authz.common.profile.OidcProfileConstants.ID_ATTRIBUTE_OIDC_ISSUER;
import static org.glite.authz.common.profile.OidcProfileConstants.ID_ATTRIBUTE_OIDC_ORGANISATION;
import static org.glite.authz.common.profile.OidcProfileConstants.ID_ATTRIBUTE_OIDC_SCOPE;
import static org.glite.authz.common.profile.OidcProfileConstants.ID_ATTRIBUTE_OIDC_SUBJECT;
import static org.glite.authz.common.profile.OidcProfileConstants.ID_ATTRIBUTE_OIDC_USER_ID;
import static org.glite.authz.common.profile.OidcProfileConstants.ID_ATTRIBUTE_OIDC_USER_NAME;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Set;

import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Request;
import org.glite.authz.pep.pip.PIPProcessingException;
import org.glite.authz.pep.pip.PolicyInformationPoint;
import org.glite.authz.pep.pip.provider.oidc.error.HttpError;
import org.glite.authz.pep.pip.provider.oidc.error.TokenError;
import org.glite.authz.pep.pip.provider.oidc.impl.OidcHttpServiceImpl;
import org.glite.authz.pep.pip.provider.oidc.impl.OidcProfileTokenServiceImpl;
import org.glite.authz.pep.pip.provider.oidc.impl.OidcTokenDecoderImpl;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import com.fasterxml.jackson.databind.ObjectMapper;

import net.sf.ehcache.CacheManager;

public class OidcProfilePIPTest extends OidcTestUtils {

  private PolicyInformationPoint pip;
  private OidcProfileTokenService tokenService = new OidcProfileTokenServiceImpl();
  private OidcTokenDecoder decoder;
  private ObjectMapper mapper = new ObjectMapper();

  @Mock
  private OidcHttpService httpService = new OidcHttpServiceImpl(TEST_OIDC_CLIENT);

  @Rule
  public MockitoRule mockitoRule = MockitoJUnit.rule();

  @Before
  public void setup() throws Exception {

    when(httpService.inspectToken(VALID_ACCESS_TOKEN_STRING))
      .thenReturn(mapper.writeValueAsString(VALID_TOKEN_INFO));

    when(httpService.inspectToken(EXPIRED_ACCESS_TOKEN_STRING))
      .thenReturn(mapper.writeValueAsString(EXPIRED_TOKEN_INFO));

    when(httpService.inspectToken(CLIENT_CRED_TOKEN_STRING))
      .thenReturn(mapper.writeValueAsString(CLIENT_CRED_TOKEN_INFO));

    when(httpService.inspectToken(DECODE_ERR_TOKEN_STRING))
      .thenReturn("randoms-$tring.that-is_not.an^access-token");

    when(httpService.inspectToken(HTTP_ERR_TOKEN_STRING))
      .thenThrow(new HttpError("HTTP communication error", new IOException()));

    decoder = new OidcTokenDecoderImpl(httpService, 1, 1, true);
    pip = new OidcProfilePIP("test", tokenService, decoder);
    pip.start();
  }

  @After
  public void teardown() throws Exception {
    if (pip != null) {
      pip.stop();
    }
    CacheManager.getInstance().shutdown();
  }

  @Test
  public void testRequestWithAccessToken() throws Exception {

    Request request = createOidcRequest(VALID_ACCESS_TOKEN_STRING);

    Boolean retval = pip.populateRequest(request);

    assertThat(retval, equalTo(true));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_SUBJECT).get().getValues(),
        everyItem(equalTo(SUBJECT)));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_ISSUER).get().getValues(),
        everyItem(equalTo(ISSUER)));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_CLIENTID).get().getValues(),
        everyItem(equalTo(PASSWD_GRANT_CLIENT_ID)));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_ORGANISATION).get().getValues(),
        everyItem(equalTo(ORGANIZATION)));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_USER_ID).get().getValues(),
        everyItem(equalTo(USER_ID)));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_USER_NAME).get().getValues(),
        everyItem(equalTo(USER_NAME)));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_GROUP).get().getValues(),
        containsInAnyOrder("Production", "Analysis"));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_SCOPE).get().getValues(),
        containsInAnyOrder("openid", "profile", "email", "address"));
  }

  @Test(expected = PIPProcessingException.class)
  public void testRequestWithoutAccessToken() throws Exception {

    Request request = createOidcRequestWithoutAccessToken();
    try {
      pip.populateRequest(request);
    } catch (PIPProcessingException e) {
      assertThat(e.getMessage(), containsString("No access token found"));
      throw e;
    }
  }

  @Test
  public void testWithExpiredAccessToken() throws Exception {

    Request request = createOidcRequest(EXPIRED_ACCESS_TOKEN_STRING);

    Boolean retval = pip.populateRequest(request);
    assertThat(retval, is(false));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_SUBJECT).isPresent(), is(false));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_ISSUER).isPresent(), is(false));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_ORGANISATION).isPresent(),
        is(false));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_CLIENTID).isPresent(), is(false));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_USER_ID).isPresent(), is(false));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_USER_NAME).isPresent(), is(false));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_GROUP).isPresent(), is(false));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_SCOPE).isPresent(), is(false));
  }

  @Test
  public void testRequestWithoutEnvironment() throws Exception {

    Request request = createOidcRequestWithoutEnv(VALID_ACCESS_TOKEN_STRING);
    Boolean retval = pip.populateRequest(request);

    assertNotNull(retval);
    assertThat(retval, is(false));
  }

  @Test
  public void testCleanAttributesBeforeDecoding() throws Exception {

    Request request = createOidcRequest(VALID_ACCESS_TOKEN_STRING);

    Set<Attribute> fakeAttrs = new LinkedHashSet<>();

    Attribute attr = createAttribute(ID_ATTRIBUTE_OIDC_SUBJECT, "fake_oidc_subject");
    fakeAttrs.add(attr);

    attr = createAttribute(ID_ATTRIBUTE_OIDC_ISSUER, "fake_oidc_issuer");
    fakeAttrs.add(attr);

    attr = createAttribute(ID_ATTRIBUTE_OIDC_ORGANISATION, "fake_oidc_organization");
    fakeAttrs.add(attr);

    request.getSubjects().iterator().next().getAttributes().addAll(fakeAttrs);

    Boolean retval = pip.populateRequest(request);

    assertThat(retval, equalTo(true));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_SUBJECT).get().getValues(),
        everyItem(equalTo(SUBJECT)));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_ISSUER).get().getValues(),
        everyItem(equalTo(ISSUER)));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_ORGANISATION).get().getValues(),
        everyItem(equalTo(ORGANIZATION)));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_USER_ID).get().getValues(),
        everyItem(equalTo(USER_ID)));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_USER_NAME).get().getValues(),
        everyItem(equalTo(USER_NAME)));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_GROUP).get().getValues(),
        containsInAnyOrder("Production", "Analysis"));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_SCOPE).get().getValues(),
        containsInAnyOrder("openid", "profile", "email", "address"));

  }

  @Test
  public void testRequestWithClientCredentialsToken() throws Exception {

    Request request = createOidcRequest(CLIENT_CRED_TOKEN_STRING);
    Boolean retval = pip.populateRequest(request);

    assertThat(retval, is(true));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_SUBJECT).get().getValues(),
        everyItem(equalTo(CLIENT_CRED_CLIENT_ID)));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_ISSUER).get().getValues(),
        everyItem(equalTo(ISSUER)));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_ORGANISATION).isPresent(),
        is(false));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_CLIENTID).get().getValues(),
        everyItem(equalTo(CLIENT_CRED_CLIENT_ID)));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_USER_ID).isPresent(), is(false));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_USER_NAME).isPresent(), is(false));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_GROUP).isPresent(), is(false));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_SCOPE).get().getValues(),
        containsInAnyOrder("read-tasks", "write-tasks"));

  }

  @Test(expected = TokenError.class)
  public void testTokenDecodingException() throws Exception {

    Request request = createOidcRequest(DECODE_ERR_TOKEN_STRING);
    try {
      pip.populateRequest(request);
    } catch (Exception e) {
      assertThat(e.getMessage(), containsString("Error decoding access token"));
      throw e;
    }
  }

  @Test(expected = HttpError.class)
  public void testHttpCommunicationError() throws Exception {
    Request request = createOidcRequest(HTTP_ERR_TOKEN_STRING);
    try {
      pip.populateRequest(request);
    } catch (Exception e) {
      assertThat(e.getMessage(), containsString("HTTP communication error"));
      throw e;
    }
  }
}

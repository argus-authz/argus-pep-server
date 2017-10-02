package org.glite.authz.pep.pip.provider.oidc;

import static org.glite.authz.common.profile.OidcProfileConstants.ID_ATTRIBUTE_OIDC_GROUPS;
import static org.glite.authz.common.profile.OidcProfileConstants.ID_ATTRIBUTE_OIDC_ISSUER;
import static org.glite.authz.common.profile.OidcProfileConstants.ID_ATTRIBUTE_OIDC_ORGANISATION;
import static org.glite.authz.common.profile.OidcProfileConstants.ID_ATTRIBUTE_OIDC_SUBJECT;
import static org.glite.authz.common.profile.OidcProfileConstants.ID_ATTRIBUTE_OIDC_USER_ID;
import static org.glite.authz.common.profile.OidcProfileConstants.ID_ATTRIBUTE_OIDC_USER_NAME;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Set;

import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Request;
import org.glite.authz.pep.pip.PIPProcessingException;
import org.glite.authz.pep.pip.PolicyInformationPoint;
import org.glite.authz.pep.pip.provider.oidc.error.TokenDecodingException;
import org.glite.authz.pep.pip.provider.oidc.impl.OidcProfileTokenImpl;
import org.glite.authz.pep.pip.provider.oidc.impl.TokenDecoderImpl;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import net.sf.ehcache.CacheManager;

public class OidcProfilePIPTest extends OidcTestUtils {

  private PolicyInformationPoint pip;
  private OidcProfileToken tokenService = new OidcProfileTokenImpl();

  @Mock
  private TokenDecoder decoder = new TokenDecoderImpl("localhost", 1, 1, true);

  @Rule
  public MockitoRule mockitoRule = MockitoJUnit.rule();

  @Before
  public void setup() throws Exception {

    Mockito.when(decoder.decodeAccessToken(VALID_ACCESS_TOKEN_STRING))
      .thenReturn(VALID_TOKEN_INFO);

    Mockito.when(decoder.decodeAccessToken(EXPIRED_ACCESS_TOKEN_STRING))
      .thenReturn(EXPIRED_TOKEN_INFO);

    Mockito.when(decoder.decodeAccessToken(CLIENT_CRED_TOKEN_STRING))
      .thenReturn(CLIENT_CRED_TOKEN_INFO);

    Mockito.when(decoder.decodeAccessToken(DECODE_ERR_TOKEN_STRING))
      .thenThrow(new TokenDecodingException("Error decoding access token",
        new IOException()));

    pip = new OidcProfilePIP("test", tokenService, decoder);
    pip.start();
  }

  @After
  public void teardown() throws Exception {

    if (pip != null) {
      pip.stop();
    }
    CacheManager.getInstance()
      .shutdown();
  }

  @Test
  public void testRequestWithAccessToken() throws Exception {

    Request request = createOidcRequest(VALID_ACCESS_TOKEN_STRING);

    Boolean retval = pip.populateRequest(request);

    assertThat(retval, equalTo(true));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_SUBJECT).get()
      .getValues(), everyItem(equalTo(SUBJECT)));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_ISSUER).get()
      .getValues(), everyItem(equalTo(ISSUER)));
    assertThat(
      getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_ORGANISATION).get()
        .getValues(),
      everyItem(equalTo(ORGANIZATION)));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_USER_ID).get()
      .getValues(), everyItem(equalTo(USER_ID)));
    assertThat(
      getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_USER_NAME).get()
        .getValues(),
      everyItem(equalTo(USER_NAME)));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_GROUPS).get()
      .getValues(), containsInAnyOrder("Production", "Analysis"));
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

  @Test(expected = PIPProcessingException.class)
  public void testWithExpiredAccessToken() throws Exception {

    Request request = createOidcRequest(EXPIRED_ACCESS_TOKEN_STRING);

    try {
      pip.populateRequest(request);
    } catch (PIPProcessingException e) {
      assertThat(e.getMessage(), containsString("expired access token"));
      throw e;
    }
  }

  @Test(expected = PIPProcessingException.class)
  public void testRequestWithoutEnvironment() throws Exception {

    Request request = createOidcRequestWithoutEnv(VALID_ACCESS_TOKEN_STRING);

    try {
      pip.populateRequest(request);
    } catch (Exception e) {
      assertThat(e.getMessage(),
        containsString("Request doesn't match OIDC profile"));
      throw e;
    }
  }

  @Test
  public void testCleanAttributesBeforeDecoding() throws Exception {

    Request request = createOidcRequest(VALID_ACCESS_TOKEN_STRING);

    Set<Attribute> fakeAttrs = new LinkedHashSet<>();

    Attribute attr = createAttribute(ID_ATTRIBUTE_OIDC_SUBJECT,
      "fake_oidc_subject");
    fakeAttrs.add(attr);

    attr = createAttribute(ID_ATTRIBUTE_OIDC_ISSUER, "fake_oidc_issuer");
    fakeAttrs.add(attr);

    attr = createAttribute(ID_ATTRIBUTE_OIDC_ORGANISATION,
      "fake_oidc_organization");
    fakeAttrs.add(attr);

    request.getSubjects()
      .iterator()
      .next()
      .getAttributes()
      .addAll(fakeAttrs);

    Boolean retval = pip.populateRequest(request);

    assertThat(retval, equalTo(true));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_SUBJECT).get()
      .getValues(), everyItem(equalTo(SUBJECT)));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_ISSUER).get()
      .getValues(), everyItem(equalTo(ISSUER)));
    assertThat(
      getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_ORGANISATION).get()
        .getValues(),
      everyItem(equalTo(ORGANIZATION)));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_USER_ID).get()
      .getValues(), everyItem(equalTo(USER_ID)));
    assertThat(
      getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_USER_NAME).get()
        .getValues(),
      everyItem(equalTo(USER_NAME)));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_GROUPS).get()
      .getValues(), containsInAnyOrder("Production", "Analysis"));

  }

  @Test
  public void testRequestWithClientCredentialsToken() throws Exception {

    Request request = createOidcRequest(CLIENT_CRED_TOKEN_STRING);
    Boolean retval = pip.populateRequest(request);

    assertThat(retval, equalTo(true));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_SUBJECT).get()
      .getValues(), everyItem(equalTo(CLIENT_CRED_CLIENT_ID)));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_ISSUER).get()
      .getValues(), everyItem(equalTo(ISSUER)));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_ORGANISATION)
      .isPresent(), is(false));
    assertThat(getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_USER_ID).get()
      .getValues(), everyItem(equalTo(CLIENT_CRED_CLIENT_ID)));
    assertThat(
      getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_USER_NAME).isPresent(),
      is(false));
    assertThat(
      getAttributeValuesById(request, ID_ATTRIBUTE_OIDC_GROUPS).isPresent(),
      is(false));

  }

  @Test(expected = TokenDecodingException.class)
  public void testTokenDecodingException() throws Exception {

    Request request = createOidcRequest(DECODE_ERR_TOKEN_STRING);
    try {
      pip.populateRequest(request);
    } catch (Exception e) {
      assertThat(e.getMessage(), containsString("Error decoding access token"));
      throw e;
    }
  }
}

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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.httpclient.HttpStatus;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.glite.authz.pep.pip.provider.oidc.OidcHttpService;
import org.glite.authz.pep.pip.provider.oidc.error.HttpError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OidcHttpServiceImpl implements OidcHttpService {

  private static final Logger LOG = LoggerFactory.getLogger(OidcHttpServiceImpl.class);

  private static final String USER_AGENT = "Mozilla 5.0";

  private String oidcClientUrl;
  private HttpClient client;
  private HttpPost post;

  public OidcHttpServiceImpl(String oidcClientUrl) {
    this.oidcClientUrl = oidcClientUrl;

    this.client = HttpClientBuilder.create().build();
    this.post = new HttpPost(oidcClientUrl);
    this.post.setHeader("User-Agent", USER_AGENT);
  }

  @Override
  public String getOidcClientUrl() {
    return oidcClientUrl;
  }

  @Override
  public String inspectToken(String accessToken) {

    List<NameValuePair> urlParameters = new ArrayList<>();
    urlParameters.add(new BasicNameValuePair("token", accessToken));

    try {
      post.setEntity(new UrlEncodedFormEntity(urlParameters));

      HttpResponse response = client.execute(post);
      LOG.debug("Response Code : {}", response.getStatusLine());

      String result = readResponseBody(response);
      LOG.debug("Response Body : {}", result);

      if (HttpStatus.SC_OK != response.getStatusLine().getStatusCode()) {
        throw new HttpError("Error connecting to OIDC client: " + result);
      }

      return result;
    } catch (IOException e) {
      LOG.error("HTTP communication error: {}", e.getMessage());
      throw new HttpError("HTTP communication error: " + e.getMessage(), e);
    }
  }

  private String readResponseBody(HttpResponse response) throws IOException {
    BufferedReader rd =
        new BufferedReader(new InputStreamReader(response.getEntity().getContent()));

    StringBuilder result = new StringBuilder();
    String line = "";
    while ((line = rd.readLine()) != null) {
      result.append(line);
    }
    return result.toString();
  }
}

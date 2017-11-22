package org.glite.authz.pep.pip.provider.oidc.impl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.glite.authz.pep.pip.provider.oidc.OidcHttpService;
import org.glite.authz.pep.pip.provider.oidc.error.HttpCommunicationException;
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
  public String postRequest(String accessToken) {

    List<NameValuePair> urlParameters = new ArrayList<>();
    urlParameters.add(new BasicNameValuePair("token", accessToken));

    try {
      post.setEntity(new UrlEncodedFormEntity(urlParameters));

      HttpResponse response = client.execute(post);
      LOG.debug("Response Code : {}", response.getStatusLine().getStatusCode());

      BufferedReader rd =
          new BufferedReader(new InputStreamReader(response.getEntity().getContent()));

      StringBuilder result = new StringBuilder();
      String line = "";
      while ((line = rd.readLine()) != null) {
        result.append(line);
      }
      LOG.debug("Response Body : {}", result);
      return result.toString();
    } catch (IOException e) {
      LOG.error("HTTP communication error: {}", e.getMessage());
      throw new HttpCommunicationException("HTTP communication error: " + e.getMessage(), e);
    }
  }
}

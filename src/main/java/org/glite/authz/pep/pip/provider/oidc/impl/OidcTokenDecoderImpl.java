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

import java.io.IOException;

import org.glite.authz.oidc.client.model.TokenInfo;
import org.glite.authz.pep.pip.provider.oidc.OidcHttpService;
import org.glite.authz.pep.pip.provider.oidc.OidcTokenDecoder;
import org.glite.authz.pep.pip.provider.oidc.error.TokenDecodingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;

import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Element;
import net.sf.ehcache.config.CacheConfiguration;

public class OidcTokenDecoderImpl implements OidcTokenDecoder {

  private static final String CACHE_NAME = "token-info-cache";

  private static final Logger LOG = LoggerFactory.getLogger(OidcTokenDecoderImpl.class);

  private final OidcHttpService oidcHttpService;
  private final Integer cacheTTLInSecs;
  private final Integer cacheMaxElements;
  private final Boolean cacheDisabled;

  private final ObjectMapper mapper;
  private final Cache tokenCache;

  public OidcTokenDecoderImpl(OidcHttpService oidcHttpService, Integer cacheTTLInSecs,
      Integer cacheMaxElements, Boolean cacheDisabled) {

    this.oidcHttpService = oidcHttpService;
    this.cacheTTLInSecs = cacheTTLInSecs;
    this.cacheMaxElements = cacheMaxElements;
    this.cacheDisabled = cacheDisabled;

    mapper = new ObjectMapper();
    tokenCache = initCache();
  }

  private Cache initCache() {

    CacheManager cacheManager = CacheManager.getInstance();
    CacheConfiguration cacheConfiguration = new CacheConfiguration().name(CACHE_NAME)
      .maxEntriesLocalHeap(cacheMaxElements)
      .timeToLiveSeconds(cacheTTLInSecs);
    cacheManager.addCache(new Cache(cacheConfiguration));

    Cache cache = cacheManager.getCache(CACHE_NAME);
    cache.setDisabled(cacheDisabled);

    return cache;
  }

  @Override
  public TokenInfo decodeAccessToken(String accessToken) {

    Element elem = tokenCache.get(accessToken);
    if (elem != null) {
      LOG.debug("Cache hit for access token '{}'", accessToken);
      return (TokenInfo) elem.getObjectValue();
    }

    LOG.debug("Cache miss for access token '{}'", accessToken);
    LOG.debug("Sending request to OIDC client '{}'", oidcHttpService.getOidcClientUrl());

    String response = oidcHttpService.postRequest(accessToken);
    LOG.debug("Get response from OIDC client: '{}'", response);

    try {
      TokenInfo tokenInfo = mapper.readValue(response, TokenInfo.class);
      tokenCache.put(new Element(accessToken, tokenInfo));
      return tokenInfo;
    } catch (IOException e) {
      String msg = "Error decoding access token: " + e.getMessage();
      LOG.error(msg, e);
      throw new TokenDecodingException(msg, e);
    }
  }
}

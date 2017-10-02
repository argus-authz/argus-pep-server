package org.glite.authz.pep.pip.provider.oidc.impl;

import java.io.IOException;

import org.apache.commons.httpclient.methods.PostMethod;
import org.glite.authz.oidc.client.model.TokenInfo;
import org.glite.authz.pep.pip.provider.oidc.TokenDecoder;
import org.glite.authz.pep.pip.provider.oidc.error.TokenDecodingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;

import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Element;
import net.sf.ehcache.config.CacheConfiguration;

public class TokenDecoderImpl implements TokenDecoder {

  private static final String CACHE_NAME = "token-info-cache";

  private static final Logger LOG = LoggerFactory
    .getLogger(TokenDecoderImpl.class);

  private final String oidcClientUrl;
  private final Integer cacheTTLInSecs;
  private final Integer cacheMaxElements;
  private final Boolean cacheDisabled;

  private final ObjectMapper mapper;
  private final Cache tokenCache;

  public TokenDecoderImpl(String oidcClientUrl, Integer cacheTTLInSecs,
    Integer cacheMaxElements, Boolean cacheDisabled) {

    this.oidcClientUrl = oidcClientUrl;
    this.cacheTTLInSecs = cacheTTLInSecs;
    this.cacheMaxElements = cacheMaxElements;
    this.cacheDisabled = cacheDisabled;

    mapper = new ObjectMapper();
    tokenCache = initCache();
  }

  private Cache initCache() {

    CacheManager cacheManager = CacheManager.getInstance();
    CacheConfiguration cacheConfiguration = new CacheConfiguration()
      .name(CACHE_NAME)
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

    try {
      LOG.debug("Cache miss for access token '{}'", accessToken);

      PostMethod method = new PostMethod(oidcClientUrl);
      method.setParameter("token", accessToken);

      String response = method.getResponseBodyAsString();
      TokenInfo tokenInfo = mapper.readValue(response, TokenInfo.class);

      tokenCache.put(new Element(accessToken, tokenInfo));
      return tokenInfo;
    } catch (IOException e) {
      String msg = "Error decoding access token";
      LOG.error(msg, e);
      throw new TokenDecodingException(msg, e);
    }
  }
}

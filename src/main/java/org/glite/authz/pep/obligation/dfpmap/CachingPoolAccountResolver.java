/*
 * Copyright (c) Members of the EGEE Collaboration. 2006-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.glite.authz.pep.obligation.dfpmap;

import java.io.File;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Element;
import net.sf.ehcache.store.MemoryStoreEvictionPolicy;

/**
 * 
 * A caching pool account resolver.
 * 
 * This resolver wraps {@link DefaultPoolAccountResolver} but caches the results
 * for a configurable amount of time.
 *
 */
public class CachingPoolAccountResolver implements PoolAccountResolver {

  public static final Logger LOG = LoggerFactory
    .getLogger(CachingPoolAccountResolver.class);

  /** Name of the cache, as registered in the EHCache manager **/
  public static final String POOL_ACCOUNT_CACHE_NAME = "pool-accounts-cache";

  /** The wrapped pool account resolver **/
  final DefaultPoolAccountResolver defaultResolver;

  /** The cached used to cache results **/
  final Cache cache;

  /**
   * Constructor.
   * 
   * @param gridmapDir
   *          the gridmap dir holding pool accounts
   * @param cacheTTL
   *          the TTL for cache elements
   * @param cacheTTLUnit
   *          the unit for cache elements TTL
   */
  public CachingPoolAccountResolver(File gridmapDir, long cacheTTL,
    TimeUnit cacheTTLUnit) {

    defaultResolver = new DefaultPoolAccountResolver(gridmapDir);

    cache = new Cache(POOL_ACCOUNT_CACHE_NAME, 100,
      MemoryStoreEvictionPolicy.LFU, false, null, false,
      cacheTTLUnit.toMillis(cacheTTL), cacheTTLUnit.toMillis(cacheTTL), false,
      Long.MAX_VALUE, null, null);

    CacheManager.create().addCache(cache);

  }

  public File[] getAccountFiles(String prefix) {

    Element cacheElement = cache.get(prefix);

    File[] accountFiles = null;

    if (cacheElement == null) {

      LOG.debug("Cache miss for prefix {}", prefix);
      accountFiles = defaultResolver.getAccountFiles(prefix);
      cacheElement = new Element(prefix, accountFiles);

      cache.put(cacheElement);

    } else {

      LOG.debug("Cache hit for prefix {}", prefix);
      accountFiles = (File[])cacheElement.getValue();
    }

    return accountFiles;

  }

}

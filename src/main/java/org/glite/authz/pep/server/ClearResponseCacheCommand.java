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

package org.glite.authz.pep.server;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Status;

import org.glite.authz.common.http.AbstractAdminCommand;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** An admin command that expunges all the current entries in the PDP response cache. */
public class ClearResponseCacheCommand extends AbstractAdminCommand {

    /** Serial version UID. */
    private static final long serialVersionUID = -2575767336984093204L;
    
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(ClearResponseCacheCommand.class);

    /** Constructors. */
    public ClearResponseCacheCommand() {
        super("/clearResponseCache");
    }

    /** {@inheritDoc} */
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        CacheManager cacheMgr = CacheManager.getInstance();
        if (cacheMgr != null && cacheMgr.getStatus() == Status.STATUS_ALIVE) {
            log.info("Clearing PDP response cache");
            Cache responseCache = cacheMgr.getCache(PEPDaemonRequestHandler.RESPONSE_CACHE_NAME);
            if(responseCache != null){
                responseCache.removeAll();
            }
        }

        resp.setStatus(HttpServletResponse.SC_OK);
    }
}
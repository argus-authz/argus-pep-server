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

import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.emi.security.authn.x509.impl.OpensslNameUtils;

/** A matching strategy for {@link X500Principal}. */
public class X509MatchStrategy implements DFPMMatchStrategy<X500Principal> {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(X509MatchStrategy.class);

    /** {@inheritDoc} */
    public boolean isMatch(String dfpmKey, X500Principal candidate) {
        X500Principal target = keyToDN(dfpmKey);
        if (target == null) {
            return false;
        }
        boolean matches = target.equals(candidate);
        if (log.isTraceEnabled()) {
            log.trace("'{}' matches '{}' ? {}", new Object[] { candidate, target, matches });
        }
        return matches;
    }

    /**
     * Converts a key to a DN. If key starts with "/" it assumes key format is openssl DN format, otherwise it
     * assumes key format is RFC2253 format.
     * 
     * @param key the key to convert
     * 
     * @return the constructed DN or null if the key is not a valid DN
     */
    @SuppressWarnings("deprecation")
	private X500Principal keyToDN(String key) {

        String rfc2253DN;

        if (key.startsWith("/")) {
            // Workaround to support gridmap-file's DN with escaped slashes 
            key = key.replace("\\", "");
            rfc2253DN = OpensslNameUtils.opensslToRfc2253(key);
        } else {
            rfc2253DN = key;
        }

        try {
            return new X500Principal(rfc2253DN);
        } catch (Exception e) {
            log.debug("Failed to convert '" + rfc2253DN + "' to X500Principal", e);
            return null;
        }
    }
}
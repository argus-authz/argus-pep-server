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

import java.util.ArrayList;

import javax.security.auth.x500.X500Principal;

/** A matching strategy for {@link X500Principal}. */
public class X509MatchStrategy implements DFPMMatchStrategy<X500Principal> {

    /** {@inheritDoc} */
    public boolean isMatch(String dfpmKey, X500Principal candidate) {
        X500Principal target = keyToDN(dfpmKey);
        if (target == null) {
            return false;
        }
        return target.equals(candidate);
    }

    /**
     * Converts an key in to a DN. If the key starts with a "/" it assumed to be in the openssl DN format, otherwise it
     * is assumed to be in RFC2253 format.
     * 
     * @param key the key to convert
     * 
     * @return the constructed DN or null if the key is not a valid DN
     */
    private X500Principal keyToDN(String key) {
        String rfc2253DN;
        if (key.startsWith("/")) {
            ArrayList<String> rdns = new ArrayList<String>();
            StringBuilder rdnBuilder = new StringBuilder();
            char character;
            for (int i = 1; i < key.length(); i++) {
                character = key.charAt(i);
                if (character != '/') {
                    rdnBuilder.append(character);
                    continue;
                }

                if (key.charAt(i - 1) == '\\') {
                    rdnBuilder.deleteCharAt(rdnBuilder.length() - 1);
                    rdnBuilder.append("/");
                } else {
                    rdns.add(rdnBuilder.toString());
                    rdnBuilder = new StringBuilder();
                }
            }
            rdns.add(rdnBuilder.toString());

            StringBuilder dn = new StringBuilder();
            for (int i = rdns.size() - 1; i >= 0; i--) {
                dn.append(rdns.get(i));
                if (i > 0) {
                    dn.append(",");
                }
            }
            rfc2253DN = dn.toString();
        } else {
            rfc2253DN = key;
        }

        try {
            return new X500Principal(rfc2253DN);
        } catch (Exception e) {
            return null;
        }
    }
}
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

/** A matching strategy used to match {@link FQAN}s against other FQANs, possibly containing the wildcard '*'. */
public class FQANMatchStrategy implements DFPMMatchStrategy<FQAN> {

    /** {@inheritDoc} */
    public boolean isMatch(String dfpmKey, FQAN candidate) {
        FQAN target= null;
        try {
            target = FQAN.parseFQAN(dfpmKey);
        } catch (IllegalArgumentException e) {
            return false;
        }

        if (target.getAttributeGroupId().endsWith("*")) {
            String targetGroupIDRegex = target.getAttributeGroupId().replace("*", ".+");
            if (!candidate.getAttributeGroupId().matches(targetGroupIDRegex)) {
                return false;
            }
        } else {
            if (!candidate.getAttributeGroupId().equals(target.getAttributeGroupId())) {
                return false;
            }
        }

        ArrayList<String> attributeIds = new ArrayList<String>();
        attributeIds.addAll(target.getAttributeIds());
        attributeIds.addAll(candidate.getAttributeIds());

        for (String id : attributeIds) {
            if (!attributeMatches(target.getAttributeById(id), candidate.getAttributeById(id))) {
                return false;
            }
        }

        return true;
    }

    /**
     * Checks whether an attribute matches another attribute.
     * 
     * @param target the attribute the candidate is checked against
     * @param candidate the attribute checked against the target
     * 
     * @return true if the candidate matches the target, false if not
     */
    private boolean attributeMatches(FQAN.Attribute target, FQAN.Attribute candidate) {
        if (target == null && candidate == null) {
            return true;
        }

        if (candidate == null) {
            if (target.getValue().equals(FQAN.Attribute.NULL_VALUE)) {
                return true;
            }
            return false;
        }

        if (target == null) {
            if (candidate.getValue().equals(FQAN.Attribute.NULL_VALUE)) {
                return true;
            }
            return false;
        }

        if (!target.getId().equals(candidate.getId())) {
            return false;
        }

        String valueMatch = target.getValue().replace("*", ".+");
        return candidate.getValue().matches(valueMatch);
    }
}
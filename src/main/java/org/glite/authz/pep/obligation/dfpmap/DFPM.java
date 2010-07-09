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

import java.util.List;
import java.util.Map;

/**
 * Represents a DN/FQAN to POSIX UID/GID information mapping.
 * 
 * A DFP map does not allow the same key to be inserted more than once nor does it allow null keys or values.
 */
public interface DFPM extends Map<String, List<String>> { 
    
    /**
     * Determines if the given key is a mapping from a DN.
     * 
     * @param key the key
     * 
     * @return true if the key is a DN mapping key
     */
    public boolean isDNMapEntry(String key);

    /**
     * Determines if the given key is a mapping from a FQAN.
     * 
     * @param key the key
     * 
     * @return true if the key is a FQAN mapping key
     */
    public boolean isFQANMapEntry(String key);
}
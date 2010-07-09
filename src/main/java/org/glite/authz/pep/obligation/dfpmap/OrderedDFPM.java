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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.glite.authz.common.util.Strings;

/** An implementation of {@link DFPM} that orders entries by insertion order. */
public class OrderedDFPM extends LinkedHashMap<String, List<String>> implements DFPM {

    /** Serial version UID. */
    private static final long serialVersionUID = -4204108400547508390L;

    /** Constructor. */
    public OrderedDFPM() {
        super();
    }

    /**
     * Constructor.
     * 
     * @param map map whose entries will be added to this map in the order returned by its iterator
     */
    public OrderedDFPM(Map<String, List<String>> map) {
        super(map);
    }
    
    /** {@inheritDoc} */
    public boolean isDNMapEntry(String key) {
        return !isFQANMapEntry(key);
    }
    
    /** {@inheritDoc} */
    public boolean isFQANMapEntry(String key) {
        // DNs must contain a = in their first component
        // a FQAN must not

        String[] components = key.split("/");
        // both DNs and FQANs must begin with a / so there is an empty
        // component preceding the first real component
        if (components.length > 1 && !components[1].contains("=")) {
            return true;
        }

        return false;
    }

    /** {@inheritDoc} */
    public List<String> put(String key, List<String> value) {
        String trimmedKey = Strings.safeTrim(key);
        if (trimmedKey == null) {
            throw new IllegalArgumentException("key may not be null or empty");
        }

        if (containsKey(trimmedKey)) {
            throw new IllegalArgumentException("An entry with that key already exists, it can not be replaced");
        }

        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("value may not be null or mepty");
        }

        super.put(key, value);
        return null;
    }

    /** {@inheritDoc} */
    public void putAll(Map<? extends String, ? extends List<String>> map) {
        if (map == null || map.isEmpty()) {
            return;
        }

        for (Map.Entry<? extends String, ? extends List<String>> entry : map.entrySet()) {
            put(entry.getKey(), entry.getValue());
        }
    }
}
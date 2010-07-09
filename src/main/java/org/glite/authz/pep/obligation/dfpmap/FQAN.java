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
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

import org.glite.authz.common.util.Strings;

/** A FQAN (fully qualified attribute name). */
public class FQAN {

    /** The allowed characters in the components of an FQAN (group component ID, attribute ID, and attribute value). */
    public static final String fqanComponentCharactersRegex = "[_\\w\\.\\-\\*]+";

    /** ID of the {@value} attribute. */
    public static final String ROLE_ATTRIB_ID = "Role";

    /** ID of the {@value} attribute. */
    public static final String CAPABILITY_ATTRIB_ID = "Capability";

    /** The group component of the FQAN. */
    private String attributeGroupId;

    /** The role component of the FQAN. */
    private Map<String, Attribute> attributes;

    /**
     * Constructor.
     * 
     * @param groupId the ID of the attribute group
     * @param groupAttributes the attributes in the group
     */
    public FQAN(String groupId, Collection<Attribute> groupAttributes) {
        attributeGroupId = groupId;

        if (groupAttributes != null) {
            TreeMap<String, Attribute> modifiableAttributes = new TreeMap<String, Attribute>();
            for (Attribute attribute : groupAttributes) {
                modifiableAttributes.put(attribute.getId(), attribute);
            }
            attributes = modifiableAttributes;
        } else {
            attributes = Collections.emptyMap();
        }
    }

    /**
     * Gets the ID of the attribute group.
     * 
     * @return ID of the attribute group
     */
    public String getAttributeGroupId() {
        return attributeGroupId;
    }

    /**
     * Gets the attributes.
     * 
     * @return the attributes
     */
    public Collection<Attribute> getAttributes() {
        return attributes.values();
    }

    /**
     * Gets the IDs of the attributes.
     * 
     * @return IDs of the attributes
     */
    public Collection<String> getAttributeIds() {
        return attributes.keySet();
    }

    /**
     * Gets an attribute by its ID.
     * 
     * @param id id of the attribute
     * 
     * @return the attribute with the given ID or null if there is no attribute with that ID
     */
    public Attribute getAttributeById(String id) {
        return attributes.get(id);
    }

    /** {@inheritDoc} */
    public String toString() {
        StringBuilder fqanStr = new StringBuilder(getAttributeGroupId());

        Attribute attribute;
        for (String id : attributes.keySet()) {
            attribute = attributes.get(id);
            fqanStr.append("/").append(attribute.getId());
            fqanStr.append("=").append(attribute.getValue());
        }

        return fqanStr.toString();
    }

    /** {@inheritDoc} */
    public int hashCode() {
        return toString().hashCode();
    }

    /** {@inheritDoc} */
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }

        if (obj == null) {
            return false;
        }

        if (obj instanceof FQAN) {
            FQAN otherFQAN = (FQAN) obj;

            boolean equalIds = attributeGroupId.equals(otherFQAN.attributeGroupId);
            boolean equalAttributes = attributes.equals(otherFQAN.attributes);

            return equalIds && equalAttributes;
        }

        return false;
    }

    /** An attribute with an FQAN. */
    public static class Attribute {

        /** The string representing a null value, {@value} . */
        public static final String NULL_VALUE = "NULL";

        /** The ID of the attribute. */
        private String id;

        /** The value of the attribute. */
        private String value;

        /**
         * Constructor.
         * 
         * @param attributeId ID of the attribute
         * @param attributeValue value of the attribute
         */
        public Attribute(String attributeId, String attributeValue) {
            id = attributeId;
            value = attributeValue;
        }

        /**
         * Parses an FQAN attribute string. An FQAN attribute string takes the format {@literal <id>=<value>} where the
         * both the id and value contain only a-z, A-Z, underscore, hyphen, period, and asterisk characters. The value
         * must contain at least on of the allowed characters, the value must contain zero or more allowed characters.
         * If no characters are included in the value of the attribute is considered to be the null value
         * {@value #NULL_VALUE}.
         * 
         * @param attributeString the string to parse
         * 
         * @return the constructed attribute
         * 
         * @throws IllegalArgumentException thrown if the FQAN contains illegal characters or is not in the proper
         *             {@literal <id>=<value>} format
         */
        public static Attribute parse(String attributeString) throws IllegalArgumentException {
            if (!attributeString.contains("=")) {
                throw new IllegalArgumentException("FQAN attribute " + attributeString
                        + " does not contain an equals sign");
            }

            String[] components = attributeString.split("=");

            String id = Strings.safeTrim(components[0]);
            if (!id.matches(fqanComponentCharactersRegex)) {
                throw new IllegalArgumentException("FQAN attribute " + attributeString
                        + " contains illegal characters within its id");
            }

            String value;
            if (components.length == 1) {
                value = NULL_VALUE;
            } else {
                value = Strings.safeTrimOrNullString(components[1]);
                if ("NULL".equals(value)) {
                    value = NULL_VALUE;
                } else {
                    if (!value.matches(fqanComponentCharactersRegex)) {
                        throw new IllegalArgumentException("FQAN attribute " + attributeString
                                + " contains illegal characters within its value");
                    }
                }
            }

            return new Attribute(id, value);
        }

        /**
         * Gets the ID of the attribute.
         * 
         * @return ID of the attribute
         */
        public String getId() {
            return id;
        }

        /**
         * Gets the value of the attribute.
         * 
         * @return value of the attribute
         */
        public String getValue() {
            return value;
        }

        /** {@inheritDoc} */
        public String toString() {
            return "Attribute { id: " + id + ", value: " + value + "}";
        }

        /** {@inheritDoc} */
        public int hashCode() {
            int hash = 13;

            hash = 31 * hash + (null == id ? 0 : id.hashCode());
            hash = 31 * hash + (null == value ? 0 : value.hashCode());

            return hash;
        }

        /** {@inheritDoc} */
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }

            if (obj == null || !(obj instanceof FQAN.Attribute)) {
                return false;
            }

            FQAN.Attribute otherAttribute = (FQAN.Attribute) obj;

            boolean equalIds = Strings.safeEquals(id, otherAttribute.getId());
            boolean equalValues = Strings.safeEquals(value, otherAttribute.getValue());

            return equalIds && equalValues;
        }
    }

    /**
     * Parses an FQAN.
     * 
     * @param fqanString the FQAN string to parse
     * 
     * @return the FQAN
     * 
     * @throws IllegalArgumentException thrown if the FQAN is not valid either because its format is wrong or one of
     *             its components contains invalid characters
     */
    public static FQAN parseFQAN(String fqanString) throws IllegalArgumentException {
        String trimmedStr = Strings.safeTrimOrNullString(fqanString);
        if (trimmedStr == null) {
            throw new NullPointerException("FQAN string may not be null or empty");
        }

        if (!trimmedStr.startsWith("/")) {
            throw new IllegalArgumentException("FQAN " + trimmedStr + " does not start with a '/'");
        }

        String[] components = fqanString.split("/");
        String component;
        boolean encounteredAttribute = false;
        StringBuilder groupIdBuilder = new StringBuilder();
        ArrayList<Attribute> attributes = new ArrayList<Attribute>();
        // we start with 1 since nothing precedes the first '/' in a FQAN
        for (int i = 1; i < components.length; i++) {
            component = components[i];
            if (!encounteredAttribute && component.contains("=")) {
                encounteredAttribute = true;
            }

            if (!encounteredAttribute) {
                if (!component.matches(FQAN.fqanComponentCharactersRegex)) {
                    throw new IllegalArgumentException("FQAN" + fqanString
                            + " contains an invalid character in the group ID component " + component);
                }
                groupIdBuilder.append("/").append(component);
            } else {
                attributes.add(Attribute.parse(component));
            }
        }

        return new FQAN(groupIdBuilder.toString(), attributes);
    }
}
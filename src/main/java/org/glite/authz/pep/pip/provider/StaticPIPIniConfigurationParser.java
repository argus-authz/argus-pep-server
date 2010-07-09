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

package org.glite.authz.pep.pip.provider;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.config.AbstractConfigurationBuilder;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.config.IniConfigUtil;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.pep.pip.IniPIPConfigurationParser;
import org.glite.authz.pep.pip.PolicyInformationPoint;
import org.glite.authz.common.util.Files;
import org.glite.authz.common.util.Strings;
import org.ini4j.Ini;
import org.ini4j.Ini.Section;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Configuration parser for {@link StaticPIP}. */
@ThreadSafe
public class StaticPIPIniConfigurationParser implements IniPIPConfigurationParser {

    /**
     * The name of the {@value} property which gives the absolute path the file containing the definition for the static
     * attributes.
     */
    public static final String CONFIG_FILE_PROP = "staticAttributesFile";

    /** The name of the {@value} property which gives a default issuer for all static attributes. */
    public static final String DEFAULT_ATTRIBUTE_ISSUER_PROP = "defaultAttributeIssuer";

    /**
     * The name of the {@value} property which indicates whether the static resource attributes should be included in
     * all resources in the request.
     */
    public static final String RESOURCE_ATTRIBUTES_IN_ALL_PROP = "includeResourceAttribtuesInAllResources";

    /**
     * The name of the {@value} property which indicates whether the static subject attributes should be included in all
     * subject in the request.
     */
    public static final String SUBJECT_ATTRIBUTES_IN_ALL_PROP = "includeSubjectAttribtuesInAllSubjects";

    /** The name of the {@value} property which gives the space delimited list of action attributes. */
    public static final String ACTION_ATTRIBS_PROP = "actionAttributes";

    /** The name of the {@value} property which gives the space delimited list of environment attributes. */
    public static final String ENVIRONMENT_ATTRIBS_PROP = "environmentAttributes";

    /** The name of the {@value} property which gives the space delimited list of resource attributes. */
    public static final String RESOURCE_ATTRIBS_PROP = "resourceAttributes";

    /** The name of the {@value} property which gives the space delimited list of subject attributes. */
    public static final String SUBJECT_ATTRIBS_PROP = "subjectAttributes";

    /** The name of the {@value} attribute definition property which gives the ID of the static attribute. */
    public static final String ATTRIBUTE_ID_PROP = "id";

    /** The name of the {@value} attribute definition property which gives the ID of the static attribute. */
    public static final String ATTRIBUTE_DT_PROP = "datatype";

    /** The name of the {@value} attribute definition property which gives the issuer of the static attribute. */
    public static final String ATTRIBUTE_ISSUER_PROP = "issuer";

    /** The name of the {@value} attribute definition property which gives the values of the static attribute. */
    public static final String ATTRIBUTE_VALUE_PROP = "values";

    /**
     * The name of the {@value} attribute definition property which gives the delimiter used in the
     * {@value #ATTRIBUTE_VALUE_PROP} property.
     */
    public static final String ATTRIBUTE_VALUE_DELIM_PROP = "valueDelimiter";

    /** The default value of the {@value #ATTRIBUTE_VALUE_DELIM_PROP} property: {@value} . */
    public static final String DEFAULT_VALUE_DELIM = ",";

    /** The default value of the {@value #RESOURCE_ATTRIBUTES_IN_ALL_PROP} property: {@value} . */
    public static final boolean DEFAULT_RESOURCE_ATTRIBUTES_IN_ALL = false;

    /** The default value of the {@value #SUBJECT_ATTRIBUTES_IN_ALL_PROP} property: {@value} . */
    public static final boolean DEFAULT_SUBJECT_ATTRIBUTES_IN_ALL = false;

    /** The default value of the {@value #ATTRIBUTE_DT_PROP} property: {@value} . */
    public static final String DEFAULT_ATTRIBUTE_DT = Attribute.DT_STRING;

    /** Class logger. */
    private Logger log = LoggerFactory.getLogger(StaticPIPIniConfigurationParser.class);

    /** {@inheritDoc} */
    public PolicyInformationPoint parse(Section iniConfig, AbstractConfigurationBuilder<?> configBuilder)
            throws ConfigurationException {
        Ini iniFile = readIniFile(iniConfig.get(CONFIG_FILE_PROP));

        String pipId = Strings.safeTrimOrNullString(iniConfig.getName());

        String defaultAttributeIssuer = Strings.safeTrimOrNullString(IniConfigUtil.getString(iniConfig,
                DEFAULT_ATTRIBUTE_ISSUER_PROP, null));
        log.info("default attribute issuer: {}", (defaultAttributeIssuer == null) ? "none" : defaultAttributeIssuer);

        List<Attribute> actionAttributes = parseAttributes(iniFile, IniConfigUtil.getString(iniConfig,
                ACTION_ATTRIBS_PROP, null), defaultAttributeIssuer);
        log.info("action attributes: {} ", pipId, actionAttributes);

        List<Attribute> environmentAttributes = parseAttributes(iniFile, IniConfigUtil.getString(iniConfig,
                ENVIRONMENT_ATTRIBS_PROP, null), defaultAttributeIssuer);
        log.info("envrionment attributes: {}", pipId, environmentAttributes);

        List<Attribute> resourceAttributes = parseAttributes(iniFile, IniConfigUtil.getString(iniConfig,
                RESOURCE_ATTRIBS_PROP, null), defaultAttributeIssuer);
        log.info("resource attributes: {}", pipId, resourceAttributes);

        List<Attribute> subjectAttributes = parseAttributes(iniFile, IniConfigUtil.getString(iniConfig,
                SUBJECT_ATTRIBS_PROP, null), defaultAttributeIssuer);
        log.info("subject attributes: {}", pipId, subjectAttributes);

        StaticPIP pip = new StaticPIP(pipId, actionAttributes, environmentAttributes, resourceAttributes,
                subjectAttributes);

        boolean resourceAttributesInAllResource = IniConfigUtil.getBoolean(iniConfig, RESOURCE_ATTRIBUTES_IN_ALL_PROP,
                DEFAULT_RESOURCE_ATTRIBUTES_IN_ALL);
        log
                .info("resource attributes will be applied to all resources in request: {}",
                        resourceAttributesInAllResource);
        pip.setAddAttributesToAllResources(resourceAttributesInAllResource);

        boolean subjectAttributesInAllSubject = IniConfigUtil.getBoolean(iniConfig, SUBJECT_ATTRIBUTES_IN_ALL_PROP,
                DEFAULT_SUBJECT_ATTRIBUTES_IN_ALL);
        log.info("subject attributes will be applied to all subject in request: {}", subjectAttributesInAllSubject);
        pip.setAddAttributesToAllSubjects(subjectAttributesInAllSubject);

        return pip;
    }

    /**
     * Reads in the static attributes configuration file.
     * 
     * @param filePath the path to the configuration file
     * 
     * @return the parsed INI file
     * 
     * @throws ConfigurationException thrown if the INI file is invalid
     */
    private Ini readIniFile(String filePath) throws ConfigurationException {
        File staticAttributesFile = null;

        try {
            staticAttributesFile = Files.getReadableFile(filePath);
        } catch (IOException e) {
            throw new ConfigurationException(e.getMessage());
        }

        Ini iniFile = new Ini();
        try {
            iniFile.load(new FileReader(staticAttributesFile));
        } catch (Exception e) {
            throw new ConfigurationException("Unable to parse static attribtues file " + filePath, e);
        }

        return iniFile;
    }

    /**
     * Creates a collection of {@link Attribute} objects from a list of configuration sections that contain attribute
     * definitions.
     * 
     * @param configFile the INI configuration file
     * @param attributeSectionNamess a space delimited list of section names that contain attribute definitions
     * @param defaultAttributeIssuer the default value to use as attribute issuer, or null if there is no default value
     * 
     * @return the list of constructed attributes
     * 
     * @throws ConfigurationException throw if required data is not present
     */
    private List<Attribute> parseAttributes(Ini configFile, String attributeSectionNamess, String defaultAttributeIssuer)
            throws ConfigurationException {
        List<String> sectionNames = Strings.toList(attributeSectionNamess, " ");
        if (sectionNames == null) {
            return null;
        }

        List<Attribute> attributes = new ArrayList<Attribute>();
        Section configSection = null;
        for (String sectionName : sectionNames) {
            configSection = configFile.get(sectionName);
            if (configSection == null) {
                String errorMsg = "INI section " + sectionName
                        + " does not exist but was listed as an attribute definition section";
                log.error(errorMsg);
                throw new ConfigurationException(errorMsg);
            }

            attributes.add(parseAttributeDefinition(configSection, defaultAttributeIssuer));
        }

        return attributes;
    }

    /**
     * Creates an {@link Attribute} from a INI configuration section containing the following properties.
     * 
     * <ul>
     * <li>{@value #ATTRIBUTE_ID_PROP} - required - contains the ID of the attribute</li>
     * <li>{@value #ATTRIBUTE_DT_PROP} - optional - contains the datatype of the attribute, defaults to
     * {@value Attribute#DT_STRING}</li>
     * <li>{@value #ATTRIBUTE_ISSUER_PROP} - optional - contains the issuer of the attribute, defaults to the value of
     * the {@value #DEFAULT_ATTRIBUTE_ISSUER_PROP} if this property was set</li>
     * <li>{@value #ATTRIBUTE_VALUE_PROP} - required - contains a delimited list of attribute values</li>
     * <li>{@value #ATTRIBUTE_VALUE_DELIM_PROP} - optional - delimiter used in {@value #ATTRIBUTE_VALUE_PROP} property,
     * defaults to ',' (comma)</li>
     * </ul>
     * 
     * @param configSection configuration section containing the attribute definition
     * @param defaultAttributeIssuer the default attribute issuer, if there is one
     * 
     * @return the constructed attribute definition
     * 
     * @throws ConfigurationException thrown if any required data is missing
     */
    private Attribute parseAttributeDefinition(Section configSection, String defaultAttributeIssuer)
            throws ConfigurationException {
        if (configSection == null) {
            return null;
        }

        Attribute attribute = new Attribute();
        attribute.setId(IniConfigUtil.getString(configSection, ATTRIBUTE_ID_PROP));
        attribute.setDataType(IniConfigUtil.getString(configSection, ATTRIBUTE_DT_PROP, DEFAULT_ATTRIBUTE_DT));
        attribute.setIssuer(IniConfigUtil.getString(configSection, ATTRIBUTE_ISSUER_PROP, defaultAttributeIssuer));

        List<String> values = Strings.toList(IniConfigUtil.getString(configSection, ATTRIBUTE_VALUE_PROP),
                IniConfigUtil.getString(configSection, ATTRIBUTE_VALUE_DELIM_PROP, DEFAULT_VALUE_DELIM));
        attribute.getValues().addAll(values);

        log.debug("Created the following attribute definition from INI section {}: {}", configSection.getName(),
                attribute);
        return attribute;
    }
}
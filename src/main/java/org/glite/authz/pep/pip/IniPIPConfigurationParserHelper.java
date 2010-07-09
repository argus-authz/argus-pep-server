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

package org.glite.authz.pep.pip;

import java.util.List;
import java.util.StringTokenizer;

import org.glite.authz.common.config.AbstractConfigurationBuilder;
import org.glite.authz.common.config.AbstractIniConfigurationParser;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.config.IniConfigUtil;
import org.glite.authz.common.util.LazyList;
import org.glite.authz.common.util.Strings;
import org.ini4j.Ini;
import org.ini4j.Ini.Section;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Helper for parsing configuration files which contain {@link PolicyInformationPoint} declarations. */
public class IniPIPConfigurationParserHelper {

    /** The name of the {@value} which gives the space-delimited lists of to-be-configured PIPs. */
    public static final String PIP_PROP = "pips";

    /** Class logger. */
    private static final Logger LOG = LoggerFactory.getLogger(IniPIPConfigurationParserHelper.class);

    /**
     * Processing the {@value #PIP_PROP} configuration property, if there is one.
     * 
     * @param iniFile INI configuration file being processed
     * @param configSection current configuration section being processed
     * @param configBuilder current builder being constructed from the parser
     * 
     * @return policy information points loaded based on the given configuration
     * 
     * @throws ConfigurationException thrown if there is a problem building the policy information points
     */
    public static List<PolicyInformationPoint> processPolicyInformationPoints(Ini iniFile, Section configSection,
            AbstractConfigurationBuilder<?> configBuilder) throws ConfigurationException {
        List<PolicyInformationPoint> pips = new LazyList<PolicyInformationPoint>();
        if (configSection.containsKey(PIP_PROP)) {
            String pipName;
            StringTokenizer pipNames = new StringTokenizer(configSection.get(PIP_PROP), " ");
            while (pipNames.hasMoreTokens()) {
                pipName = Strings.safeTrimOrNullString(pipNames.nextToken());
                if (pipName != null) {
                    if (!iniFile.containsKey(pipName)) {
                        String errorMsg = "INI configuration file does not contain a configuration section for policy information point "
                                + pipName;
                        LOG.error(errorMsg);
                        throw new ConfigurationException(errorMsg);
                    }
                    pips.add(buildPolicyInformationPoint(iniFile.get(pipName), configBuilder));
                    LOG.debug("loadded policy information point: {}", pipName);
                }
            }
        }
        return pips;
    }

    /**
     * Processes each individual PIP configuration section.
     * 
     * @param pipConfig the PIP configuration section
     * @param configBuilder configuration builder currently being populated
     * 
     * @return the PIP configured with the information provided in the configuration section
     * 
     * @throws ConfigurationException throw if a PIP can not be instantiated
     */
    @SuppressWarnings("unchecked")
    private static PolicyInformationPoint buildPolicyInformationPoint(Section pipConfig,
            AbstractConfigurationBuilder<?> configBuilder) throws ConfigurationException {
        LOG.info("Loading Policy Information Point {}", pipConfig.getName());
        String parserClassName = IniConfigUtil.getString(pipConfig, IniPIPConfigurationParser.PARSER_CLASS_PROP);

        try {
            Class<IniPIPConfigurationParser> parserClass = (Class<IniPIPConfigurationParser>) AbstractIniConfigurationParser.class
                    .getClassLoader().loadClass(parserClassName);
            IniPIPConfigurationParser parser = parserClass.getConstructor().newInstance();
            return parser.parse(pipConfig, configBuilder);
        } catch (Exception e) {
            throw new ConfigurationException("Unable to configure PIP " + pipConfig.getName()
                    + ". The following error was reported: " + e.getMessage(), e);
        }
    }
}
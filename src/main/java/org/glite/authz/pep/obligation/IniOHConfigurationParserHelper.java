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

package org.glite.authz.pep.obligation;

import java.util.StringTokenizer;

import org.glite.authz.common.config.AbstractConfigurationBuilder;
import org.glite.authz.common.config.AbstractIniServiceConfigurationParser;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.config.IniConfigUtil;
import org.glite.authz.common.util.Strings;
import org.ini4j.Ini;
import org.ini4j.Ini.Section;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Helper for parsing configuration files which contain {@link AbstractObligationHandler} declarations. */
public class IniOHConfigurationParserHelper {

    /** The name of the {@value} which gives the space-delimited lists of to-be-configured obligation handlers. */
    public static final String OH_PROP = "obligationHandlers";

    /** Class logger. */
    private static final Logger LOG = LoggerFactory.getLogger(IniOHConfigurationParserHelper.class);

    /**
     * Processing the {@value #OH_PROP} configuration property, if there is one.
     * 
     * @param iniFile INI configuration file being processed
     * @param configSection current configuration section being processed
     * @param configBuilder current builder being constructed from the parser
     * 
     * @return obligation processing service
     * 
     * @throws ConfigurationException thrown if there is a problem building the obligations handlers
     */
    public static ObligationService processObligationHandlers(Ini iniFile, Section configSection,
            AbstractConfigurationBuilder<?> configBuilder) throws ConfigurationException {
        ObligationService service = new ObligationService();
        if (configSection.containsKey(OH_PROP)) {
            StringTokenizer obligationHandlers = new StringTokenizer(configSection.get(OH_PROP), " ");
            String obligationHandlerName;
            while (obligationHandlers.hasMoreTokens()) {
                obligationHandlerName = Strings.safeTrimOrNullString(obligationHandlers.nextToken());
                if (!iniFile.containsKey(obligationHandlerName)) {
                    String errorMsg = "INI configuration file does not contain a configuration section for obligation handler "
                            + obligationHandlerName;
                    LOG.error(errorMsg);
                    throw new ConfigurationException(errorMsg);
                }
                if (obligationHandlerName != null) {
                    service.addObligationhandler(buildObligationHandler(iniFile.get(obligationHandlerName),
                            configBuilder));
                    LOG.info("Added obligation handler: {}", obligationHandlerName);
                }
            }
        }
        return service;
    }

    /**
     * Processes each individual Obligation Handler configuration section.
     * 
     * @param ohConfig the obligation handler configuration section
     * @param configBuilder configuration builder currently being populated
     * 
     * @return the obligation handler configured with the information provided in the configuration section
     * 
     * @throws ConfigurationException throw if a obligation handler can not be instantiated
     */
    @SuppressWarnings("unchecked")
    private static ObligationHandler buildObligationHandler(Section ohConfig,
            AbstractConfigurationBuilder<?> configBuilder) throws ConfigurationException {
        LOG.info("Loading Obligation Handler {}", ohConfig.getName());
        String parserClassName = IniConfigUtil.getString(ohConfig, IniOHConfigurationParser.PARSER_CLASS_PROP);

        try {
            Class<IniOHConfigurationParser> parserClass = (Class<IniOHConfigurationParser>) AbstractIniServiceConfigurationParser.class
                    .getClassLoader().loadClass(parserClassName);
            IniOHConfigurationParser parser = parserClass.getConstructor().newInstance();
            return parser.parse(ohConfig, configBuilder);
        } catch (Exception e) {
            throw new ConfigurationException("Unable to configure Obligation Handler " + ohConfig.getName()
                    + ". The following error was reported: " + e.getMessage(), e);
        }
    }
}
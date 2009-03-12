/*
 * Copyright 2008 EGEE Collaboration
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.glite.authz.pep.server.config;

import java.io.Reader;
import java.io.StringReader;
import java.util.StringTokenizer;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.config.AbstractIniServiceConfigurationParser;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.config.IniConfigUtil;
import org.ini4j.Ini;
import org.ini4j.Ini.Section;
import org.opensaml.ws.soap.client.http.HttpClientBuilder;
import org.opensaml.ws.soap.client.http.HttpSOAPClient;
import org.opensaml.xml.parse.BasicParserPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Parser for a {@link org.glite.authz.pep.server.PEPDaemon} configuration file. */
@ThreadSafe
public final class PEPDaemonIniConfigurationParser extends AbstractIniServiceConfigurationParser<PEPDaemonConfiguration> {

    /** The name of the {@value} INI header which contains the property for configuring the PDP interaction. */
    public static final String PDP_SECTION_HEADER = "PDP";

    /** The name of the {@value} property which gives the space-delimited PDP endpoint URLs. */
    public static final String PDP_PROP = "pdps";
    
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(PEPDaemonIniConfigurationParser.class);

    /** Constructor. */
    public PEPDaemonIniConfigurationParser() {
    }

    /** {@inheritDoc} */
    public PEPDaemonConfiguration parse(Reader iniReader) throws ConfigurationException {
        return parseIni(iniReader);
    }

    /** {@inheritDoc} */
    public PEPDaemonConfiguration parse(String iniString) throws ConfigurationException {
        return parseIni(new StringReader(iniString));
    }

    /**
     * Parses a configuration.
     * 
     * @param iniReader INI to parse
     * 
     * @return the daemon configuration
     * 
     * @throws ConfigurationException thrown if there is a problem configuring the system
     */
    private PEPDaemonConfiguration parseIni(Reader iniReader) throws ConfigurationException {
        PEPDaemonConfigurationBuilder configBuilder = new PEPDaemonConfigurationBuilder();

        Ini daemonIni = new Ini();
        try {
            daemonIni.load(iniReader);
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }
        
        processServiceSection(daemonIni, configBuilder);
        processPDPConfiguration(daemonIni, configBuilder);

        return configBuilder.build();
    }

    /**
     * Processes the PDP configuration section.
     * 
     * @param iniFile the INI configuration file
     * @param configBuilder the daemon configuration builder
     * 
     * @throws ConfigurationException thrown if the communication to the PDP can be configured
     */
    private void processPDPConfiguration(Ini iniFile, PEPDaemonConfigurationBuilder configBuilder)
            throws ConfigurationException {
        Section configSection = iniFile.get(PDP_SECTION_HEADER);
        if (configSection == null) {
            String errorMsg = "INI configuration does not contain the rquired '" + PDP_SECTION_HEADER
                    + "' INI section";
            log.error(errorMsg);
            throw new ConfigurationException(errorMsg);
        }

        String pdpEndpointStr = IniConfigUtil.getString(configSection, PDP_PROP);
        log.debug("PDP endpoints: {}", pdpEndpointStr);
        StringTokenizer pdpEndpoints = new StringTokenizer(pdpEndpointStr, " ");
        while (pdpEndpoints.hasMoreTokens()) {
            configBuilder.getPDPEndpoints().add(pdpEndpoints.nextToken());
        }

        HttpClientBuilder soapClientBuilder = buildSOAPClientBuilder(configSection);
        BasicParserPool parserPool = new BasicParserPool();
        parserPool.setMaxPoolSize(soapClientBuilder.getMaxTotalConnections());
        configBuilder.setSoapClient(new HttpSOAPClient(soapClientBuilder.buildClient(), parserPool));
    }
}
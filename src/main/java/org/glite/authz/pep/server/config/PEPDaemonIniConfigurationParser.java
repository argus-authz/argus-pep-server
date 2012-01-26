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

package org.glite.authz.pep.server.config;

import java.io.Reader;
import java.io.StringReader;
import java.util.List;
import java.util.StringTokenizer;

import javax.net.ssl.X509TrustManager;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.config.AbstractIniServiceConfigurationParser;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.config.IniConfigUtil;
import org.glite.authz.pep.obligation.IniOHConfigurationParserHelper;
import org.glite.authz.pep.obligation.ObligationService;
import org.glite.authz.pep.pip.IniPIPConfigurationParserHelper;
import org.glite.authz.pep.pip.PolicyInformationPoint;
import org.glite.voms.VOMSTrustManager;
import org.ini4j.Ini;
import org.opensaml.ws.soap.client.http.HttpClientBuilder;
import org.opensaml.ws.soap.client.http.HttpSOAPClient;
import org.opensaml.xml.parse.BasicParserPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Parser for a {@link org.glite.authz.pep.server.PEPDaemon} configuration file. */
@ThreadSafe
public class PEPDaemonIniConfigurationParser extends AbstractIniServiceConfigurationParser<PEPDaemonConfiguration> {

    /** The name of the {@value} INI header which contains the property for configuring the PDP interaction. */
    public static final String PDP_SECTION_HEADER = "PDP";

    /** The name of the {@value} property which gives the space-delimited PDP endpoint URLs. */
    public static final String PDP_PROP = "pdps";

    /**
     * The name of the {@value} property which gives the maximum number of responses that will be cached. A value of
     * zero will disable caching.
     */
    public static final String MAX_CACHED_RESP_PROP = "maximumCachedResponses";

    /** The name of the {@value} property which gives the time-to-live, in seconds, for a cached item. */
    public static final String CACHED_RESP_TTL_PROP = "cachedResponseTTL";

    /** Default value of the {@value AbstractIniServiceConfigurationParser#PORT_PROP} property, {@value} . */
    public static final int DEFAULT_PORT = 8154;

    /** Default value of the {@value AbstractIniServiceConfigurationParser#ADMIN_PORT_PROP} property, {@value} . */
    public static final int DEFAULT_ADMIN_PORT = 8155;

    /** Default value of the {@value #MAX_CACHED_RESP_PROP} property, {@value} . */
    public static final int DEFAULT_MAX_CACHED_RESP = 500;

    /** Default value of the {@value #CACHED_RESP_TTL_PROP} property, {@value} . */
    public static final int DEFAULT_CACHED_RESP_TTL = 10 * 60;

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(PEPDaemonIniConfigurationParser.class);

    /** Constructor. */
    public PEPDaemonIniConfigurationParser() {
        super();
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
     * {@inheritDoc}
     * 
     * @return the port value, or the default port {@value #DEFAULT_PORT} if it is not set
     */
    protected int getPort(Ini.Section configSection) {
        return IniConfigUtil.getInt(configSection, PORT_PROP, DEFAULT_PORT, 1, 65535);
    }

    /** 
     * {@inheritDoc}
     * 
     * @return the admin port value, or the default admin port {@value #DEFAULT_ADMIN_PORT} if it is not set
     */
    protected int getAdminPort(Ini.Section configSection) {
        return IniConfigUtil.getInt(configSection, ADMIN_PORT_PROP, DEFAULT_ADMIN_PORT, 1, 65535);
    }

    /**
     * Gets the value of the {@value #CACHED_RESP_TTL_PROP} property from the configuration section. If the property is
     * not present or is not valid the default value of {@value #DEFAULT_CACHED_RESP_TTL} will be used.
     * 
     * @param configSection configuration section from which to extract the value
     * 
     * @return the value
     */
    protected int getCacheResponseTTL(Ini.Section configSection) {
        return IniConfigUtil.getInt(configSection, CACHED_RESP_TTL_PROP, DEFAULT_CACHED_RESP_TTL, 1, Integer.MAX_VALUE);
    }

    /**
     * Gets the value of the {@value #MAX_CACHED_RESP_PROP} property from the configuration section. If the property is
     * not present or is not valid the default value of {@value #DEFAULT_MAX_CACHED_RESP} will be used.
     * 
     * @param configSection configuration section from which to extract the value
     * 
     * @return the value
     */
    protected int getMaxCachedResponses(Ini.Section configSection) {
        return IniConfigUtil.getInt(configSection, MAX_CACHED_RESP_PROP, DEFAULT_MAX_CACHED_RESP, 0, Integer.MAX_VALUE);
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

        Ini iniFile = new Ini();
        try {
            log.info("Loading and parsing INI configuration file");
            iniFile.load(iniReader);
        } catch (Exception e) {
            log.error("Unable to load and parse the INI configuration file", e);
            throw new ConfigurationException("Unable to parse INI configuration file", e);
        }
        
        PEPDaemonConfigurationBuilder configBuilder = new PEPDaemonConfigurationBuilder();

        log.info("Processing PEP Server {} configuration section", SECURITY_SECTION_HEADER);
        processSecuritySection(iniFile, configBuilder);
        
        log.info("Processing PEP Server {} configuration section", SERVICE_SECTION_HEADER);
        processServiceSection(iniFile, configBuilder);
        
        Ini.Section configSection = iniFile.get(SERVICE_SECTION_HEADER);
        List<PolicyInformationPoint> pips = IniPIPConfigurationParserHelper.processPolicyInformationPoints(iniFile,
                configSection, configBuilder);
        log.info("Total policy information points: {}", pips.size());
        configBuilder.getPolicyInformationPoints().addAll(pips);

        ObligationService service = IniOHConfigurationParserHelper.processObligationHandlers(iniFile, configSection,
                configBuilder);
        log.info("Total obligation handlers: {}", service.getObligationHandlers().size());
        configBuilder.setObligationService(service);

        log.info("Processing PEP Server {} configuration section", PDP_SECTION_HEADER);
        processPDPConfiguration(iniFile, configBuilder);

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
        Ini.Section configSection = iniFile.get(PDP_SECTION_HEADER);
        if (configSection == null) {
            String errorMsg = "INI configuration does not contain the required '" + PDP_SECTION_HEADER + "' INI section";
            log.error(errorMsg);
            throw new ConfigurationException(errorMsg);
        }
        String name= configSection.getName();
        String pdpEndpointStr = IniConfigUtil.getString(configSection, PDP_PROP);
        log.info("{}: endpoints: {}", name,pdpEndpointStr);
        StringTokenizer pdpEndpoints = new StringTokenizer(pdpEndpointStr, " ");
        while (pdpEndpoints.hasMoreTokens()) {
            configBuilder.getPDPEndpoints().add(pdpEndpoints.nextToken());
        }

        int maxCachedResponses = getMaxCachedResponses(configSection);
        log.info("{}: max cached responses: {}", name,maxCachedResponses);
        configBuilder.setMaxCachedResponses(maxCachedResponses);

        int cachedResponseTTL = getCacheResponseTTL(configSection) * 1000;
        log.info("{}: cached response TTL: {}ms", name,cachedResponseTTL);
        configBuilder.setCachedResponseTTL(cachedResponseTTL);
        
        try {
            X509TrustManager trustManager = new VOMSTrustManager(configBuilder.getTrustMaterialStore());
            HttpClientBuilder soapClientBuilder = buildSOAPClientBuilder(configSection, configBuilder.getKeyManager(),
                    trustManager);
            BasicParserPool parserPool = new BasicParserPool();
            parserPool.setMaxPoolSize(soapClientBuilder.getMaxTotalConnections());
            configBuilder.setSoapClient(new HttpSOAPClient(soapClientBuilder.buildClient(), parserPool));
        } catch (Exception e) {
            log.error("Unable to create PDP SOAP client",e);
            throw new ConfigurationException("Unable to create PDP SOAP client", e);
        }
    }
}

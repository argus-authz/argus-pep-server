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

import org.glite.authz.common.config.AbstractConfigurationBuilder;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.config.IniConfigUtil;
import org.glite.authz.pep.pip.IniPIPConfigurationParser;
import org.glite.authz.pep.pip.PolicyInformationPoint;
import org.glite.authz.common.util.Files;
import org.glite.voms.PKIStore;
import org.ini4j.Ini.Section;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Configuration parser for {@link AbstractX509PIP} PIPs. */
public abstract class AbstractX509PIPIniConfigurationParser implements IniPIPConfigurationParser {

    /**
     * The name of the {@value} property which determines whether a subject's certificate chain must contain a proxy
     * certificate.
     */
    public static final String REQ_PROXY_PROP = "requireProxy";

    /**
     * The name of the {@value} property the indicates whether PKIX validation will be performed on the certificate
     * chain.
     */
    public static final String PERFORM_PKIX_VALIDATION_PROP = "performPKIXValidation";

    /** The name of the {@value} property which gives the absolute path to the 'vomsdir' directory. */
    public static final String VOMS_INFO_DIR_PROP = "vomsInfoDir";

    /** The name of the {@value} which gives the refresh period, in minutes, for 'vomsdir' information. */
    public static final String VOMS_INFO_REFRESH_PROP = "vomsInfoRefresh";

    /** Default value (1 hour in minutes) of the {@value #VOMS_INFO_REFRESH_PROP} property, {@value} . */
    public static final int DEFAULT_VOMS_INFO_REFRESH = 60;

    /** Default value of {@value #PERFORM_PKIX_VALIDATION_PROP}, {@value} . */
    public static final boolean DEFAULT_PERFORM_PKIX_VALIDATION = true;

    /** Class logger. */
    private Logger log = LoggerFactory.getLogger(AbstractX509PIPIniConfigurationParser.class);

    /** {@inheritDoc} */
    public PolicyInformationPoint parse(Section iniConfig, AbstractConfigurationBuilder<?> configurationBuilder)
            throws ConfigurationException {
        boolean requireProxy = IniConfigUtil.getBoolean(iniConfig, REQ_PROXY_PROP, false);
        log.info("subject proxy certificate required: {}", requireProxy);

        PKIStore acTrustMaterial = null;
        String vomsInfoDir = IniConfigUtil.getString(iniConfig, VOMS_INFO_DIR_PROP, null);
        if (vomsInfoDir != null) {
            log.info("voms info directory: {}", vomsInfoDir);
            // get refresh interval: default 1h
            int vomsInfoRefresh = IniConfigUtil.getInt(iniConfig, VOMS_INFO_REFRESH_PROP, DEFAULT_VOMS_INFO_REFRESH, 1,
                    Integer.MAX_VALUE);
            // minute -> millis
            vomsInfoRefresh = vomsInfoRefresh * 60 * 1000;
            log.info("voms info refresh interval: {}ms", vomsInfoRefresh);
            try {
                Files.getFile(vomsInfoDir, false, true, true, false);
                acTrustMaterial = new PKIStore(vomsInfoDir, PKIStore.TYPE_VOMSDIR);
                acTrustMaterial.rescheduleRefresh(vomsInfoRefresh);
            } catch (Exception e) {
                throw new ConfigurationException("Unable to read VOMS AC validation information", e);
            }
        }

        boolean performPKIXValidation = IniConfigUtil.getBoolean(iniConfig, PERFORM_PKIX_VALIDATION_PROP,
                DEFAULT_PERFORM_PKIX_VALIDATION);
        log.info("perform PKIX validation on cert chains: {}", performPKIXValidation);

        return buildInformationPoint(iniConfig.getName(), requireProxy, configurationBuilder.getTrustMaterialStore(),
                acTrustMaterial, performPKIXValidation);
    }

    /**
     * Builds the instance of the policy information point given the parsed configuration.
     * 
     * @param id ID of the PIP
     * @param requireProxy whether proxy certificates are required
     * @param trustMaterial the trust anchors used for validating user certificates
     * @param acTrustMaterial the trust anchors used for validating attribute certificates
     * @param performPKIXValidation whether PKIX validation should be performed
     * 
     * @return the constructed information point
     * 
     * @throws ConfigurationException thrown if there is a problem building the PIP with the given configuration
     *             parameters
     */
    protected abstract AbstractX509PIP buildInformationPoint(String id, boolean requireProxy, PKIStore trustMaterial,
            PKIStore acTrustMaterial, boolean performPKIXValidation) throws ConfigurationException;
}
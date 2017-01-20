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
import org.glite.authz.common.config.IniSectionConfigurationParser;
import org.glite.authz.common.util.Strings;
import org.glite.authz.pep.pip.PolicyInformationPoint;

import org.ini4j.Ini;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Configuration parser for an {@link EnvironmentTimePIP}. */
public class EnvironmentTimePIPIniConfigurationParser implements
        IniSectionConfigurationParser<PolicyInformationPoint> {

    /**
     * The name of the {@value} property to use UTC timezone (#dateTime, #date
     * and #time with the <code>Z</code> indicator) or to use local timezone
     * (#dateTime, #date and #time with the <code>+/-HH:MM</code> indicator)
     */
    public static final String USE_UTC_TIMEZONE_PROP= "useUTCTimeZone";

    /** Default value of the {@value #USE_UTC_TIMEZONE_PROP} property: {@value} */
    public static final boolean DEFAULT_USE_UTC_TIMEZONE= true;

    /** logger */
    private static final Logger LOG= LoggerFactory.getLogger(EnvironmentTimePIP.class);

    /** {@inheritDoc} */
    public PolicyInformationPoint parse(Ini.Section iniConfig,
                                        AbstractConfigurationBuilder<?> configBuilder)
            throws ConfigurationException {
        String pipid= Strings.safeTrimOrNullString(iniConfig.getName());
        EnvironmentTimePIP pip= new EnvironmentTimePIP(pipid);
        boolean useUTC= IniConfigUtil.getBoolean(iniConfig, USE_UTC_TIMEZONE_PROP, DEFAULT_USE_UTC_TIMEZONE);
        LOG.info("{}: uses UTC time zone: {}", pipid, useUTC);
        pip.setUTC(useUTC);
        return pip;
    }
}

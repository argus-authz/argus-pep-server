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
 *
 * Authors:
 * 2016-
 *    Mischa Salle <msalle@nikhef.nl>
 *    Rens Visser <rensv@nikhef.nl>
 *    NIKHEF Amsterdam, the Netherlands
 *    <grid-mw-security@nikhef.nl>
 */

package org.glite.authz.pep.pip.provider;

import org.glite.authz.common.config.AbstractConfigurationBuilder;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.config.IniSectionConfigurationParser;
import org.glite.authz.pep.pip.PolicyInformationPoint;

import org.ini4j.Ini;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import static java.lang.String.format;

/**
 * The configuration parser for the PolicyNamesPIP.
 * @author Mischa Salle, Rens Visser
 */
public class PolicyNamesPIPIniConfigurationParser
    implements IniSectionConfigurationParser<PolicyInformationPoint>
{
    /** Class logger. */
    private static final Logger LOG = LoggerFactory.getLogger( PolicyNamesPIPIniConfigurationParser.class);

    /**
     * Name of the {@value} property in ini file which defines the directory
     * where the .info files are located.
     * @see PolicyNamesPIP#setTrustDir(String)
     */
    private final static String TRUSTDIR_KEY = "trustInfoDir";

    /**
     * Name of the {@value} property in ini file which defines the time interval
     * after which the .info files are reprocessed.
     * @see PolicyNamesPIP#setUpdateInterval(long)
     */
    private final static String UPDATEINTERVAL_KEY = "updateInterval";

    /**
     * Name of the {@value} property in ini file which defines the name of the
     * attribute set by this PIP.
     * @see PolicyNamesPIP#setAttributeName(String) */
    private final static String ATTRIBUTENAME_KEY = "policyNamesAttribute";

    /**
     * {@inheritDoc}
     * Creates a {@link PolicyNamesPIP} PIP instance from the information in
     * the corresponding {@link Ini.Section}.
     * @param iniConfig the INI configuration for this obligation handler
     * @param configBuilder the configuration builder currently being populated
     * @return PolicyInformationPoint
     * @throws ConfigurationException
     *     thrown if there is a problem creating the obligation handler from the
     *     given information
     */
    public PolicyInformationPoint parse(Ini.Section iniConfig, AbstractConfigurationBuilder<?> configBuilder)
		    throws ConfigurationException {

	    long updateIntervalLong = -1;

	    // Get configuration values
	    String id = iniConfig.getName();
	    String trustDir = iniConfig.get(TRUSTDIR_KEY);
	    String updateInterval = iniConfig.get(UPDATEINTERVAL_KEY);
	    String attributeName = iniConfig.get(ATTRIBUTENAME_KEY);

	    // Log trustDir (if set)
	    if (trustDir != null)   {
		LOG.debug("Found {} = {}", TRUSTDIR_KEY, trustDir);
	    }

	    // Convert updateInterval to a long (when set)
	    if (updateInterval != null) {
		try {
		    updateIntervalLong = Integer.parseInt(updateInterval);
		} catch (NumberFormatException e)	{
		    throw new ConfigurationException(
			format("Cannot convert %s = %s to a long", UPDATEINTERVAL_KEY, updateInterval));
		}
		if (updateIntervalLong<=0)  {
		    throw new ConfigurationException(
			format("%s should be >0", UPDATEINTERVAL_KEY));
		}
	    }

	    // Instantiate PIP
	    PolicyNamesPIP pip;
	    try {
		if (updateIntervalLong>0)  {
		    // Use update interval
		    LOG.debug("Found {} = {}", UPDATEINTERVAL_KEY, updateIntervalLong);
		    pip = new PolicyNamesPIP(id, trustDir, updateIntervalLong);
		} else	{
		    // Use default update interval
		    pip = new PolicyNamesPIP(id, trustDir);
		}
	    } catch (IOException e) {
		final String errorMsg = format("Could not instantiate PIP: %s", e.getMessage());
		LOG.error(errorMsg, e);
		throw new ConfigurationException(errorMsg, e);
	    }

	    // Set attribute name
	    if (attributeName != null)  {
		LOG.debug("Found {} = {}", ATTRIBUTENAME_KEY, attributeName);
		pip.setAttributeName(attributeName);
	    }

	    // Return new PIP
	    return pip;
    }
}


// Copyright (c) FOM-Nikhef 2015-
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Authors:
// 2016-
//    Mischa Salle <msalle@nikhef.nl>
//    Rens Visser <rensv@nikhef.nl>
//    NIKHEF Amsterdam, the Netherlands
//    <grid-mw-security@nikhef.nl>
//

package org.glite.authz.pep.pip.provider;

import org.glite.authz.common.config.AbstractConfigurationBuilder;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.config.IniSectionConfigurationParser;
import org.glite.authz.pep.pip.PolicyInformationPoint;

import org.ini4j.Ini;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;

/**
 * Configuration parser for a {@link X509ExtractorPIP}.
 * @author Mischa Sall&eacute;, Rens Visser
 */
public class X509ExtractorPIPIniConfigurationParser
    implements IniSectionConfigurationParser<PolicyInformationPoint>
{
    /** Class logger. */
    private Logger log = LoggerFactory.getLogger(PolicyNamesPIPIniConfigurationParser.class);

    /**
     * Name of the {@value} property in ini file which defines the list of
     * handled (to-be-set) attribute IDs.
     * @see X509ExtractorPIP#setAcceptedAttrIDs(AcceptedAttr[])
     */
    private final String ACCEPTED_ATTRS_KEY = "acceptedAttributeIDs";


    /**
     * {@inheritDoc}
     * Creates a {@link X509ExtractorPIP} PIP instance from the information in
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

	// Get configuration values
	String id = iniConfig.getName();
	String acceptedAttributesValue = iniConfig.get(ACCEPTED_ATTRS_KEY);

	// Mandatory argument is missing
	if (acceptedAttributesValue == null)
	    throw new ConfigurationException("No "+ACCEPTED_ATTRS_KEY+" specified, nothing to do");

	// Split list on whitespace
	String[] acceptedAttrName=acceptedAttributesValue.split("\\s+");

	// Value is invalid
	if (acceptedAttrName.length==0)
	    throw new ConfigurationException("Empty value for "+ACCEPTED_ATTRS_KEY+" specified");

	// Initialize new acceptedAttribute ArrayList
	ArrayList<X509ExtractorPIP.AcceptedAttr> acceptedAttrList=new ArrayList<X509ExtractorPIP.AcceptedAttr>();
	for (int i=0; i<acceptedAttrName.length; i++)	{
	    if (X509ExtractorPIP.ATTR_X509_ISSUER.equals(acceptedAttrName[i]))
		acceptedAttrList.add(X509ExtractorPIP.AcceptedAttr.ACCEPT_ATTR_X509_ISSUER);
	    else if (X509ExtractorPIP.ATTR_CA_POLICY_OID.equals(acceptedAttrName[i]))
		acceptedAttrList.add(X509ExtractorPIP.AcceptedAttr.ACCEPT_ATTR_CA_POLICY_OID);
	    else
		throw new ConfigurationException(
		    "Unknown value for "+ACCEPTED_ATTRS_KEY+" found: "+acceptedAttrName[i]);
	    log.debug("Will produce attributeID \""+acceptedAttrName[i]+"\"");
	}

	// Instantiate PIP, convert new ArrayList to right AcceptedAttribute[]
	X509ExtractorPIP pip = new X509ExtractorPIP(id, acceptedAttrList.toArray(new X509ExtractorPIP.AcceptedAttr[0]));

	// Return new PIP
	return pip;
    }
}

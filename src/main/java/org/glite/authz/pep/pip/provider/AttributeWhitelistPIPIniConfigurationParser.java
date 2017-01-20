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

import java.util.ArrayList;
import java.util.Arrays;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.config.AbstractConfigurationBuilder;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.config.IniSectionConfigurationParser;
import org.glite.authz.common.util.Strings;
import org.glite.authz.pep.pip.PolicyInformationPoint;

import org.ini4j.Ini;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Configuration parser for {@link AttributeWhitelistPIP}. */
@ThreadSafe
public class AttributeWhitelistPIPIniConfigurationParser implements IniSectionConfigurationParser<PolicyInformationPoint> {

    /** The name of the {@value} property which gives the IDs of the action attributes allowed to appear in the request. */
    public static final String ACT_ATTRIBS_PROP = "acceptedActionAttributes";

    /**
     * The name of the {@value} property which gives the IDs of the environment attributes allowed to appear in the
     * request.
     */
    public static final String ENV_ATTRIBS_PROP = "acceptedEnvironmentAttributes";

    /**
     * The name of the {@value} property which gives the IDs of the resource attributes allowed to appear in the
     * request.
     */
    public static final String RES_ATTRIBS_PROP = "acceptedResourceAttributes";

    /**
     * The name of the {@value} property which gives the IDs of the subject attributes allowed to appear in the request.
     */
    public static final String SUB_ATTRIBS_PROP = "acceptedSubjectAttributes";

    /** Class logger. */
    private static final Logger LOG = LoggerFactory.getLogger(AttributeWhitelistPIPIniConfigurationParser.class);

    /** {@inheritDoc} */
    public PolicyInformationPoint parse(Ini.Section iniConfig, AbstractConfigurationBuilder<?> configBuilder)
            throws ConfigurationException {
        String pipId = iniConfig.getName();
        String[] actionAttributeIds = parseAcceptedAttributeIds(iniConfig.get(ACT_ATTRIBS_PROP));
        if (actionAttributeIds != null && actionAttributeIds.length > 0) {
            LOG.info("{}: white listed action attributes: {}", pipId, Arrays.toString(actionAttributeIds));
        } else {
            LOG.info("{}: white listed action attributes: all", pipId);
        }

        String[] environmentAttributeIds = parseAcceptedAttributeIds(iniConfig.get(ENV_ATTRIBS_PROP));
        if (environmentAttributeIds != null && environmentAttributeIds.length > 0) {
            LOG.info("{}: white listed environment attributes: ", pipId, Arrays.toString(environmentAttributeIds));
        } else {
            LOG.info("{}: white listed environment attributes: all", pipId);
        }

        String[] resourceAttributeIds = parseAcceptedAttributeIds(iniConfig.get(RES_ATTRIBS_PROP));
        if (resourceAttributeIds != null && resourceAttributeIds.length > 0) {
            LOG.info("{}: white listed resource attributes: ", pipId, Arrays.toString(resourceAttributeIds));
        } else {
            LOG.info("{}: white listed resource attributes: all", pipId);
        }

        String[] subjectAttributeIds = parseAcceptedAttributeIds(iniConfig.get(SUB_ATTRIBS_PROP));
        if (subjectAttributeIds != null && subjectAttributeIds.length > 0) {
            LOG.info("{}: white listed subject attributes: ", pipId, Arrays.toString(subjectAttributeIds));
        } else {
            LOG.info("{}: white listed subject attributes: all", pipId);
        }
        return new AttributeWhitelistPIP(pipId, actionAttributeIds, environmentAttributeIds, resourceAttributeIds,
                subjectAttributeIds);
    }

    /**
     * Parses a space delimited list of attribute IDs.
     * 
     * @param ids space delimited list of attribute IDs, may be null
     * 
     * @return list of attribute IDs
     */
    protected String[] parseAcceptedAttributeIds(String ids) {
        if (ids == null) {
            return null;
        }

        ArrayList<String> acceptedIds = new ArrayList<String>();
        for (String id : ids.split(" ")) {
            String trimmedId = Strings.safeTrimOrNullString(id);
            if (trimmedId != null) {
                acceptedIds.add(trimmedId);
            }
        }

        return acceptedIds.toArray(new String[acceptedIds.size()]);
    }
}

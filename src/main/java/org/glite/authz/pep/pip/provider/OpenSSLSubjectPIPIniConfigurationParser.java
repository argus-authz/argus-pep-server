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

import java.util.Arrays;
import java.util.List;

import org.glite.authz.common.config.AbstractConfigurationBuilder;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.config.IniConfigUtil;
import org.glite.authz.common.config.IniSectionConfigurationParser;
import org.glite.authz.pep.pip.PolicyInformationPoint;

import org.ini4j.Ini;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Configuration parser for an {@link OpenSSLSubjectPIP}. */
public class OpenSSLSubjectPIPIniConfigurationParser implements
        IniSectionConfigurationParser<PolicyInformationPoint> {

    /** Class logger. */
    private static final Logger LOG= LoggerFactory.getLogger(OpenSSLSubjectPIPIniConfigurationParser.class);

    /**
     * Name of the {@value} property in the INI configuration file to define the
     * list of subject attribute IDs to convert.
     */
    public static final String OPENSSL_SUBJECT_ATTIBUTE_IDS_PROP= "opensslSubjectAttributeIDs";

    /**
     * Name of the {@value} property in the INI configuration file to define the
     * list of subject attribute datatypes to convert.
     */
    public static final String OPENSSL_SUBJECT_ATTIBUTE_DATATYPES_PROP= "opensslSubjectAttributeDatatypes";

    /** {@inheritDoc} */
    public PolicyInformationPoint parse(Ini.Section iniConfig,
            AbstractConfigurationBuilder<?> configBuilder)
            throws ConfigurationException {

        String pipid= iniConfig.getName();

        OpenSSLSubjectPIP pip= new OpenSSLSubjectPIP(pipid);

        // parse additional optional options
        List<String> subjectAttributeIDs= null;
        try {
            String[] opensslSubjectAttributeIDs= IniConfigUtil.getStringsArray(iniConfig,
                                                                               OPENSSL_SUBJECT_ATTIBUTE_IDS_PROP);
            subjectAttributeIDs= Arrays.asList(opensslSubjectAttributeIDs);
        } catch (ConfigurationException e) {
            subjectAttributeIDs= OpenSSLSubjectPIP.DEFAULT_OPENSSL_SUBJECT_ATTRIBUTE_IDS;
        }
        LOG.info("{}: OpenSSL subject attributes IDs to convert: {}",
                 pipid,
                 subjectAttributeIDs);
        pip.setSubjectAttributeIDs(subjectAttributeIDs);

        List<String> subjectAttributeDatatypes= null;
        try {
            String[] opensslSubjectAttributeDatatypes= IniConfigUtil.getStringsArray(iniConfig,
                                                                                     OPENSSL_SUBJECT_ATTIBUTE_DATATYPES_PROP);
            subjectAttributeDatatypes= Arrays.asList(opensslSubjectAttributeDatatypes);
        } catch (ConfigurationException e) {
            subjectAttributeDatatypes= OpenSSLSubjectPIP.DEFAULT_OPENSSL_SUBJECT_ATTRIBUTE_DATATYPES;
        }
        LOG.info("{}: OpenSSL subject attributes datatypes to convert: {}",
                 pipid,
                 subjectAttributeDatatypes);
        pip.setSubjectAttributeDataTypes(subjectAttributeDatatypes);
        return pip;
    }
}

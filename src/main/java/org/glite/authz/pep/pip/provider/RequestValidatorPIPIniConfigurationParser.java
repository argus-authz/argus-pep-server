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

/** Configuration parser for an {@link RequestValidatorPIP}. */
public class RequestValidatorPIPIniConfigurationParser implements
        IniSectionConfigurationParser<PolicyInformationPoint> {

    /** Class logger. */
    private static final Logger LOG= LoggerFactory.getLogger(RequestValidatorPIPIniConfigurationParser.class);

    /**
     * Name of the {@value} property in the INI configuration file to
     * enable/disable validation of the request subjects
     */
    public static final String VALIDATE_REQUEST_SUBJECTS_PROP= "validateRequestSubjects";

    /**
     * Name of the {@value} property in the INI configuration file to
     * enable/disable validation of the request resources
     */
    public static final String VALIDATE_REQUEST_RESOURCES_PROP= "validateRequestResources";

    /**
     * Name of the {@value} property in the INI configuration file to
     * enable/disable validation of the request action
     */
    public static final String VALIDATE_REQUEST_ACTION_PROP= "validateRequestAction";

    /**
     * Name of the {@value} property in the INI configuration file to
     * enable/disable validation of the request environment
     */
    public static final String VALIDATE_REQUEST_ENVIRONMENT_PROP= "validateRequestEnvironment";

    /**
     * Default value for the {@value #VALIDATE_REQUEST_SUBJECTS_PROP} property:
     * * {@value}
     */
    public static boolean DEFAULT_VALIDATE_REQUEST_SUBJECTS= true;

    /**
     * Default value for the {@value #VALIDATE_REQUEST_RESOURCES_PROP} property:
     * * {@value}
     */
    public static boolean DEFAULT_VALIDATE_REQUEST_RESOURCES= true;

    /**
     * Default value for the {@value #VALIDATE_REQUEST_ACTION_PROP} property: *
     * {@value}
     */
    public static boolean DEFAULT_VALIDATE_REQUEST_ACTION= true;

    /**
     * Default value for the {@value #VALIDATE_REQUEST_ENVIRONMENT_PROP}
     * property: {@value}
     */
    public static boolean DEFAULT_VALIDATE_REQUEST_ENVIRONMENT= false;

    /** {@inheritDoc} */
    public PolicyInformationPoint parse(Ini.Section iniConfig,
            AbstractConfigurationBuilder<?> configBuilder)
            throws ConfigurationException {
        String pipid= Strings.safeTrimOrNullString(iniConfig.getName());
        RequestValidatorPIP pip= new RequestValidatorPIP(pipid);

        boolean validateRequestSubjects= IniConfigUtil.getBoolean(iniConfig,
                                                                  VALIDATE_REQUEST_SUBJECTS_PROP,
                                                                  DEFAULT_VALIDATE_REQUEST_SUBJECTS);
        LOG.info("{}: validate request subjects: {}",
                 pipid,
                 validateRequestSubjects);
        pip.setValidateRequestSubjects(validateRequestSubjects);

        boolean validateRequestResources= IniConfigUtil.getBoolean(iniConfig,
                                                                   VALIDATE_REQUEST_RESOURCES_PROP,
                                                                   DEFAULT_VALIDATE_REQUEST_RESOURCES);
        LOG.info("{}: validate request resources: {}",
                 pipid,
                 validateRequestResources);
        pip.setValidateRequestResources(validateRequestResources);

        boolean validateRequestAction= IniConfigUtil.getBoolean(iniConfig,
                                                                VALIDATE_REQUEST_ACTION_PROP,
                                                                DEFAULT_VALIDATE_REQUEST_ACTION);
        LOG.info("{}: validate request action: {}",
                 pipid,
                 validateRequestAction);
        pip.setValidateRequestAction(validateRequestAction);

        boolean validateRequestEnvironment= IniConfigUtil.getBoolean(iniConfig,
                                                                     VALIDATE_REQUEST_ENVIRONMENT_PROP,
                                                                     DEFAULT_VALIDATE_REQUEST_ENVIRONMENT);
        LOG.info("{}: validate request environment: {}",
                 pipid,
                 validateRequestEnvironment);
        pip.setValidateRequestEnvironment(validateRequestEnvironment);

        return pip;
    }
}

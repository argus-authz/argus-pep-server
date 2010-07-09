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
import org.glite.authz.pep.pip.IniPIPConfigurationParser;
import org.glite.authz.pep.pip.PolicyInformationPoint;
import org.glite.authz.common.util.Strings;
import org.ini4j.Ini.Section;

/** Configuration parser for an {@link EnvironmentTimePIP}. */
public class EnvironmentTimePIPIniConfigurationParser implements IniPIPConfigurationParser {

    /** {@inheritDoc} */
    public PolicyInformationPoint parse(Section iniConfig, AbstractConfigurationBuilder<?> configBuilder)
            throws ConfigurationException {
        return new EnvironmentTimePIP(Strings.safeTrimOrNullString(iniConfig.getName()));
    }
}
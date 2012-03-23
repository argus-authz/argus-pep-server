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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The class AuthorizationProfilePIPIniConfigurationParser is keep back for compatibility
 * with Argus PEP Server 1.4 configuration.
 * 
 * @deprecated use {@link GLiteAuthorizationProfilePIPIniConfigurationParser} instead.
 * 
 * @author Valery Tschopp &lt;valery.tschopp&#64;switch.ch&gt;
 */
public class AuthorizationProfilePIPIniConfigurationParser extends
        GLiteAuthorizationProfilePIPIniConfigurationParser {

    /** Class logger. */
    private Logger log= LoggerFactory.getLogger(AuthorizationProfilePIPIniConfigurationParser.class);

    /**
     * Constructor
     */
    public AuthorizationProfilePIPIniConfigurationParser() {
        super();
        log.warn(AuthorizationProfilePIPIniConfigurationParser.class.getCanonicalName() + " is DEPRECATED, update your configuration");
    }

}

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

import org.glite.authz.common.config.ConfigurationException;
import org.glite.voms.PKIStore;

/** Configuration parser for {@link SCASLegacyPIP} PIPs. */
public class SCASSLegacyPIPIniConfigurationParser extends AbstractX509PIPIniConfigurationParser {

    /** {@inheritDoc} */
    protected AbstractX509PIP buildInformationPoint(String id, boolean requireProxy, PKIStore tustMaterial,
            PKIStore acTrustMaterial, boolean performPKIXValidation) throws ConfigurationException {

        SCASLegacyPIP pip= new SCASLegacyPIP(id, requireProxy, tustMaterial, acTrustMaterial);
        // bug fix: perform PKIX validation not passed to PIP
        pip.performPKIXValidation(performPKIXValidation);
        return pip;
    }
}
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
import org.glite.authz.pep.pip.PolicyInformationPoint;
import org.ini4j.Ini;
import org.italiangrid.voms.ac.VOMSACValidator;

import eu.emi.security.authn.x509.X509CertChainValidator;

/**
 * Configuration parser for {@link SCASLegacyPIP} PIPs.
 * 
 * @deprecated {@link SCASLegacyPIP} is deprecated
 */
public class SCASSLegacyPIPIniConfigurationParser extends
        AbstractX509PIPIniConfigurationParser {

    /** {@inheritDoc} */
    protected PolicyInformationPoint buildInformationPoint(Ini.Section iniConfig,
                                                           boolean requireProxy,
                                                           X509CertChainValidator x509Validator,
                                                           VOMSACValidator vomsACValidator,
                                                           boolean performPKIXValidation,boolean requireCertificate)
            throws ConfigurationException {
        String pipId= iniConfig.getName();
        SCASLegacyPIP pip= new SCASLegacyPIP(pipId, requireProxy, x509Validator, vomsACValidator);
        // bug fix: perform PKIX validation not passed to PIP
        pip.performPKIXValidation(performPKIXValidation);
        pip.setRequireCertificate(requireCertificate);
        return pip;
    }
}

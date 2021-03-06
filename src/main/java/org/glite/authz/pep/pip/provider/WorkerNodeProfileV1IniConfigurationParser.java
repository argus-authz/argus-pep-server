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
 * A policy information point that extracts information from a X.509, version 3,
 * certificate. The certificate may include VOMS attribute certificates. All
 * extract information is added to the subject(s) containing a valid certificate
 * chain.
 * 
 * The PEM encoded end entity certificate, and its certificate chain, are
 * expected to be bound to the subject attribute
 * {@value org.glite.authz.common.model.Attribute#ID_SUB_KEY_INFO}. Only one
 * end-entity certificate may be present in the chain. If the end entity
 * certificate contains a VOMS attribute certificate, and VOMS certificate
 * validation is enabled, information from that attribute certificate will also
 * be added to the subject. Only one VOMS attribute certificate may be present
 * in the end-entity certificate.
 * 
 * @see <a href="https://twiki.cnaf.infn.it/cgi-bin/twiki/view/VOMS">VOMS
 *      website</a>
 *      
 * @deprecated {@link WorkerNodeProfileV1} is deprecated.
 */
public class WorkerNodeProfileV1IniConfigurationParser extends
        AbstractX509PIPIniConfigurationParser {

    /** {@inheritDoc} */
    protected PolicyInformationPoint buildInformationPoint(Ini.Section iniConfig,
                                                           boolean requireProxy,
                                                           X509CertChainValidator x509Validator,
                                                           VOMSACValidator vomsACValidator,
                                                           boolean performPKIXValidation,boolean requireCertificate)
            throws ConfigurationException {
        String pipId= iniConfig.getName();
        WorkerNodeProfileV1 pip= new WorkerNodeProfileV1(pipId, requireProxy, x509Validator, vomsACValidator, performPKIXValidation);
        pip.setRequireCertificate(requireCertificate);
        return pip;

    }
}

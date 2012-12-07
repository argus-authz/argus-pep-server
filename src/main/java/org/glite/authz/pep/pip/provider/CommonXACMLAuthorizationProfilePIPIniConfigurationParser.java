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

import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants;
import org.glite.authz.common.util.Strings;
import org.glite.authz.pep.pip.PolicyInformationPoint;
import org.ini4j.Ini;
import org.italiangrid.voms.ac.VOMSACValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.emi.security.authn.x509.X509CertChainValidator;

/**
 * The PIP applies to request which have a profile identifier
 * {@value CommonXACMLAuthorizationProfileConstants#ID_ATTRIBUTE_PROFILE_ID}
 * defined in the request environment. By default accept all profile identifier
 * values, but a list (space separated) of accepted profile identifier values
 * can be specified in the ini config file with the
 * {@value #ACCEPTED_PROFILE_IDS_PROP} property.
 * <p>
 * A policy information point that extracts information from a X.509, version 3,
 * certificate. The certificate may include VOMS attribute certificates. All
 * extract information is added to the subject(s) containing a valid certificate
 * chain.
 * <p>
 * 
 * The base64 encoded end-entity certificate, and its certificate chain, are
 * expected to be bound to the subject attribute
 * {@value Attribute#ID_SUB_KEY_INFO} with a datatype of
 * {@value Attribute#DT_BASE64_BINARY}.
 * 
 * Only one end-entity certificate may be present in the chain. If the end
 * entity certificate contains a VOMS attribute certificate, and VOMS
 * certificate validation is enabled, information from that attribute
 * certificate will also be added to the subject. Only one VOMS attribute
 * certificate may be present in the end-entity certificate.
 * 
 * @see <a href="https://twiki.cnaf.infn.it/cgi-bin/twiki/view/VOMS">VOMS
 *      website</a>
 */
public class CommonXACMLAuthorizationProfilePIPIniConfigurationParser extends
        AbstractX509PIPIniConfigurationParser {

    /** Class logger. */
    private Logger log= LoggerFactory.getLogger(CommonXACMLAuthorizationProfilePIPIniConfigurationParser.class);

    /**
     * The name of the {@value} property to define the accepted Grid
     * Authorization Profile ID to process.
     */
    public static String ACCEPTED_PROFILE_IDS_PROP= "acceptedProfileIDs";

    /** {@inheritDoc} */
    protected PolicyInformationPoint buildInformationPoint(Ini.Section iniConfig,
            boolean requireProxy, X509CertChainValidator x509Validator,
            VOMSACValidator vomsACValidator, boolean performPKIXValidation,boolean requireCertificate)
            throws ConfigurationException {
        String pipId= iniConfig.getName();

        // read accepted profile IDs from config
        String[] acceptedProfileIds= parseValuesList(iniConfig.get(ACCEPTED_PROFILE_IDS_PROP));
        if (acceptedProfileIds != null && acceptedProfileIds.length > 0) {
            log.info("{}: accepted profile IDs: {}",
                     pipId,
                     Arrays.toString(acceptedProfileIds));
        }
        else {
            log.info("{}: accepted profile IDs: all", pipId);
        }

        CommonXACMLAuthorizationProfilePIP pip= new CommonXACMLAuthorizationProfilePIP(pipId,
                                                                                       requireProxy,
                                                                                       x509Validator,
                                                                                       vomsACValidator,
                                                                                       performPKIXValidation,
                                                                                       acceptedProfileIds);
        pip.setRequireCertificate(requireCertificate);
        return pip;

    }

    /**
     * @return <code>false</code>
     */
    protected boolean getRequireCertificateDefault() {
        return false;
    }

    /**
     * Parses a space delimited list of values.
     * 
     * @param valuesList
     *            space delimited list of values, may be <code>null</code>.
     * 
     * @return array of values or <code>null</code> if valuesList is
     *         <code>null</code>
     */
    private String[] parseValuesList(String valuesList) {
        if (valuesList == null) {
            return null;
        }

        ArrayList<String> values= new ArrayList<String>();
        for (String value : valuesList.split(" ")) {
            String trimmedValue= Strings.safeTrimOrNullString(value);
            if (trimmedValue != null) {
                values.add(trimmedValue);
            }
        }

        return values.toArray(new String[values.size()]);
    }
}

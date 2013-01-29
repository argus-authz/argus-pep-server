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
import org.glite.authz.common.util.Files;
import org.glite.authz.pep.pip.PolicyInformationPoint;
import org.ini4j.Ini;
import org.italiangrid.voms.VOMSValidators;
import org.italiangrid.voms.ac.VOMSACValidator;
import org.italiangrid.voms.store.VOMSTrustStore;
import org.italiangrid.voms.store.VOMSTrustStores;
import org.italiangrid.voms.util.NullListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.X509CertChainValidatorExt;

/** Configuration parser for {@link AbstractX509PIP} PIPs. */
public abstract class AbstractX509PIPIniConfigurationParser implements
        IniSectionConfigurationParser<PolicyInformationPoint> {

    /**
     * The name of the {@value} property to enable or disable the requirement to
     * have a certificate chain in the Subject.
     */
    public static final String REQUIRE_CERTIFICATE_PROP= "requireCertificate";

    /** Default value of {@value #REQUIRE_CERTIFICATE_PROP}: {@value} . */
    public static final boolean DEFAULT_REQUIRE_CERTIFICATE= true;

    /**
     * The name of the {@value} property which determines whether a subject's
     * certificate chain must contain a proxy certificate.
     */
    public static final String REQUIRE_PROXY_PROP= "requireProxy";

    /** Default value of {@value #REQUIRE_PROXY_PROP}: {@value} . */
    public static final boolean DEFAULT_REQUIRE_PROXY= false;

    /**
     * The name of the {@value} property the indicates whether PKIX validation
     * will be performed on the certificate chain.
     */
    public static final String PERFORM_PKIX_VALIDATION_PROP= "performPKIXValidation";

    /**
     * The name of the {@value} property which gives the absolute path to the
     * 'vomsdir' directory.
     */
    public static final String VOMS_INFO_DIR_PROP= "vomsInfoDir";

    /**
     * The name of the {@value} which gives the refresh period, in minutes, for
     * 'vomsdir' information.
     */
    public static final String VOMS_INFO_REFRESH_PROP= "vomsInfoRefresh";

    /**
     * Default value (1 hour in minutes) of the {@value #VOMS_INFO_REFRESH_PROP}
     * property, {@value} .
     */
    public static final int DEFAULT_VOMS_INFO_REFRESH= 60;

    /** Default value of {@value #PERFORM_PKIX_VALIDATION_PROP}, {@value} . */
    public static final boolean DEFAULT_PERFORM_PKIX_VALIDATION= true;

    /** Class logger. */
    private Logger log= LoggerFactory.getLogger(AbstractX509PIPIniConfigurationParser.class);

    /** {@inheritDoc} */
    public PolicyInformationPoint parse(Ini.Section iniConfig,
                                        AbstractConfigurationBuilder<?> configurationBuilder)
            throws ConfigurationException {

        String pipId= iniConfig.getName();

        boolean requireProxy= IniConfigUtil.getBoolean(iniConfig, REQUIRE_PROXY_PROP, DEFAULT_REQUIRE_PROXY);
        log.info("{}: subject proxy certificate required: {}", pipId, requireProxy);

        VOMSACValidator vomsValidator= null;
        String vomsInfoDir= IniConfigUtil.getString(iniConfig, VOMS_INFO_DIR_PROP, null);
        if (vomsInfoDir != null) {
            log.info("{}: VOMS info directory: {}", pipId, vomsInfoDir);
            // get refresh interval: default 1h
            int vomsInfoRefresh= IniConfigUtil.getInt(iniConfig, VOMS_INFO_REFRESH_PROP, DEFAULT_VOMS_INFO_REFRESH, 1, Integer.MAX_VALUE);
            // minute -> millis
            vomsInfoRefresh= vomsInfoRefresh * 60 * 1000;
            log.info("{}: VOMS info refresh interval: {}ms", pipId, vomsInfoRefresh);
            try {
                Files.getFile(vomsInfoDir, false, true, true, false);
                List<String> vomsInfoDirs= Arrays.asList(vomsInfoDir);
                // TODO: add update listener!!!!
                VOMSTrustStore vomsTrustStore= VOMSTrustStores.newTrustStore(vomsInfoDirs, vomsInfoRefresh, NullListener.INSTANCE);
                X509CertChainValidatorExt certChainValidator= configurationBuilder.getCertChainValidator();
                // TODO: add validation listener!!!!
                vomsValidator= VOMSValidators.newValidator(vomsTrustStore, certChainValidator);
            } catch (Exception e) {
                throw new ConfigurationException("Unable to read VOMS AC validation information", e);
            }
        }

        boolean requireCertificate= IniConfigUtil.getBoolean(iniConfig, REQUIRE_CERTIFICATE_PROP, getRequireCertificateDefault());
        log.info("{}: require a certificate chains: {}", pipId, requireCertificate);

        boolean performPKIXValidation= IniConfigUtil.getBoolean(iniConfig, PERFORM_PKIX_VALIDATION_PROP, DEFAULT_PERFORM_PKIX_VALIDATION);
        log.info("{}: perform PKIX validation on cert chains: {}", pipId, performPKIXValidation);

        PolicyInformationPoint pip= buildInformationPoint(iniConfig, requireProxy, configurationBuilder.getCertChainValidator(), vomsValidator, performPKIXValidation, requireCertificate);
        return pip;
    }

    /**
     * @return the default value for requireCertificate:
     *         {@value #DEFAULT_REQUIRE_CERTIFICATE}
     */
    protected boolean getRequireCertificateDefault() {
        return DEFAULT_REQUIRE_CERTIFICATE;
    }

    /**
     * Builds the instance of the policy information point given the parsed
     * configuration.
     * 
     * @param iniConfig
     *            the INI configuration for the PIP
     * @param requireProxy
     *            whether proxy certificates are required
     * @param x509Validator
     *            the X.509 validator used for validating user certificates
     * @param vomsACValidator
     *            the VOMS AC validator used for validating attribute
     *            certificates
     * @param performPKIXValidation
     *            whether PKIX validation should be performed
     * @param requireCertificate
     *            to disable the requirement to have a cert in subject (default
     *            is true)
     * 
     * @return the constructed information point
     * 
     * @throws ConfigurationException
     *             thrown if there is a problem building the PIP with the given
     *             configuration parameters
     */
    protected abstract PolicyInformationPoint buildInformationPoint(Ini.Section iniConfig,
                                                                    boolean requireProxy,
                                                                    X509CertChainValidator x509Validator,
                                                                    VOMSACValidator vomsACValidator,
                                                                    boolean performPKIXValidation,
                                                                    boolean requireCertificate)
            throws ConfigurationException;
}

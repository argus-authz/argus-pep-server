/*
 * Copyright (c) Members of the EGEE Collaboration. 2006-2010. See http://www.eu-egee.org/partners/
 * for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package org.glite.authz.pep.pip.provider.oidc;

import org.glite.authz.common.config.AbstractConfigurationBuilder;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.config.IniConfigUtil;
import org.glite.authz.common.config.IniSectionConfigurationParser;
import org.glite.authz.pep.pip.PolicyInformationPoint;
import org.glite.authz.pep.pip.provider.oidc.impl.OidcHttpServiceImpl;
import org.glite.authz.pep.pip.provider.oidc.impl.OidcProfileTokenServiceImpl;
import org.glite.authz.pep.pip.provider.oidc.impl.OidcTokenDecoderImpl;
import org.ini4j.Profile.Section;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OidcProfilePIPConfigurationParser
    implements IniSectionConfigurationParser<PolicyInformationPoint> {

  private static final Logger LOG =
      LoggerFactory.getLogger(OidcProfilePIPConfigurationParser.class);

  private static final String LOG_PROP_PATTERN = "{}: {} = {}";

  private static final String OIDC_CLIENT_URL_PROP = "oidcClientUrl";
  private static final String OIDC_CACHE_TTL_PROP = "oidcCacheTTLInSecs";
  private static final String OIDC_CACHE_MAX_ELEMS_PROP = "oidcCacheMaxElements";
  private static final String OIDC_CACHE_DISABLED_PROP = "oidcCacheDisabled";

  private static final String DEFAULT_OIDC_URL = "http://127.0.0.1:8156/argus-oidc-client/user";
  private static final Integer DEFAULT_OIDC_CACHE_TTL = 60;
  private static final Integer DEFAULT_OIDC_CACHE_MAX_ELEMENTS = 100;
  private static final Boolean DEFAULT_OIDC_CACHE_DISABLED = false;

  @Override
  public PolicyInformationPoint parse(Section iniConfig,
      AbstractConfigurationBuilder<?> configBuilder) throws ConfigurationException {

    String pipId = iniConfig.getName();

    String oidcClientUrl =
        IniConfigUtil.getString(iniConfig, OIDC_CLIENT_URL_PROP, DEFAULT_OIDC_URL);
    LOG.info(LOG_PROP_PATTERN, new Object[] {pipId, OIDC_CLIENT_URL_PROP, oidcClientUrl});

    Integer oidcCacheTTL =
        IniConfigUtil.getInt(iniConfig, OIDC_CACHE_TTL_PROP, DEFAULT_OIDC_CACHE_TTL, 0, 3600);
    LOG.info(LOG_PROP_PATTERN, new Object[] {pipId, OIDC_CACHE_TTL_PROP, oidcCacheTTL});

    Integer oidcCacheMaxElements = IniConfigUtil.getInt(iniConfig, OIDC_CACHE_MAX_ELEMS_PROP,
        DEFAULT_OIDC_CACHE_MAX_ELEMENTS, 0, Integer.MAX_VALUE);
    LOG.info(LOG_PROP_PATTERN,
        new Object[] {pipId, OIDC_CACHE_MAX_ELEMS_PROP, oidcCacheMaxElements});

    Boolean oidcCacheEnabled =
        IniConfigUtil.getBoolean(iniConfig, OIDC_CACHE_DISABLED_PROP, DEFAULT_OIDC_CACHE_DISABLED);
    LOG.info(LOG_PROP_PATTERN, new Object[] {pipId, OIDC_CACHE_DISABLED_PROP, oidcCacheEnabled});

    try {
      OidcProfileTokenService tokenService = new OidcProfileTokenServiceImpl();
      OidcHttpService httpService = new OidcHttpServiceImpl(oidcClientUrl);

      OidcTokenDecoder decoder = new OidcTokenDecoderImpl(httpService, oidcCacheTTL,
          oidcCacheMaxElements, oidcCacheEnabled);
      return new OidcProfilePIP(pipId, tokenService, decoder);

    } catch (Exception e) {
      String errorMsg =
          String.format("%s: error building OIDC profile PIP: %s", pipId, e.getMessage());
      LOG.error(errorMsg, e);
      throw new ConfigurationException(errorMsg, e);
    }
  }

}

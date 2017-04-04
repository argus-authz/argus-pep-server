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

package org.glite.authz.pep.pip.provider.authnprofilespip;


import java.util.concurrent.TimeUnit;

import org.glite.authz.common.config.AbstractConfigurationBuilder;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.config.IniConfigUtil;
import org.glite.authz.common.config.IniSectionConfigurationParser;
import org.glite.authz.pep.pip.PolicyInformationPoint;
import org.ini4j.Profile.Section;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthenticationProfilePIPConfigurationParser
    implements IniSectionConfigurationParser<PolicyInformationPoint> {

  static final Logger LOG =
      LoggerFactory.getLogger(AuthenticationProfilePIPConfigurationParser.class);

  static final String DEFAULT_PROFILE_POLICY_FILENAME = "/etc/grid-security/vo-ca-ap-file";

  static final String PROFILE_POLICY_FILENAME_PROP = "authenticationProfilePolicyFile";

  static final String DEFAULT_TRUST_ANCHORS_DIRECTORY = "/etc/grid-security/certificates";

  static final int DEFAULT_TRUST_ANCHORS_REFRESH_INTERVAL_IN_SECS =
      (int) TimeUnit.HOURS.toSeconds(4);

  static final String TRUST_ANCHORS_DIRECTORY_PROP = "trustAnchors.directory";

  static final String DEFAULT_TRUST_ANCHORS_POLICY_FILE_PATTERN = "policy-*.info";

  static final String TRUST_ANCHORS_POLICY_FILE_PATTERN_PROP = "trustAnchors.policyFilePattern";

  static final String TRUST_ANCHORS_REFRESH_INTERVAL_IN_SECS_PROP =
      "trustAnchors.refreshIntervalInSecs";


  @Override
  public PolicyInformationPoint parse(Section iniConfig,
      AbstractConfigurationBuilder<?> configBuilder) throws ConfigurationException {

    String pipId = iniConfig.getName();

    final String authenticationProfilePolicyFile = IniConfigUtil.getString(iniConfig,
        PROFILE_POLICY_FILENAME_PROP, DEFAULT_PROFILE_POLICY_FILENAME);

    LOG.info("{}: {} = {}",
        new Object[] {pipId, PROFILE_POLICY_FILENAME_PROP, authenticationProfilePolicyFile});

    final String trustAnchorsDir = IniConfigUtil.getString(iniConfig, TRUST_ANCHORS_DIRECTORY_PROP,
        DEFAULT_TRUST_ANCHORS_DIRECTORY);

    LOG.info("{}: {} = {}", new Object[] {pipId, TRUST_ANCHORS_DIRECTORY_PROP, trustAnchorsDir});

    final String policyFilePattern = IniConfigUtil.getString(iniConfig,
        TRUST_ANCHORS_POLICY_FILE_PATTERN_PROP, DEFAULT_TRUST_ANCHORS_POLICY_FILE_PATTERN);

    LOG.info("{}: {} = {}", new Object[] {pipId, TRUST_ANCHORS_DIRECTORY_PROP, policyFilePattern});

    final int refreshIntervalInSecs =
        IniConfigUtil.getInt(iniConfig, TRUST_ANCHORS_REFRESH_INTERVAL_IN_SECS_PROP,
            DEFAULT_TRUST_ANCHORS_REFRESH_INTERVAL_IN_SECS, Integer.MIN_VALUE, 604_800);
    
    LOG.info("{}: {} = {}", new Object[] {pipId, TRUST_ANCHORS_REFRESH_INTERVAL_IN_SECS_PROP, 
        refreshIntervalInSecs});
    
    try {

      AuthenticationProfilePDP pdp = new DefaultAuthenticationProfilePDP.Builder()
        .authenticationPolicyFile(authenticationProfilePolicyFile)
        .trustAnchorsDir(trustAnchorsDir)
        .policyFilePattern(policyFilePattern)
        .refreshIntervalInSecs(refreshIntervalInSecs)
        .build();

      AuthenticationProfilePIP pip = new AuthenticationProfilePIP(pipId,pdp);

      return pip;

    } catch (Exception e) {

      String errorMsg =
          String.format("%s: error building authentication profile PIP: %s", pipId, e.getMessage());

      LOG.error(errorMsg, e);
      throw new ConfigurationException(errorMsg, e);

    }

  }

}

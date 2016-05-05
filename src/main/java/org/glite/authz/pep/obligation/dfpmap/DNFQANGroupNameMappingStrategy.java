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

package org.glite.authz.pep.obligation.dfpmap;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.glite.authz.common.fqan.FQAN;
import org.glite.authz.pep.obligation.ObligationProcessingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A strategy for mapping a subject's DN, primary and secondary FQANs to primary
 * and secondary groups.
 */
public class DNFQANGroupNameMappingStrategy
  implements GroupNameMappingStrategy {

  /** Class logger. */
  private final Logger log = LoggerFactory
    .getLogger(DNFQANGroupNameMappingStrategy.class);

  /** DN/FQAN to POSIX group name mappings. */
  private DFPM groupNameMapping;

  /** Strategy to see if a {@link DFPM} key matches a given {@link FQAN}. */
  private DFPMMatchStrategy<FQAN> fqanMatchStrategy;

  /**
   * Strategy to see if a {@link DFPM} key matches a given {@link X500Principal}
   * .
   */
  private DFPMMatchStrategy<X500Principal> dnMatchStrategy;

  /**
   * Whether to prefer a DN based mapping for the primary group name mapping.
   */
  private boolean preferDNForPrimaryGroupName;

  /**
   * Constructor.
   * 
   * @param groupMappings
   *          DN/FQAN to POSIX group name mappings, may not be null
   * @param dnMatching
   *          strategy to see if a {@link DFPM} key matches a given
   *          {@link X500Principal}, may not be null
   * @param fqanMatching
   *          strategy to see if a {@link DFPM} key matches a given {@link FQAN}
   *          , may not be null
   * @param preferDNmappings
   *          whether to prefer a DN based mapping, over an FQAN based mapping,
   *          for the primary group name
   */
  public DNFQANGroupNameMappingStrategy(final DFPM groupMappings,
    final DFPMMatchStrategy<X500Principal> dnMatching,
    final DFPMMatchStrategy<FQAN> fqanMatching,
    final boolean preferDNmappings) {
    if (groupMappings == null) {
      throw new IllegalArgumentException(
        "DN/FQAN to POSIX group mapping may not be null");
    }
    groupNameMapping = groupMappings;

    if (dnMatching == null) {
      throw new IllegalArgumentException(
        "DN matching strategy may not be null");
    }
    dnMatchStrategy = dnMatching;

    if (fqanMatching == null) {
      throw new IllegalArgumentException(
        "FQAN matching strategy may not be null");
    }
    fqanMatchStrategy = fqanMatching;

    preferDNForPrimaryGroupName = preferDNmappings;
  }

  /** {@inheritDoc} */
  public List<String> mapToGroupNames(final X500Principal subjectDN,
    final FQAN primaryFQAN, final List<FQAN> secondaryFQANs)
      throws ObligationProcessingException {

    log.debug(
      "Mapping group names for subject {} with primary FQAN {} and secondary FQANs {}",
      new Object[] { subjectDN.getName(), primaryFQAN, secondaryFQANs });

    Set<String> dnGroupNames = new LinkedHashSet<String>();
    Set<String> fqanPrimaryGroupNames = new LinkedHashSet<String>();
    Set<String> fqanSecondaryGroupNames = new LinkedHashSet<String>();

    for (String mapKey : groupNameMapping.keySet()) {
      if (groupNameMapping.isDNMapEntry(mapKey)) {
        if (subjectDN != null) {
          if (dnMatchStrategy.isMatch(mapKey, subjectDN)) {
            List<String> grNames = groupNameMapping.get(mapKey);
            dnGroupNames.addAll(grNames);
          }
        }
      } else if (groupNameMapping.isFQANMapEntry(mapKey)) {
        if (primaryFQAN != null) {
          if (fqanMatchStrategy.isMatch(mapKey, primaryFQAN)) {
            List<String> grNames = groupNameMapping.get(mapKey);
            fqanPrimaryGroupNames.addAll(grNames);
          }
        }
      }
    }
    for (String mapKey : groupNameMapping.keySet()) {
      if (groupNameMapping.isFQANMapEntry(mapKey)) {
        if (secondaryFQANs != null) {
          for (FQAN secondaryFQAN : secondaryFQANs) {
            if (fqanMatchStrategy.isMatch(mapKey, secondaryFQAN)) {
              List<String> grNames = groupNameMapping.get(mapKey);
              fqanSecondaryGroupNames.addAll(grNames);
            }
          }
        }
      }
    }

    Set<String> groupNames = new LinkedHashSet<String>();
    
    if (log.isTraceEnabled()) {
      log.trace(
        "DN groups: {} FQAN primary groups: {} FQAN secondary groups: {}",
        dnGroupNames, fqanPrimaryGroupNames, fqanSecondaryGroupNames);
    }
    if (preferDNForPrimaryGroupName) {
      groupNames.addAll(dnGroupNames);
      groupNames.addAll(fqanPrimaryGroupNames);
      groupNames.addAll(fqanSecondaryGroupNames);
    } else {
      groupNames.addAll(fqanPrimaryGroupNames);
      groupNames.addAll(fqanSecondaryGroupNames);
      groupNames.addAll(dnGroupNames);
    }

    log.debug(
      "Subject {} with primary FQAN {} and secondary FQANs {} mapped to group names: {}",
      new Object[] { subjectDN.getName(), primaryFQAN, secondaryFQANs,
        groupNames });
    
    List<String> result = new ArrayList<String>(groupNames);
    return result;
  }

}
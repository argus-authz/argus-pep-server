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

import java.io.File;

import javax.security.auth.x500.X500Principal;

/**
 * 
 * A strategy for link a subject identifier to unix local account name
 *
 */
public interface GridmapDirGetMappingStrategy {

  /**
   * Creates a mapping between an account and a subject identified by the
   * account key.
   * 
   * @param accountNamePrefix
   *          prefix of the pool account names
   * 
   * @param subjectDN
   *          the subject DN
   * 
   * @param subjectIdentifierPath
   *          the file associated to the subject identifier
   * 
   * @return the unix file for account to which the subject was mapped or null
   *         if no account was available
   * 
   */
  public UnixFile getMapping(final String accountNamePrefix,
    final X500Principal subjectDN, final File subjectIdentifierPath);
  
  
}

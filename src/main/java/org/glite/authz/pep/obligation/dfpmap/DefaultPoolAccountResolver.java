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
import java.io.FilenameFilter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DefaultPoolAccountResolver implements PoolAccountResolver{

  /**
   * Regexp pattern used to identify pool account names.
   * 
   * Contains a single group match whose value is the pool account name prefix.
   * 
   */
  private final Pattern poolAccountNamePattern_ = Pattern
    .compile("^([a-zA-Z][a-zA-Z0-9._-]*?)[0-9]++$");

  final File gridmapDir;

  public DefaultPoolAccountResolver(final File gridmapDir) {
    this.gridmapDir = gridmapDir;
  }

  /**
   * Gets a list of account files where the file names begin with the given
   * prefix.
   * 
   * @param prefix
   *          prefix with which the file names should begin, may be null to
   *          signify all file names
   * 
   * @return the selected account files
   */
  public File[] getAccountFiles(final String prefix) {

    return gridmapDir.listFiles(new FilenameFilter() {

      public boolean accept(final File dir, final String name) {

        Matcher nameMatcher = poolAccountNamePattern_.matcher(name);

        if (nameMatcher.matches()) {
          if (prefix == null || prefix.equals(nameMatcher.group(1))) {
            return true;
          }
        }
        return false;
      }
    });
  }

}

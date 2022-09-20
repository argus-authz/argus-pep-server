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

public class DefaultFilenameFilter implements FilenameFilter {

  private final String prefix;

  /**
   * RegExp pattern used to identify pool account names.
   * 
   * Contains a single group match whose value is the pool account name prefix.
   * 
   */
  private final Pattern poolAccountNamePattern =
      Pattern.compile("^([a-zA-Z][a-zA-Z0-9._-]*?)[0-9]{3,3}$");

  public DefaultFilenameFilter(String prefix) {
    this.prefix = prefix;
  }

  @Override
  public boolean accept(File dir, String name) {

    Matcher nameMatcher = poolAccountNamePattern.matcher(name);

    return nameMatcher.matches() && (prefix == null || prefix.equals(nameMatcher.group(1)));
  }

}

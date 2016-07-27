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
import java.io.IOException;

import org.apache.commons.io.FileUtils;

public class TestUtils {
  
  public static boolean deleteTempGridMapDir(final File path) {

    boolean lRetVal = false;
    try {
      FileUtils.deleteDirectory(path);
      lRetVal = true;
    } catch (IOException e) {
      lRetVal = false;
    }
    return lRetVal;
  }

  public static File createTempGridMapDir(String accountPrefix, int numAccounts)
    throws IOException {

    File temp = File.createTempFile("test-gridmapdir", ".junit");
    if (!(temp.delete())) {
      throw new IOException(
        "Could not delete temp file: " + temp.getAbsolutePath());
    }

    if (!(temp.mkdir())) {
      throw new IOException(
        "Could not create temp directory: " + temp.getAbsolutePath());
    }

    temp.deleteOnExit();

    for (int idx = 1; idx <= numAccounts; idx++) {
      String lFileName = String.format("%s%02d", accountPrefix, idx);
      File f = new File(temp, lFileName);
      f.createNewFile();
      f.deleteOnExit();
    }

    return temp;
  }

}

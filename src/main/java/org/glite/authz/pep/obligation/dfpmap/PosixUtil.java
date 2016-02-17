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
import java.io.InputStream;
import java.io.PrintStream;

import org.jruby.ext.posix.FileStat;
import org.jruby.ext.posix.POSIX;
import org.jruby.ext.posix.POSIX.ERRORS;
import org.jruby.ext.posix.POSIXFactory;
import org.jruby.ext.posix.POSIXHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** A set of utility function for working with POSIX environments. */
public class PosixUtil {

  /** POSIX bridge implementation. */
  private static POSIX posix = POSIXFactory.getPOSIX(new BasicPOSIXHandler(),
    true);

  /** Class logger. */
  private static Logger log = LoggerFactory.getLogger(PosixUtil.class);

  /**
   * Gets the stats about the given file.
   * 
   * @param file
   *          the file to stat
   * 
   * @return the stats on the file
   */
  public static FileStat getFileStat(final String file) {

    return posix.stat(file);
  }

  /**
   * Creates a symbolic link, where targetPath point to sourcePath.
   * 
   * @param sourcePath
   *          absolute source path
   * @param targetPath
   *          absolute target path
   * @return 0 in case of success, the ERRNO value in case of errors
   */
  public static int createSymlink(final String sourcePath,
    final String targetPath) {

    if (posix.symlink(sourcePath, targetPath) < 0) {
      return posix.errno();
    }

    return 0;

  }

  /**
   * Creates a hard link, where targetPath point to sourcePath.
   * 
   * @param sourcePath
   *          absolute source path
   * @param targetPath
   *          absolute target path
   * @return 0 if the call is successful, the ERRNO value in case of errors
   */
  public static int createHardlink(final String sourcePath,
    final String targetPath) {

    if (posix.link(sourcePath, targetPath) < 0) {
      return posix.errno();
    }

    return 0;
  }

  /**
   * Creates a hard link, where targetFile points to sourceFile. This method is
   * a shortcut for {@link #createHardlink(String, String)}, which takes two
   * paths. The paths are from file using {@link File#getAbsolutePath()}
   * 
   * @param sourceFile
   *          the source file
   * @param targetFile
   *          the target file
   * 
   * @return 0 if the call is succesful, the ERRNO value in case of errors
   */
  public static int createHardlink(final File sourceFile,
    final File targetFile) {

    return createHardlink(sourceFile.getAbsolutePath(),
      targetFile.getAbsolutePath());
  }

  /**
   * Tries to "touch" a file, like the UNIX touch command, and update the last
   * modified timestamp.
   * 
   * @param file
   *          the file to "touch"
   */
  public static void touchFile(final File file) {

    try {
      log.debug("touch {}", file.getAbsolutePath());
      if (!file.exists()) {
        file.createNewFile();
      }
      boolean success = file.setLastModified(System.currentTimeMillis());
      if (!success) {
        throw new IOException(
          "Unable to set the last modification time for " + file);
      }
    } catch (IOException e) {
      log.warn("touch {} failed: {}", file.getAbsolutePath(), e.getMessage());
    }

  }

  /** A basic handler for logging and stream handling. */
  public static class BasicPOSIXHandler implements POSIXHandler {

    public void error(final ERRORS error, final String extraData) {

      log.error("Error performing POSIX operation. Error: " + error.toString()
        + ", additional data: " + extraData);
    }

    public void unimplementedError(final String methodName) {

      log.error("Error performing POSIX operation.  Operation " + methodName
        + " is not supported");
    }

    public void warn(final WARNING_ID id, final String message,
      final Object... data) {

      log.warn(message);
    }

    public boolean isVerbose() {

      return false;
    }

    public File getCurrentWorkingDirectory() {

      return new File("/tmp");
    }

    /**
     * {@inheritDoc}
     * 
     * This operation is <strong>not</strong> supported.
     */
    public String[] getEnv() {

      throw new UnsupportedOperationException("Not supported yet.");
    }

    public InputStream getInputStream() {

      return System.in;
    }

    public PrintStream getOutputStream() {

      return System.out;
    }

    /**
     * {@inheritDoc}
     * 
     * This operation is <strong>not</strong> supported.
     */
    public int getPID() {

      throw new UnsupportedOperationException("Not supported yet.");
    }

    public PrintStream getErrorStream() {

      return System.err;
    }
  }
}
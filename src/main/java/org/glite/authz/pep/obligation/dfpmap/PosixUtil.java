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
import java.io.InputStream;
import java.io.PrintStream;

import org.jruby.ext.posix.FileStat;
import org.jruby.ext.posix.POSIX;
import org.jruby.ext.posix.POSIXFactory;
import org.jruby.ext.posix.POSIXHandler;
import org.jruby.ext.posix.POSIX.ERRORS;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** A set of utility function for working with POSIX environments. */
public class PosixUtil {

    /** POSIX bridge implementation. */
    private static POSIX posix = POSIXFactory.getPOSIX(new BasicPOSIXHandler(), true);

    /** Class logger. */
    private static Logger log = LoggerFactory.getLogger(PosixUtil.class);

    /**
     * Gets the stats about the given file.
     * 
     * @param file the file to stat
     * 
     * @return the stats on the file
     */
    public static FileStat getFileStat(String file) {
        return posix.stat(file);
    }

    /**
     * Creates a link such that the new path points to the same thing as the old path.
     * 
     * @param currenPath current path
     * @param newPath new path that will point to the current path
     * @param symbolic true if the link should be a symbolic or false if it should be a hard link
     */
    public static void createLink(String currenPath, String newPath, boolean symbolic) {
        if (symbolic) {
            posix.symlink(currenPath, newPath);
        } else {
            posix.link(currenPath, newPath);
        }
    }

    /** A basic handler for logging and stream handling. */
    public static class BasicPOSIXHandler implements POSIXHandler {

        /** {@inheritDoc} */
        public void error(ERRORS error, String extraData) {
            log.error("Error performing POSIX operation. Error: " + error.toString() + ", additional data: "
                    + extraData);
        }

        /** {@inheritDoc} */
        public void unimplementedError(String methodName) {
            log.error("Error performing POSIX operation.  Operation " + methodName + " is not supported");
        }

        /** {@inheritDoc} */
        public void warn(WARNING_ID id, String message, Object... data) {
            log.warn(message);
        }

        /** {@inheritDoc} */
        public boolean isVerbose() {
            return false;
        }

        /** {@inheritDoc} */
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

        /** {@inheritDoc} */
        public InputStream getInputStream() {
            return System.in;
        }

        /** {@inheritDoc} */
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

        /** {@inheritDoc} */
        public PrintStream getErrorStream() {
            return System.err;
        }
    }
}
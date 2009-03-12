/*
 * Copyright 2008 EGEE Collaboration
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.glite.authz.pep.server;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.glite.authz.common.http.BaseHttpServlet;
import org.glite.authz.pep.server.config.PEPDaemonConfiguration;

/** A Servlet that reports basic daemon status and metrics. */
public class PEPDaemonStatusServlet extends BaseHttpServlet {

    /** Serial version UID. */
    private static final long serialVersionUID = -2568208432192021145L;

    /** Configuration for the daemon. */
    private PEPDaemonConfiguration daemonConfig;

    /** {@inheritDoc} */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        daemonConfig = (PEPDaemonConfiguration) getServletContext().getAttribute(PEPDaemonConfiguration.BINDING_NAME);
        if (daemonConfig == null) {
            throw new ServletException("Unable to initialize, no daemon configuration available in servlet context");
        }
    }

    /** {@inheritDoc} */
    protected void doGet(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws ServletException,
            IOException {
        PEPDaemonMetrics metrics = daemonConfig.getMetrics();
        Runtime runtime = Runtime.getRuntime();
        long usedMemory = (runtime.totalMemory() - runtime.freeMemory()) / 1048576;

        httpResponse.setContentType("text/plain");
        PrintWriter out = httpResponse.getWriter();
        out.println("status: ok");
        out.println("start time: " + metrics.getStartupTime());
        out.println("number of processors: " + runtime.availableProcessors());
        out.println("memory usage: " + usedMemory + "MB");
        out.println("total authorization requests: " + metrics.getTotalAuthorizationRequests().toString());
        out.println("total successful authorization requests: "
                + metrics.getTotalAuthorizationRequests().subtract(metrics.getTotalAuthorizationRequestErrors())
                        .toString());
        out.println("total authorization request errors: " + metrics.getTotalAuthorizationRequestErrors());
    }

    /** {@inheritDoc} */
    protected String getSupportedMethods() {
        return "GET";
    }
}
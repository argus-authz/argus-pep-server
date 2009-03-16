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

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.glite.authz.common.http.BaseHttpServlet;
import org.glite.authz.common.util.Base64;
import org.glite.authz.pep.server.config.PEPDaemonConfiguration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;

import com.caucho.hessian.io.HessianInput;
import com.caucho.hessian.io.HessianOutput;

/** Adapts a {@link PEPDaemonRequestHandler} in to a Servlet. */
public class PEPDaemonServlet extends BaseHttpServlet {

    /** Name of the initialization parameter that holds the path to the PEP daemon configuration file. */
    public static final String CONFIG_FILE_INIT_PARAM_NAME = "pep-daemon-configuration";

    /** Serial version UID. */
    private static final long serialVersionUID = -3190215376394138266L;

    /** The request handler being adapted in to this Servlet. */
    private PEPDaemonRequestHandler requestHandler;

    /** {@inheritDoc} */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        PEPDaemonConfiguration daemonConfig = (PEPDaemonConfiguration) getServletContext().getAttribute(
                PEPDaemonConfiguration.BINDING_NAME);
        if (daemonConfig == null) {
            throw new ServletException("Unable to initialize, no daemon configuration available in servlet context");
        }
        requestHandler = new PEPDaemonRequestHandler(daemonConfig);

        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            throw new ServletException("Error initializing OpenSAML library", e);
        }
    }

    /** {@inheritDoc} */
    protected void doPost(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws ServletException,
            IOException {
        HessianInput hin = new HessianInput(new Base64.InputStream(httpRequest.getInputStream()));
        
        ByteArrayOutputStream responseOut = new ByteArrayOutputStream();
        HessianOutput hout = new HessianOutput(responseOut);
        
        requestHandler.handle(hin,hout);
        hout.flush();
        responseOut.flush();
        
        httpResponse.getWriter().write(Base64.encodeBytes(responseOut.toByteArray()));
        httpResponse.flushBuffer();
        return;
    }

    /** {@inheritDoc} */
    protected String getSupportedMethods() {
        return "POST";
    }
}
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

package org.glite.authz.pep.server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.http.BaseHttpServlet;
import org.glite.authz.common.logging.LoggingConstants;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Response;
import org.glite.authz.common.util.Base64;
import org.glite.authz.pep.server.config.PEPDaemonConfiguration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.caucho.hessian.io.HessianInput;
import com.caucho.hessian.io.HessianOutput;

/** Adapts a {@link PEPDaemonRequestHandler} in to a Servlet. */
@ThreadSafe
public class PEPDaemonServlet extends BaseHttpServlet {

    /** Serial version UID. */
    private static final long serialVersionUID = -4114670420901954784L;

    /** Protocol message log. */
    private final Logger protocolLog = LoggerFactory.getLogger(LoggingConstants.PROTOCOL_MESSAGE_CATEGORY);

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

        // get the simple model request
        HessianInput hin = new HessianInput(new Base64.InputStream(httpRequest.getInputStream()));
        Request request = (Request) hin.readObject(Request.class);
        protocolLog.debug("Incomming hessian request\n{}", request.toString());

        // do the authorization
        Response response = requestHandler.handle(request);

        // write out response
        protocolLog.debug("Outgoing hessian response\n{}", response.toString());

        ByteArrayOutputStream responseBytes = new ByteArrayOutputStream();
        HessianOutput hout = new HessianOutput(responseBytes);
        hout.writeObject(response);
        hout.flush();

        httpResponse.getWriter().write(Base64.encodeBytes(responseBytes.toByteArray()));
        httpResponse.flushBuffer();
        return;
    }

    /** {@inheritDoc} */
    protected String getSupportedMethods() {
        return "POST";
    }
}
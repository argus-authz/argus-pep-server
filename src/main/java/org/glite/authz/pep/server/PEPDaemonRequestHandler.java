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
import java.util.Iterator;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.AuthzServiceConstants;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Response;
import org.glite.authz.common.model.Result;
import org.glite.authz.common.model.Status;
import org.glite.authz.common.model.StatusCode;
import org.glite.authz.pep.server.config.PEPDaemonConfiguration;
import org.opensaml.ws.soap.client.BasicSOAPMessageContext;
import org.opensaml.ws.soap.client.SOAPClientException;
import org.opensaml.ws.soap.client.http.HttpSOAPRequestParameters;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xacml.ctx.RequestType;
import org.opensaml.xacml.ctx.StatusCodeType;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType;
import org.opensaml.xml.security.SecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.caucho.hessian.io.AbstractHessianInput;
import com.caucho.hessian.io.AbstractHessianOutput;

/** Handles an incoming daemon {@link Request}. */
@ThreadSafe
public class PEPDaemonRequestHandler {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(PEPDaemonRequestHandler.class);

    /** The daemon's configuration. */
    private PEPDaemonConfiguration daemonConfig;

    /**
     * Constructor.
     * 
     * @param config the constructor for the daemon
     */
    public PEPDaemonRequestHandler(final PEPDaemonConfiguration config) {
        if (config == null) {
            throw new IllegalArgumentException("Daemon configuration may not be null");
        }
        daemonConfig = config;

    }

    /**
     * Handles a PEP think client request. The request is deserialized from the input stream and then converted into a
     * {@link RequestType}. The request is sent to a PDP with each registered PDP being tried in turn until one accepts
     * the incoming connection. The {@link org.opensaml.xacml.ctx.ResponseType} from the PDP is then turned in to a
     * {@link Response}, serialized and then written out.
     * 
     * @param input the input stream containing incoming, serialized, {@link Request}
     * @param output the output stream to which the serialized {@link Response} is written
     * 
     * @throws IOException thrown if there is an error read or writing information from the given streams or if there is
     *             a problem contacting the PDPs
     */
    public void handle(AbstractHessianInput input, AbstractHessianOutput output) throws IOException {
        daemonConfig.getMetrics().incrementTotalAuthorizationRequests();

        Request hessianRequest = null;
        Envelope soapRequest = null;
        try {
            // decode in to Hessian data model
            hessianRequest = (Request) input.readObject(Request.class);
            log.debug("Received Hessian request\n{}", hessianRequest.toString());

            // convert in to XACML-SAML request
            RequestType xacmlRequestContext = XACMLSAMLUtil.toXACMLRequest(hessianRequest);
            XACMLAuthzDecisionQueryType samlAuthzQuery = XACMLSAMLUtil.buildSAMLRequest(xacmlRequestContext, daemonConfig.getEntityId(), false, false);
            soapRequest = XACMLSAMLUtil.buildSOAPRequest(samlAuthzQuery);
        } catch (IOException e) {
            daemonConfig.getMetrics().incrementTotalAuthorizationRequestErrors();
            encodeResponse(buildErrorResponse(hessianRequest, StatusCodeType.SC_SYNTAX_ERROR, "Invalid Hessian message"), output);
            log.error("Invalid Hessian message", e);
            return;
        }

        try {
            Envelope soapResponse = sendSOAPMessage(soapRequest);
            if (soapResponse != null) {
                // TODO process
                // TODO add in request
                
            } else {
                log.error("No PDP available currently available");
                daemonConfig.getMetrics().incrementTotalAuthorizationRequestErrors();
                encodeResponse(buildErrorResponse(hessianRequest, StatusCodeType.SC_PROCESSING_ERROR, "Unable to complete request"),
                        output);
                return;
            }
        } catch (IOException e) {
            daemonConfig.getMetrics().incrementTotalAuthorizationRequestErrors();
            encodeResponse(buildErrorResponse(hessianRequest, StatusCodeType.SC_SYNTAX_ERROR, "Invalid Hessian message"), output);
            log.error("Invalid Hessian message", e);
            return;
        }
    }

    /**
     * Attempts to send the SOAP request. This method attempts to send the request to each registered PDP endpoint until
     * one endpoint responses with an HTTP 200 status code. If PDP returns a 200 then null is returned, indicating that
     * the response could not be sent to any PDP.
     * 
     * @param soapRequest the SOAP request to sent
     * 
     * @return the returned response
     */
    private Envelope sendSOAPMessage(Envelope soapRequest) {
        HttpSOAPRequestParameters reqParams = new HttpSOAPRequestParameters(
                "http://www.oasis-open.org/committees/security");

        // TODO fill in security policy resolver
        BasicSOAPMessageContext messageContext = new BasicSOAPMessageContext();
        messageContext.setCommunicationProfileId(AuthzServiceConstants.XACML_SAML_PROFILE_URI);
        messageContext.setOutboundMessage(soapRequest);
        messageContext.setOutboundMessageIssuer(daemonConfig.getEntityId());
        messageContext.setSOAPRequestParameters(reqParams);

        Iterator<String> pdpItr = daemonConfig.getPDPEndpoints().iterator();
        String pdpEndpoint = null;
        while (pdpItr.hasNext()) {
            try {
                pdpEndpoint = pdpItr.next();
                daemonConfig.getSOAPClient().send(pdpEndpoint, messageContext);
                return (Envelope) messageContext.getInboundMessage();
            } catch (SOAPClientException e) {
                log.error("Error sending request to PDP endpoint " + pdpEndpoint, e);
            } catch (SecurityException e) {
                log.error("Response from PDP endpoint " + pdpEndpoint + " did not meet message security requirements",
                        e);
            }
        }

        return null;
    }

    /**
     * Writes the response to the Hession output stream.
     * 
     * @param response the response
     * @param output the Hessian output stream
     * 
     * @throws IOException thrown if there is a problem writing the response
     */
    private void encodeResponse(Response response, AbstractHessianOutput output) throws IOException {
        output.writeObject(response);
        output.flush();
    }

    /**
     * Builds a Response containing an error.
     * 
     * @param request the request that caused the error
     * @param statusCode status code of the error
     * @param errorMessage associated error message
     * 
     * @return the built response
     */
    private Response buildErrorResponse(Request request, String statusCode, String errorMessage) {
        StatusCode errorCode = new StatusCode();
        errorCode.setCode(statusCode);

        Status status = new Status();
        status.setCode(errorCode);
        if (errorMessage != null) {
            status.setMessage(errorMessage);
        }

        Result result = new Result();
        result.setStatus(status);

        Response response = new Response();
        response.setRequest(request);
        response.getResults().add(result);
        return response;
    }
}
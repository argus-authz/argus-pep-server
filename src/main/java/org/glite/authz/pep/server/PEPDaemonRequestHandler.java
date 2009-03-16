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
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.List;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.AuthzServiceConstants;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Response;
import org.glite.authz.common.model.Result;
import org.glite.authz.common.model.Status;
import org.glite.authz.common.model.StatusCode;
import org.glite.authz.common.model.XACMLConverter;
import org.glite.authz.common.pip.PolicyInformationPoint;
import org.glite.authz.pep.server.config.PEPDaemonConfiguration;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.IdentifierGenerator;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Statement;
import org.opensaml.ws.soap.client.BasicSOAPMessageContext;
import org.opensaml.ws.soap.client.SOAPClientException;
import org.opensaml.ws.soap.client.http.HttpSOAPRequestParameters;
import org.opensaml.ws.soap.common.SOAPObjectBuilder;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xacml.ctx.RequestType;
import org.opensaml.xacml.ctx.StatusCodeType;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionStatementType;
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

    /** Generator for message IDs. */
    private static IdentifierGenerator idGenerator;

    /** Builder of XACMLAuthzDecisionQuery XMLObjects. */
    private static SAMLObjectBuilder<XACMLAuthzDecisionQueryType> authzDecisionQueryBuilder;

    /** Builder of Body XMLObjects. */
    private static SOAPObjectBuilder<Body> bodyBuilder;

    /** Builder of Envelope XMLObjects. */
    private static SOAPObjectBuilder<Envelope> envelopeBuilder;

    /** Builder of Issuer XMLObjects. */
    private static SAMLObjectBuilder<Issuer> issuerBuilder;

    /**
     * Constructor.
     * 
     * @param config the constructor for the daemon
     */
    @SuppressWarnings("unchecked")
    public PEPDaemonRequestHandler(final PEPDaemonConfiguration config) {
        if (config == null) {
            throw new IllegalArgumentException("Daemon configuration may not be null");
        }
        daemonConfig = config;

        try {
            idGenerator = new SecureRandomIdentifierGenerator();
        } catch (NoSuchAlgorithmException e) {
            // do nothing, all VMs are required to support the default algo
        }

        bodyBuilder = (SOAPObjectBuilder<Body>) Configuration.getBuilderFactory().getBuilder(Body.TYPE_NAME);

        envelopeBuilder = (SOAPObjectBuilder<Envelope>) Configuration.getBuilderFactory()
                .getBuilder(Envelope.TYPE_NAME);

        issuerBuilder = (SAMLObjectBuilder<Issuer>) Configuration.getBuilderFactory().getBuilder(
                Issuer.DEFAULT_ELEMENT_NAME);

        authzDecisionQueryBuilder = (SAMLObjectBuilder<XACMLAuthzDecisionQueryType>) Configuration.getBuilderFactory()
                .getBuilder(XACMLAuthzDecisionQueryType.TYPE_NAME_XACML20);

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
     * @throws IOException thrown if there is an error writing a response to the output stream
     */
    public void handle(AbstractHessianInput input, AbstractHessianOutput output) throws IOException {
        daemonConfig.getMetrics().incrementTotalAuthorizationRequests();

        Request request = null;
        Response response = null;
        try {
            // get the simple model request
            request = (Request) input.readObject(Request.class);
            log.debug("Received Hessian request\n{}", request.toString());

            // run the policy information points over the request
            for (PolicyInformationPoint pip : daemonConfig.getPolicyInformationPoints()) {
                if (pip.populateRequest(request)) {
                    log.debug("Applied PIP {} to Hessian request", pip.getId());
                } else {
                    log.debug("PIP {} did not apply to this request", pip.getId());
                }
            }
            log.debug("Hessian request after PIPs have been run\n{}", request.toString());

            // send the request to the PDP
            response = sendRequestToPDP(request);
            log.debug("Hessian response gotten from PDP's XACML response\n{}", response.toString());

            // run obligations handlers over the response
            if (daemonConfig.getObligationService() != null) {
                daemonConfig.getObligationService().processObligations(request, response.getResults().get(0));
                log.debug("Hessian response after obligation service run\n{}", response.toString());
            }
        } catch (Exception e) {
            daemonConfig.getMetrics().incrementTotalAuthorizationRequestErrors();
            log.error("Error preocessing authorization request", e);
            response = buildErrorResponse(request, StatusCodeType.SC_PROCESSING_ERROR, null);
        }

        // write out response
        output.writeObject(response);
        output.flush();
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
    private Response sendRequestToPDP(Request authzRequest) {
        Envelope soapRequest = buildSOAPMessage(XACMLConverter.requestToXACML(authzRequest));

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
        Response authzResponse;
        while (pdpItr.hasNext()) {
            try {
                pdpEndpoint = pdpItr.next();
                daemonConfig.getSOAPClient().send(pdpEndpoint, messageContext);
                authzResponse = extractResponse(pdpEndpoint, (Envelope) messageContext.getInboundMessage());
                if (authzResponse != null) {
                    return authzResponse;
                }
            } catch (SOAPClientException e) {
                log.error("Error sending request to PDP endpoint " + pdpEndpoint, e);
            } catch (SecurityException e) {
                log.error("Response from PDP endpoint " + pdpEndpoint + " did not meet message security requirements",
                        e);
            }
        }

        log.error("No PDP endpoint was able to answer the authorization request");
        return null;
    }

    /**
     * Creates a SOAP message within which lies the XACML request.
     * 
     * @param bodyMessage the message that should be placed in the SOAP body
     * 
     * @return the generated SOAP envelope containing the message
     */
    private Envelope buildSOAPMessage(RequestType authzRequest) {
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setFormat(Issuer.ENTITY);
        issuer.setValue(daemonConfig.getEntityId());

        XACMLAuthzDecisionQueryType samlRequest = authzDecisionQueryBuilder
                .buildObject(XACMLAuthzDecisionQueryType.DEFAULT_ELEMENT_NAME_XACML20,
                        XACMLAuthzDecisionQueryType.TYPE_NAME_XACML20);

        samlRequest.setID(idGenerator.generateIdentifier());
        samlRequest.setIssueInstant(new DateTime());
        samlRequest.setIssuer(issuer);
        samlRequest.setInputContextOnly(false);
        samlRequest.setReturnContext(true);
        samlRequest.setRequest(authzRequest);

        Body body = bodyBuilder.buildObject();
        body.getUnknownXMLObjects().add(samlRequest);

        Envelope envelope = envelopeBuilder.buildObject();
        envelope.setBody(body);

        return envelope;
    }

    /**
     * Extracts the response from a PDP response. If more than one assertion is present
     * 
     * @param soapResponse the SOAP response containing the XACML-SAML authorization response
     * 
     * @return the extract response
     */
    private Response extractResponse(String pdpEndpoint, Envelope soapResponse) {
        org.opensaml.saml2.core.Response samlResponse = (org.opensaml.saml2.core.Response) soapResponse.getBody()
                .getOrderedChildren().get(0);

        if (samlResponse.getAssertions() == null || samlResponse.getAssertions().isEmpty()) {
            log.warn("Response from PDP {} was an invalid message.  It did not contain an assertion", pdpEndpoint);
            return null;
        }
        if (samlResponse.getAssertions().size() > 1) {
            log.warn("Response from PDP {} was an invalid message.  It contained more than 1 assertion", pdpEndpoint);
            return null;
        }
        Assertion samlAssertion = samlResponse.getAssertions().get(0);

        List<Statement> authzStatements = samlAssertion
                .getStatements(XACMLAuthzDecisionStatementType.TYPE_NAME_XACML20);
        if (authzStatements == null || authzStatements.isEmpty()) {
            log.warn("Response from PDP {} was an invalid message.  It did not contain an authorization statement",
                    pdpEndpoint);
            return null;
        }
        if (authzStatements.size() > 1) {
            log.warn("Response from PDP {} was an invalid message.  It contained more than 1 authorization statement",
                    pdpEndpoint);
            return null;
        }

        XACMLAuthzDecisionStatementType authzStatement = (XACMLAuthzDecisionStatementType) authzStatements.get(0);
        return XACMLConverter.responseFromXACML(authzStatement.getResponse(), authzStatement.getRequest());
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
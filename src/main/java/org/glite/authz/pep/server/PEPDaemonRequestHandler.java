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

import java.io.IOException;
import java.util.Iterator;
import java.util.List;

import org.glite.authz.common.AuthzServiceConstants;
import org.glite.authz.common.context.DecisionRequestContext;
import org.glite.authz.common.context.DecisionRequestContextHelper;
import org.glite.authz.common.logging.LoggingConstants;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Response;
import org.glite.authz.common.model.Result;
import org.glite.authz.common.model.Status;
import org.glite.authz.common.model.StatusCode;
import org.glite.authz.common.model.util.XACMLConverter;
import org.glite.authz.pep.obligation.ObligationProcessingException;
import org.glite.authz.pep.pip.PIPProcessingException;
import org.glite.authz.pep.pip.PolicyInformationPoint;
import org.glite.authz.pep.server.config.PEPDaemonConfiguration;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Statement;
import org.opensaml.ws.soap.client.SOAPClient;
import org.opensaml.ws.soap.client.SOAPFaultException;
import org.opensaml.ws.soap.client.http.HttpSOAPRequestParameters;
import org.opensaml.ws.soap.common.SOAPException;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xacml.ctx.RequestType;
import org.opensaml.xacml.ctx.StatusCodeType;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionStatementType;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import net.jcip.annotations.ThreadSafe;
import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.store.MemoryStoreEvictionPolicy;

/** Handles an incoming daemon {@link Request}. */
@ThreadSafe
public class PEPDaemonRequestHandler {

    /** Name of the cache used to cache PDP responses. */
    public static final String RESPONSE_CACHE_NAME = "org.glite.authz.pep.server.responseCache";

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(PEPDaemonRequestHandler.class);

    /** Audit log. */
    private final Logger auditLog = LoggerFactory.getLogger(LoggingConstants.AUDIT_CATEGORY);

    /** Protocol message log. */
    private final Logger protocolLog = LoggerFactory.getLogger(LoggingConstants.PROTOCOL_MESSAGE_CATEGORY);

    /** The daemon's configuration. */
    private PEPDaemonConfiguration daemonConfig;

    /** Cache used to store response to a request. */
    private Cache responseCache;

    /**
     * Constructor.
     * 
     * @param config
     *            the constructor for the daemon
     */
    public PEPDaemonRequestHandler(final PEPDaemonConfiguration config) {
	if (config == null) {
	    throw new IllegalArgumentException("Daemon configuration may not be null");
	}
	daemonConfig = config;

	if (daemonConfig.getMaxCachedResponses() > 0) {
	    CacheManager cacheMgr = CacheManager.create();
	    responseCache = new Cache(RESPONSE_CACHE_NAME, daemonConfig.getMaxCachedResponses(),
		    MemoryStoreEvictionPolicy.LFU, false, null, false, daemonConfig.getCachedResponseTTL(),
		    daemonConfig.getCachedResponseTTL(), false, Long.MAX_VALUE, null, null);
	    cacheMgr.addCache(responseCache);
	} else {
	    responseCache = null;
	}
    }

    /**
     * Handles a PEP thin client Hessian request. The request is deserialized
     * from the input stream and then converted into a {@link RequestType}. The
     * request is sent to a PDP with each registered PDP being tried in turn
     * until one accepts the incoming connection. The
     * {@link org.opensaml.xacml.ctx.ResponseType} from the PDP is then turned
     * in to a {@link Response}, serialized in Hessian and then written out.
     * 
     * @param request
     *            the request to be evaluated
     * 
     * @return the response to the given request
     * 
     * @throws IOException
     *             thrown if there is an error writing a response to the output
     *             stream
     */
    public Response handle(final Request request) throws IOException {
	daemonConfig.getServiceMetrics().incrementTotalServiceRequests();

	PEPDaemonDecisionRequestContext messageContext = buildMessageContext(daemonConfig.getEntityId());

	Response response = null;
	try {
	    // run the policy information points over the request
	    for (PolicyInformationPoint pip : daemonConfig.getPolicyInformationPoints()) {
		if (pip.populateRequest(request)) {
		    log.debug("PIP {} applied to Hessian request", pip.getId());
		} else {
		    log.debug("PIP {} do not apply to request", pip.getId());
		}
	    }
	    protocolLog.info("Hessian request after PIPs have been run\n{}", request.toString());

	    // check to see if we have a cached response
	    if (responseCache != null) {
		log.debug("Checking if a response has already been cached for this request");
		net.sf.ehcache.Element cacheElement = responseCache.get(request);
		if (cacheElement != null) {
		    Response cachedResponse = (Response) cacheElement.getValue();
		    if (cachedResponse != null) {
			log.debug("Cached response found, using it");
			response = cachedResponse;
			messageContext.setRespondingPDP("PEPD cache");
			messageContext.setAuthorizationDecision(response.getResults().get(0).getDecisionString());
		    }
		}
	    }
	    // if no cached response, send request to PDP
	    if (response == null) {
		log.debug("Response not found in cache, send to PDP");
		response = sendRequestToPDP(messageContext, request);
		if (response == null) {
		    String error = "No response received from PDP: " + daemonConfig.getPDPEndpoints();
		    log.error(error);
		    daemonConfig.getServiceMetrics().incrementTotalServiceRequestErrors();
		    response = buildErrorResponse(request, StatusCodeType.SC_PROCESSING_ERROR, error);
		    writeAuditLogEntry(messageContext);
		    return response;
		}
	    }

	    Result result = response.getResults().get(0);
	    // cache Deny/Permit decisions
	    if (responseCache != null && (result.getDecision() == Result.DECISION_DENY
		    || result.getDecision() == Result.DECISION_PERMIT)) {
		log.debug("Caching response {} for request {}", messageContext.getInboundMessageId(),
			messageContext.getOutboundMessageId());
		responseCache.put(new net.sf.ehcache.Element(request, response));
	    }

	    // run obligations handlers over the response
	    if (daemonConfig.getObligationService() != null) {
		log.debug("Processing obligations");
		daemonConfig.getObligationService().processObligations(request, result);
	    }

	} catch (PIPProcessingException e) {
	    daemonConfig.getServiceMetrics().incrementTotalServiceRequestErrors();
	    log.error("Error processing PIP: " + e.getMessage());
	    log.debug("", e);
	    response = buildErrorResponse(request, StatusCodeType.SC_PROCESSING_ERROR, e.getMessage());
	} catch (ObligationProcessingException e) {
	    daemonConfig.getServiceMetrics().incrementTotalServiceRequestErrors();
	    log.error("Error processing obligation handlers: " + e.getMessage());
	    log.debug("", e);
	    response = buildErrorResponse(request, StatusCodeType.SC_PROCESSING_ERROR, e.getMessage());
	} catch (Exception e) {
	    daemonConfig.getServiceMetrics().incrementTotalServiceRequestErrors();
	    log.error("Error processing authorization request: " + e.getMessage());
	    log.debug("", e);
	    response = buildErrorResponse(request, StatusCodeType.SC_PROCESSING_ERROR, e.getMessage());
	} finally {
	    protocolLog.info("Complete hessian response\n{}", response.toString());
	}

	writeAuditLogEntry(messageContext);
	return response;
    }

    /**
     * Attempts to send the SOAP request. This method attempts to send the
     * request to each registered PDP endpoint until one endpoint responses with
     * an HTTP 200 status code. If PDP returns a 200 then null is returned,
     * indicating that the response could not be sent to any PDP.
     * 
     * @param messageContext
     *            current request context
     * @param authzRequest
     *            the authorization request to be sent
     * 
     * @return the returned response
     */
    private Response sendRequestToPDP(final PEPDaemonDecisionRequestContext messageContext,
	    final Request authzRequest) {
	RequestType xacmlRequest = XACMLConverter.requestToXACML(authzRequest);
	Envelope soapRequest = DecisionRequestContextHelper.buildSOAPMessage(daemonConfig.getEntityId(), messageContext,
		xacmlRequest);
	logSOAPProtocolMessage(soapRequest, true);

	Iterator<String> pdpItr = daemonConfig.getPDPEndpoints().iterator();
	String pdpEndpoint = null;
	Response authzResponse = null;
	String errorMessage = null;
	while (pdpItr.hasNext()) {
	    try {
		pdpEndpoint = pdpItr.next();
		log.debug("Sending request {} to {}", messageContext.getOutboundMessageId(), pdpEndpoint);
		SOAPClient lClient = daemonConfig.getSOAPClient();
		lClient.send(pdpEndpoint, messageContext);
		authzResponse = extractResponse(messageContext, pdpEndpoint,
			(Envelope) messageContext.getInboundMessage());
		if (authzResponse != null) {
		    logSOAPProtocolMessage(messageContext.getInboundMessage(), false);
		    messageContext.setRespondingPDP(pdpEndpoint);
		    messageContext.setAuthorizationDecision(authzResponse.getResults().get(0).getDecisionString());
		    break;
		}
	    } catch (SOAPFaultException e) {
		String error = "Recieved SOAP Fault " + e.getFault().getCode() + " from PDP: " + pdpEndpoint;
		log.warn(error, e);
		errorMessage = error;
	    } catch (SOAPException e) {
		String error = "Error sending request to PDP: " + pdpEndpoint;
		log.error(error, e);
		errorMessage = error;
	    } catch (SecurityException e) {
		String error = "Response from PDP " + pdpEndpoint + " did not meet message security requirements";
		log.error(error, e);
		errorMessage = error;
	    }
	}

	if (authzResponse != null) {
	    log.debug("A decision of {} was reached by {} in response to request {}",
		    new Object[] { authzResponse.getResults().get(0).getDecisionString(),
			    messageContext.getRespondingPDP(), messageContext.getOutboundMessageId(), });
	    return authzResponse;
	} else {
	    log.error("No PDP endpoint was able to answer the authorization request");
	    messageContext.setProcessingError(errorMessage);
	    return null;
	}
    }

    /**
     * Extracts the response from a PDP response. If more than one assertion is
     * present
     * 
     * @param messageContext
     *            current request context
     * @param pdpEndpoint
     *            the endpoint to which the message should be sent
     * @param soapResponse
     *            the SOAP response containing the XACML-SAML authorization
     *            response
     * 
     * @return the extract response or <code>null</code> on error.
     */
    private Response extractResponse(final DecisionRequestContext messageContext, final String pdpEndpoint,
	    final Envelope soapResponse) {
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

	messageContext.setInboundMessageId(samlResponse.getID());
	XACMLAuthzDecisionStatementType authzStatement = (XACMLAuthzDecisionStatementType) authzStatements.get(0);
	return XACMLConverter.responseFromXACML(authzStatement.getResponse(), authzStatement.getRequest());
    }

    /**
     * Builds a Response containing an error. The Decision on error in
     * <b>Indeterminate</b>
     * 
     * @param request
     *            the request that caused the error
     * @param statusCode
     *            status code of the error
     * @param errorMessage
     *            associated error message
     * 
     * @return the built response
     */
    private Response buildErrorResponse(final Request request, final String statusCode, final String errorMessage) {
	StatusCode errorCode = new StatusCode();
	errorCode.setCode(statusCode);

	Status status = new Status();
	status.setCode(errorCode);
	if (errorMessage != null) {
	    status.setMessage(errorMessage);
	}

	Result result = new Result();
	result.setDecision(Result.DECISION_INDETERMINATE);
	result.setStatus(status);

	Response response = new Response();
	response.setRequest(request);
	response.getResults().add(result);
	return response;
    }

    /**
     * Logs an inbound/outbound SOAP message.
     * 
     * @param message
     *            the message to log
     * @param isRequest
     *            whether the message is a request
     */
    private void logSOAPProtocolMessage(final XMLObject message, final boolean isRequest) {
	if (message == null) {
	    return;
	}

	if (protocolLog.isDebugEnabled()) {
	    try {
		Element messageDom = Configuration.getMarshallerFactory().getMarshaller(message).marshall(message);
		if (isRequest) {
		    protocolLog.debug("Outgoing SOAP request\n{}", XMLHelper.prettyPrintXML(messageDom));
		} else {
		    protocolLog.debug("Inbound SOAP response\n{}", XMLHelper.prettyPrintXML(messageDom));
		}
	    } catch (MarshallingException e) {
		log.error("Unable to marshall SOAP message");
	    }
	}
    }

    /**
     * Writes a PEP daemon audit log entry.
     * 
     * @param messageContext
     *            current message context
     */
    private void writeAuditLogEntry(final PEPDaemonDecisionRequestContext messageContext) {
	AuditLogEntry entry = new AuditLogEntry(messageContext.getOutboundMessageId(),
		messageContext.getRespondingPDP(), messageContext.getInboundMessageId(),
		messageContext.getAuthorizationDecision());
	entry.setErrorMessage(messageContext.getProcessingError());
	auditLog.info(entry.toString());
    }

    /**
     * Extends the {@link DecisionRequestContext} to include processing error
     * message.
     * 
     * @see PEPDaemonRequestHandler#buildMessageContext(String)
     */
    protected class PEPDaemonDecisionRequestContext extends DecisionRequestContext {

	/** The processing error message. */
	private String processingError_;

	/**
	 * @return the processing error
	 */
	public String getProcessingError() {
	    return processingError_;
	}

	/**
	 * @param processingError
	 *            the processing error to set
	 */
	public void setProcessingError(final String processingError) {
	    processingError_ = processingError;
	}

    }

    /**
     * Builds a {@link PEPDaemonDecisionRequestContext}. The communication
     * profileID used is {@value AuthzServiceConstants#XACML_SAML_PROFILE_URI}.
     * 
     * @param messageIssuerId
     *            The entityID of the message issuer
     * @return a decision
     */
    protected PEPDaemonDecisionRequestContext buildMessageContext(final String messageIssuerId) {
	PEPDaemonDecisionRequestContext messageContext = new PEPDaemonDecisionRequestContext();
	messageContext.setCommunicationProfileId(AuthzServiceConstants.XACML_SAML_PROFILE_URI);
	messageContext.setOutboundMessageIssuer(messageIssuerId);
	messageContext.setSOAPRequestParameters(
		new HttpSOAPRequestParameters("http://www.oasis-open.org/committees/security"));
	return messageContext;
    }
}
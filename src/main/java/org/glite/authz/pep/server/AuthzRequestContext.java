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

import org.glite.authz.common.AuthzServiceConstants;

import org.opensaml.ws.soap.client.BasicSOAPMessageContext;
import org.opensaml.ws.soap.client.http.HttpSOAPRequestParameters;

/** An authorization request message context. */
class AuthzRequestContext extends BasicSOAPMessageContext {

    /** ID of the outbound authorization request. */
    private String outboundMessageId;

    /** URL to the PDP that responded to the authorization response. */
    private String respondingPDP;

    /** ID of the inbound authorization response. */
    private String inboundMessageId;

    /** The result of the authorization request. */
    private String authzDecision;

    /**
     * Default constructor
     */
    private AuthzRequestContext() {
        super();
    }

    /**
     * AuthzRequestContext factory.
     * 
     * @param messageIssuerId
     *            the outbound message issuer Id
     * @return a new AuthzRequestContext
     */
    static public AuthzRequestContext buildMessageContext(String messageIssuerId) {
        AuthzRequestContext messageContext= new AuthzRequestContext();
        messageContext.setCommunicationProfileId(AuthzServiceConstants.XACML_SAML_PROFILE_URI);
        messageContext.setOutboundMessageIssuer(messageIssuerId);
        messageContext.setSOAPRequestParameters(new HttpSOAPRequestParameters("http://www.oasis-open.org/committees/security"));

        // TODO fill in security policy resolver
        return messageContext;
    }

    /**
     * Gets the ID of the outbound authorization request.
     * 
     * @return ID of the outbound authorization request
     */
    public String getOutboundMessageId() {
        return outboundMessageId;
    }

    /**
     * Sets the ID of the outbound authorization request.
     * 
     * @param id
     *            ID of the outbound authorization request
     */
    public void setOutboundMessageId(String id) {
        outboundMessageId= id;
    }

    /**
     * Gets the URL to the PDP that responded to the authorization request.
     * 
     * @return URL to the PDP that responded the authorization request
     */
    public String getRespondingPDP() {
        return respondingPDP;
    }

    /**
     * Sets the URL to the PDP that responded the authorization request.
     * 
     * @param pdp
     *            URL to the PDP that responded the authorization request
     */
    public void setRespondingPDP(String pdp) {
        respondingPDP= pdp;
    }

    /**
     * Gets the ID of the inbound authorization response.
     * 
     * @return ID of the inbound authorization response
     */
    public String getInboundMessageId() {
        return inboundMessageId;
    }

    /**
     * Sets the ID of the inbound authorization response.
     * 
     * @param id
     *            ID of the inbound authorization response
     */
    public void setInboundMessageId(String id) {
        inboundMessageId= id;
    }

    /**
     * Gets the result of the authorization request.
     * 
     * @return result of the authorization request
     */
    public String getAuthorizationDecision() {
        return authzDecision;
    }

    /**
     * Sets the result of the authorization request.
     * 
     * @param decision
     *            result of the authorization request
     */
    public void setAuthorizationDecision(String decision) {
        authzDecision= decision;
    }
}
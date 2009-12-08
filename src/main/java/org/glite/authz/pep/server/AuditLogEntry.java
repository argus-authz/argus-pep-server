/*
 * Copyright 2009 Members of the EGEE Collaboration.
 * See http://www.eu-egee.org/partners for details on the copyright holders. 
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

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.util.Strings;
import org.joda.time.DateTime;

/** A log entry representing an auditable authorization decision. */
@ThreadSafe
public class AuditLogEntry {

    /** Request timestamp. */
    private long requestTime;

    /** ID of the SAML authorization request message. */
    private String requestId;

    /** PDP URL that rendered the decision. */
    private String responderId;

    /** The ID of the SAML response returned from the PDP. */
    private String responseId;

    /** The authorization decision. */
    private String policyDecision;

    /**
     * Constructor.
     * 
     * @param request ID of the SAML authorization request message
     * @param responder URL of the PDP that responded to the authorization request
     * @param decision the authorization decision
     * @param response ID of the SAML authorization response message
     */
    public AuditLogEntry(String request, String responder, String response, String decision) {
        requestTime = new DateTime().toDateTimeISO().getMillis();
        requestId = Strings.safeTrimOrNullString(request);
        responderId = Strings.safeTrimOrNullString(responder);
        responseId = Strings.safeTrimOrNullString(response);
        policyDecision = decision;
    }

    /**
     * Gets the authorization decision.
     * 
     * @return authorization decision
     */
    public String getPolicyDecision() {
        return policyDecision;
    }

    /**
     * Gets the URL of the PDP that responded to the authorization request.
     * 
     * @return URL of the PDP that responded to the authorization request
     */
    public String getResponderId() {
        return responderId;
    }

    /**
     * Get the ID of the SAML authorization decision request message.
     * 
     * @return ID of the SAML authorization decision request message
     */
    public String getRequestId() {
        return requestId;
    }

    /**
     * Gets the time, in milliseconds since the Unix epoch, in UTC, that the request was made.
     * 
     * @return time the request was made
     */
    public long getRequestTime() {
        return requestTime;
    }

    /**
     * Gets the ID of the SAML response returned to the requester.
     * 
     * @return ID of the SAML response returned to the requester
     */
    public String getResponseId() {
        return responseId;
    }

    /** {@inheritDoc} */
    public String toString() {
        StringBuilder entryString = new StringBuilder();

        entryString.append(getRequestTime());
        entryString.append("|");

        entryString.append(getRequestId());
        entryString.append("|");

        entryString.append(getResponderId());
        entryString.append("|");

        entryString.append(getResponseId());
        entryString.append("|");

        entryString.append(getPolicyDecision());
        entryString.append("|");

        return entryString.toString();
    }
}
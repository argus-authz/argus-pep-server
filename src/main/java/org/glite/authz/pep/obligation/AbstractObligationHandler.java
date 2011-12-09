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

package org.glite.authz.pep.obligation;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.util.Strings;

/**
 * Base class for all obligation handlers.
 * 
 * Handlers are executed in order of precedence. Handlers with a higher
 * precedence are executed before those with a lower precedence. Handlers with
 * the same precedence are executed in random order.
 * 
 * Obligation handlers <strong>must</strong> be stateless.
 */
@ThreadSafe
public abstract class AbstractObligationHandler implements ObligationHandler {

    /** ID of the obligation handler (name) */
    private String id_;

    /** ID of the handled obligation. */
    private String obligationId_;

    /** Precedence of this handler. */
    private int precedence_;

    /**
     * Old constructor, keep for back compatibility (EES OH!!!).
     * 
     * @param obligationId
     *            ID of the handled obligation
     * @deprecated use the new constructor
     *             {@link #AbstractObligationHandler(String, String)}
     */
    protected AbstractObligationHandler(String obligationId) {
        this(obligationId, obligationId);
    }

    /**
     * Constructor. Obligation has the lowest precedence, zero.
     * 
     * @param name
     *            the obligation handler unique identifier (name)
     * @param obligationId
     *            ID of the handled obligation
     */
    protected AbstractObligationHandler(String name, String obligationId) {
        this(name, obligationId, 0);
    }

    /**
     * Constructor.
     * 
     * @param name
     *            the obligation handler unique identifier (name)
     * @param obligationId
     *            ID of the handled obligation
     * @param handlerPrecedence
     *            precedence of this handler, must be 0 or greater
     */
    protected AbstractObligationHandler(String name, String obligationId,
            int handlerPrecedence) {
        setId(name);
        obligationId_= Strings.safeTrimOrNullString(obligationId);
        if (obligationId_ == null) {
            throw new IllegalArgumentException("Provided obligation ID may not be null or empty");
        }

        if (handlerPrecedence < 0) {
            throw new IllegalArgumentException("Handler precedence must be 0 or greater");
        }
        precedence_= handlerPrecedence;
    }

    /**
     * Gets the ID of the handled obligation.
     * 
     * @return ID of the handled obligation
     */
    public String getObligationId() {
        return obligationId_;
    }

    /**
     * Gets the precedence of the handler.
     * 
     * @return precedence of the handler
     */
    public int getHandlerPrecedence() {
        return precedence_;
    }

    /**
     * Sets the precedence of the handler.
     * @param precedence of the handler
     */
    protected void setHanderPrecedence(int precedence) {
        precedence_= precedence;
    }
    
    /**
     * Gets a unique identifier (name) for this obligation handle.
     * 
     * @return the unique identifier (name) for this obligation handle
     */
    public String getId() {
        return id_;
    }

    /**
     * Sets the obligation handler unique identifier (name)
     * 
     * @param id
     *            the obligation handler unique identifier (name)
     */
    protected void setId(String id) {
        String tempId= Strings.safeTrimOrNullString(id);
        if (tempId == null) {
            throw new IllegalArgumentException("Obligation Handler ID may not be null or empty");
        }
        id_= tempId;
    }

    /** {@inheritDoc} */
    public int hashCode() {
        return getObligationId().hashCode();
    }

    /** {@inheritDoc} */
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }

        if (obj instanceof ObligationHandler) {
            return Strings.safeEquals(getObligationId(),
                                      ((ObligationHandler) obj).getObligationId());
        }

        return false;
    }
}
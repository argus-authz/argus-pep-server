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

import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.model.Obligation;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Result;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** A service for evaluating the obligations within a context. */
@ThreadSafe
public class ObligationService {
    
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(ObligationService.class);

    /** Read/write lock around the registered obligation handlers. */
    private ReentrantReadWriteLock rwLock;

    /** Registered obligation handlers. */
    private Set<ObligationHandler> obligationHandlers;

    /** Constructor. */
    public ObligationService() {
        rwLock = new ReentrantReadWriteLock(true);
        obligationHandlers = new TreeSet<ObligationHandler>(new ObligationHandlerComparator());
    }

    /**
     * Gets the registered obligation handlers.
     * 
     * @return registered obligation handlers
     */
    public Set<ObligationHandler> getObligationHandlers() {
        return Collections.unmodifiableSet(obligationHandlers);
    }

    /**
     * Adds an obligation handler to the list of registered handlers
     * 
     * This method waits until a write lock is obtained for the set of registered obligation handlers.
     * 
     * @param handler the handler to add to the list of registered handlers.
     */
    public void addObligationhandler(ObligationHandler handler) {
        if (handler == null) {
            return;
        }

        Lock writeLock = rwLock.writeLock();
        writeLock.lock();
        try {
            obligationHandlers.add(handler);
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Adds a collection of obligation handler to the list of registered handlers
     * 
     * This method waits until a write lock is obtained for the set of registered obligation handlers.
     * 
     * @param handlers the collection of handlers to add to the list of registered handlers.
     */
    public void addObligationhandlers(Collection<ObligationHandler> handlers) {
        if (handlers == null || handlers.isEmpty()) {
            return;
        }

        Lock writeLock = rwLock.writeLock();
        writeLock.lock();
        try {
            obligationHandlers.addAll(handlers);
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Removes an obligation handler from the list of registered handlers
     * 
     * This method waits until a write lock is obtained for the set of registered obligation handlers.
     * 
     * @param handler the handler to remove from the list of registered handlers.
     */
    public void removeObligationHandler(ObligationHandler handler) {
        if (handler == null) {
            return;
        }

        Lock writeLock = rwLock.writeLock();
        writeLock.lock();
        try {
            obligationHandlers.remove(handler);
        } finally {
            writeLock.unlock();
        }
    }

    /**
     * Processes the obligations within the effective XACML policy.
     * 
     * This method waits until a read lock is obtained for the set of registered obligation handlers.
     * 
     * @param request the authorization request
     * @param result the result currently be processed
     * 
     * @throws ObligationProcessingException thrown if there is a problem evaluating an obligation
     */
    public void processObligations(Request request, Result result) throws ObligationProcessingException {
        Lock readLock = rwLock.readLock();
        readLock.lock();
        try {
            Iterator<ObligationHandler> handlerItr = obligationHandlers.iterator();
            Map<String, Obligation> effectiveObligations = preprocessObligations(result);
            log.debug("Obligations in effect for this result: {}", effectiveObligations.keySet());

            ObligationHandler handler;
            while (handlerItr.hasNext()) {
                handler = handlerItr.next();
                if (effectiveObligations.containsKey(handler.getObligationId())) {
                    log.debug("Processing obligation {}", handler.getObligationId());
                    handler.evaluateObligation(request, result);
                }
            }
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Pre-processes the obligations returned within the result. This pre-processing determines which obligation
     * handlers are active for a given result. An obligation handler is active if it exists and its {@code Fulfillon}
     * property matches the result {@code Decision}.
     * 
     * @param result the result currently be processed
     * 
     * @return pre-processed obligations indexed by obligation ID
     */
    protected Map<String, Obligation> preprocessObligations(Result result) {
        HashMap<String, Obligation> effectiveObligations = new HashMap<String, Obligation>();

        List<Obligation> obligations = result.getObligations();
        if (obligations == null || obligations.isEmpty()) {
            return effectiveObligations;
        }

        for (Obligation obligation : obligations) {
            if (obligation != null && obligation.getFulfillOn() == result.getDecision()) {
                effectiveObligations.put(obligation.getId(), obligation);
            }
        }

        return effectiveObligations;
    }

    /** Comparator used to order obligation handlers by precedence. */
    private class ObligationHandlerComparator implements Comparator<ObligationHandler> {

        /** {@inheritDoc} */
        public int compare(ObligationHandler o1, ObligationHandler o2) {
            if (o1.getHandlerPrecedence() == o2.getHandlerPrecedence()) {
                // If they have the same precedence sort lexigraphically
                return o1.getObligationId().compareTo(o2.getObligationId());
            }

            if (o1.getHandlerPrecedence() < o2.getHandlerPrecedence()) {
                return -1;
            }

            return 1;
        }
    }
}
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

import java.math.BigInteger;

import net.jcip.annotations.ThreadSafe;

/** A set of metrics kept about a running PEP daemon. */
@ThreadSafe
public class PEPDaemonMetrics {

    /** Time the daemon started. */
    private long startupTime;

    /** Total number of authorization requests. */
    private BigInteger totalAuthzRequests;

    /** Accumulator of authorization requests. */
    private int totalAuthzRequestAccumulator;

    /** Total number of authorization request that errored out. */
    private BigInteger totalAuthzErrors;

    /** Accumulator of errored out authorization requests. */
    private int totalAuthzErrorsAccumulator;

    /** Constructor. */
    public PEPDaemonMetrics() {
        totalAuthzRequests = new BigInteger("0");
        totalAuthzErrors = new BigInteger("0");
        startupTime = System.currentTimeMillis();
    }

    /**
     * Gets the time that PEP daemon was started. The time is expressed in the system's default timezone.
     * 
     * @return time that PEP daemon was started
     */
    public long getStartupTime() {
        return startupTime;
    }

    /**
     * Gets the total number of authorization requests, successful or otherwise, serviced by the daemon.
     * 
     * @return total number of authorization requests
     */
    public BigInteger getTotalAuthorizationRequests() {
        return totalAuthzRequests.add(integerToBigInteger(totalAuthzRequestAccumulator));
    }

    /** Adds one to the total number of authorization requests. */
    public synchronized void incrementTotalAuthorizationRequests() {
        totalAuthzRequestAccumulator = incrementMetric(totalAuthzRequests, totalAuthzRequestAccumulator);
    }

    /**
     * Gets the total number of authorization requests that errored out.
     * 
     * @return total number of authorization requests that errored out
     */
    public BigInteger getTotalAuthorizationRequestErrors() {
        return totalAuthzErrors.add(integerToBigInteger(totalAuthzErrorsAccumulator));
    }

    /** Adds one to the total number of authorization requests that have errored out. */
    public synchronized void incrementTotalAuthorizationRequestErrors() {
        totalAuthzErrorsAccumulator = incrementMetric(totalAuthzErrors, totalAuthzErrorsAccumulator);
    }

    /**
     * Increments a measurement stored in a BigInteger but with a integer accumulator serving as a temporary bucket.
     * This avoids the cost of creating new BigIntegers, which are immutable, every time the metric is incremented.
     * 
     * @param store the BigInteger store
     * @param accumulator the temporary accumulation bucket
     * 
     * @return new value for the accumulator
     */
    private int incrementMetric(BigInteger store, int accumulator) {
        if (accumulator == Integer.MAX_VALUE - 1) {
            store = store.add(integerToBigInteger(accumulator++));
            return 0;
        } else {
            return accumulator + 1;
        }
    }

    /**
     * Converted an integer in to a {@link BigInteger}.
     * 
     * @param integer integer to convert
     * 
     * @return BigInteger form of the integer
     */
    private BigInteger integerToBigInteger(Integer integer) {
        return new BigInteger(Integer.toString(integer));
    }
}
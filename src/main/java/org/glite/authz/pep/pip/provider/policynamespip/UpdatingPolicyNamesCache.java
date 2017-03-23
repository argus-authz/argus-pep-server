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
 *
 * Authors:
 * 2016-
 *    Mischa Salle <msalle@nikhef.nl>
 *    NIKHEF Amsterdam, the Netherlands
 *    <grid-mw-security@nikhef.nl>
 */

package org.glite.authz.pep.pip.provider.policynamespip;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;


import java.io.IOException;


/**
 * Helper class for {@link org.glite.authz.pep.pip.provider.PolicyNamesPIP}
 * providing a an updating parsed cache of the subjectdn entries in the info
 * files in the trust directory.
 * @author Mischa Sall&eacute;
 */
public class UpdatingPolicyNamesCache {
    /** Class logger instance */
    private static final Logger LOG = LoggerFactory.getLogger(UpdatingPolicyNamesCache.class);

    /** The read/write lock that implements thread safety for this store **/
    protected final ReadWriteLock rwLock = new ReentrantReadWriteLock();

    /** A reference to the read lock **/
    protected final Lock read = rwLock.readLock();

    /** A reference to the write lock **/
    protected final Lock write = rwLock.writeLock();

    ////////////////////////////////////////////////////////////////////////
    // constants
    ////////////////////////////////////////////////////////////////////////

    /** Default time interval (in msec) after which info files cache will be
     * refreshed ({@value}) */
    public final static long UPDATEINTERVAL = TimeUnit.HOURS.toMillis(6);
  

    ////////////////////////////////////////////////////////////////////////
    // instance variables
    ////////////////////////////////////////////////////////////////////////
 
    /** time interval (in msec) after which info files cache will be
     * refreshed, default {@link #UPDATEINTERVAL}. */
    private long updateInterval = UPDATEINTERVAL;

    /** Whether a thread is updating the {@link PolicyNamesCache} */
    private volatile boolean isUpdating = false;

    /** Cache of info file directory
     * @see PolicyNamesCache */
    private volatile PolicyNamesCache cache = null;


    ////////////////////////////////////////////////////////////////////////
    // setter methods
    ////////////////////////////////////////////////////////////////////////
     
    /**
     * Sets the {@link #updateInterval} (in msec) after which info files cache
     * will be reprocessed.
     * @param msecs number of millisecs between updates
     * @see #UPDATEINTERVAL
     */
    public void setUpdateInterval(long msecs)    {
	updateInterval=msecs;
    }
    
    ////////////////////////////////////////////////////////////////////////
    // Constructors
    ////////////////////////////////////////////////////////////////////////
    
    /**
     * constructs new UpdatingPolicyNamesCache based on given trustDir and
     * updateInterval
     * @param trustDir directory containing info files
     * @param msecs number of millisecs between updates
     * @throws IOException on read errors for trust_dir or one of the info files
     * @see #UpdatingPolicyNamesCache(String)
     * @throws IOException in case of I/O errors
     */
    public UpdatingPolicyNamesCache(String trustDir, long msecs) throws IOException {
	this(trustDir);
	this.updateInterval = msecs;
    }

    /**
     * constructs new UpdatingPolicyNamesCache based on given trustDir and
     * default {@link #UPDATEINTERVAL}.
     * @param trustDir directory containing info files
     * @param updateInterval interval (msec) between info file cache updates
     * @see #UpdatingPolicyNamesCache(String, long)
     * @throws IOException in case of I/O errors
     */
    public UpdatingPolicyNamesCache(String trustDir) throws IOException {
	this.cache = new PolicyNamesCache(trustDir);
    }


    ////////////////////////////////////////////////////////////////////////
    // Main instance method
    ////////////////////////////////////////////////////////////////////////

    /**
     * Tries to find given subjectDN in the info files in trust dir.
     * @param dn String subject DN to look for
     * @return array of String with all the matching info files
     * @throws IOException upon reading errors in updating the
     * {@link PolicyNamesCache}
     * @see PolicyNamesCache#matchIssuerDN(String)
     */
    public String[] findIssuerDN(String dn) throws IOException   {
	// Update the cache (when needed)
	updateCache();

	// Obtain read lock
	read.lock();
	try {
	    // Find and return matching info files
	    return cache.matchIssuerDN(dn);
	} finally {
	    // release read lock
	    read.unlock();
	}
    }
    

    ////////////////////////////////////////////////////////////////////////
    // Private methods
    ////////////////////////////////////////////////////////////////////////

    /**
     * Update the internal {@link PolicyNamesCache} when needed
     * @throws IOException upon I/O errors in updating the
     * {@link PolicyNamesCache}
     */
    private void updateCache() throws IOException    {
	PolicyNamesCache newCache=null;

	// First check (with appropriate read lock) whether we need to do
	// anything. If so, create a new cache.
	read.lock();
	try {
	    if (cache.getLifeTime() < updateInterval || isUpdating==true)   { 
		return;
	    }

	    // Set updating flag. Note: another thread might have set the
	    // updating flag after we have just checked, in which case both will
	    // create a new cache. Even then only one will be used, due to the
	    // second getLifeTime() check below
	    isUpdating = true;

	    // Make a new cache, using the old as input. If this throws a
	    // IOException, the old cache remains valid.
	    newCache = new PolicyNamesCache(cache);
	} finally {
	    read.unlock();
	}

	// Now replace: also put a write lock
	write.lock();
	try {
	    // Check we have a valid new cache and the old cache is still
	    // out-of-date (i.e. hasn't been updated in the mean time by another
	    // thread
	    if (newCache==null)	{
		// This probably never happens: exception will have been thrown
		LOG.warn("New cache is null, continuing to use old one");
	    } else if (cache.getLifeTime() < updateInterval)	{
		LOG.info("Other thread appears to have already updated cache");
	    } else  {
		cache=newCache;
	    }

	    // now reset the updating flag
	    isUpdating = false;
	} finally {
	    write.unlock();
	}
    }
}

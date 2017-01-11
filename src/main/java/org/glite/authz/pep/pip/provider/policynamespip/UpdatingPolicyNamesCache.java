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

import java.io.IOException;


/**
 * Subclass for {@link org.glite.authz.pep.pip.provider.PolicyNamesPIP}
 * providing a an updating parsed cache of the subjectdn entries in the info
 * files in the trust directory.
 * @author Mischa Sall&eacute;
 */
public class UpdatingPolicyNamesCache {
    /** Class logger instance */
    private final Logger log = LoggerFactory.getLogger(UpdatingPolicyNamesCache.class);


    ////////////////////////////////////////////////////////////////////////
    // constants
    ////////////////////////////////////////////////////////////////////////

    /** Default time interval (in msec) after which info files cache will be
     * refreshed ({@value}) */
    public final static long UPDATEINTERVAL = 6*3600*1000;
  

    ////////////////////////////////////////////////////////////////////////
    // instance variables
    ////////////////////////////////////////////////////////////////////////
 
    /** time interval (in msec) after which info files cache will be
     * refreshed, default {@link #UPDATEINTERVAL}. */
    private long update_interval=UPDATEINTERVAL;

    /** Whether we're updating and replacing the {@link PolicyNamesCache} */
    private volatile boolean updating=false;

    /** Cache of info file directory
     * @see PolicyNamesCache */
    private volatile PolicyNamesCache cache = null;


    ////////////////////////////////////////////////////////////////////////
    // setter methods
    ////////////////////////////////////////////////////////////////////////
     
    /**
     * Sets the {@link #update_interval} (in msec) after which info files cache
     * will be reprocessed.
     * @param msecs number of millisecs between updates
     * @see #UPDATEINTERVAL
     */
    public void setUpdateInterval(long msecs)    {
	update_interval=msecs;
    }
    
    ////////////////////////////////////////////////////////////////////////
    // Constructors
    ////////////////////////////////////////////////////////////////////////
    
    /**
     * constructs new UpdatingPolicyNamesCache based on given trustDir and
     * updateInterval
     * @param trustDir directory containing info files
     * @throws IOException on read errors for trust_dir or one of the info files
     * @see #UpdatingPolicyNamesCache(String)
     * @throws IOException in case of I/O errors
     */
    public UpdatingPolicyNamesCache(String trustDir, long updateInterval) throws IOException {
	this(trustDir);
	this.update_interval = updateInterval;
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

	// Protect against empty cache
	if (cache == null)  {
	    log.warn("Encountered empty cache while matching DN "+dn);
	    return new String[0];
	}

	return cache.matchIssuerDN(dn);
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
	if (updating)
	    return;

	// set lock: prevent other threads from updating
	updating=true;

	// Check whether cached list needs updating
	if (cache.getLifeTime() > update_interval)	{
	    // Make a new cache, using the old as input. If this throws a
	    // IOException, we will not reset the updating flag, which means we
	    // will not re-try to update the cache and the old cache remains
	    // valid.
	    PolicyNamesCache newCache = new PolicyNamesCache(cache);
	    // Replace the old cache
	    cache=newCache;
	}
	
	// Unset lock
	updating=false;
    }
}

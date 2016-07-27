// Copyright (c) FOM-Nikhef 2016-
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Authors:
// 2016-
// Mischa Salle <msalle@nikhef.nl>
// Rens Visser <rensv@nikhef.nl>
// NIKHEF Amsterdam, the Netherlands
// <grid-mw-security@nikhef.nl>

package org.glite.authz.pep.pip.provider;

import org.glite.authz.pep.pip.provider.policynamespip.PolicyNamesPIPCache;

import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.model.Attribute;

import org.glite.authz.pep.pip.PIPProcessingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;
import java.io.IOException;
import java.text.ParseException;


/**
 * This PIP searches for all appearances of the issuer of the end-entity
 * certificate in the IGTF .info files. The resulting set is pushed into a
 * {@value #ATTR_CA_POLICY_NAMES} attribute.
 * @author Mischa Sall&eacute;, Rens Visser 
 */
public class PolicyNamesPIP extends AbstractPolicyInformationPoint {
    /** Class logger instance */
    private final Logger log = LoggerFactory.getLogger(PolicyNamesPIP.class);


    ////////////////////////////////////////////////////////////////////////
    // constants
    ////////////////////////////////////////////////////////////////////////
     
    /** Default name of input issuer DN attribute ({@value}) */
    public final static String ATTR_X509_ISSUER = "http://authz-interop.org/xacml/subject/subject-x509-issuer";

    /** Default name of output CA policy names attribute ({@value}) */
    public final static String ATTR_CA_POLICY_NAMES = "http://authz-interop.org/xacml/subject/ca-policy-names";

    /** Default trust dir ({@value}) */
    public final static String TRUST_DIR = "/etc/grid-security/certificates";

    /** Default time interval (in msec) after which info files cache will be
     * refreshed ({@value}) */
    public final static long UPDATEINTERVAL = 6*3600*1000;


    ////////////////////////////////////////////////////////////////////////
    // instance variables, settable
    ////////////////////////////////////////////////////////////////////////
     
    /** Time interval (in msec) after which info files cache will be
     * refreshed, default {@link #UPDATEINTERVAL}.
     * @see #setUpdateInterval(long) */
    private long update_interval = UPDATEINTERVAL;

    /** Info file directory (trust dir), default {@link #TRUST_DIR}
     * @see #setTrustDir(String) */
    private String trust_dir=TRUST_DIR;

    /** Name of attribute set by PIP, default {@link #ATTR_CA_POLICY_NAMES}
     * @see #setAttributeName(String) */
    private String attribute_name = ATTR_CA_POLICY_NAMES;


    ////////////////////////////////////////////////////////////////////////
    // instance variables, internal use only
    ////////////////////////////////////////////////////////////////////////
    
    /** Whether we're updating and replacing the {@link PolicyNamesPIPCache} */
    private boolean updating=false;

    /** Cache of info file directory
     * @see PolicyNamesPIPCache */
    private PolicyNamesPIPCache cache = null;


    ////////////////////////////////////////////////////////////////////////
    // setter methods
    ////////////////////////////////////////////////////////////////////////
     
    /**
     * Sets the {@link #update_interval} (in msec) after which info files cache
     * will be reprocessed.
     * @param msecs number of millisecs between updates
     * @see #UPDATEINTERVAL
     */
    protected void setUpdateInterval(long msecs)    {
	update_interval=msecs;
    }
   
    /**
     * Sets the output attribute name.
     * @param attributeName name of attribute set by this PIP
     * @see #ATTR_CA_POLICY_NAMES
     */
    protected void setAttributeName(String attributeName)    {
	attribute_name=attributeName;
    }

    /**
     * Sets the {@link #trust_dir} for this instance, when different from the
     * current value. In that case it also resets the {@link #cache} since that
     * is no longer valid. Note that this is not thread-safe.
     * @param trustDir directory where info files are located.
     * @see #TRUST_DIR
     * @throws IOException upon I/O errors in updating the
     * {@link PolicyNamesPIPCache}
     */
    protected void setTrustDir(String trustDir) throws IOException    {
	// If argument is different from current one, update
	if (trust_dir==null || !trust_dir.equals(trustDir)) {
	    trust_dir=trustDir;
	    cache = new PolicyNamesPIPCache(trust_dir);
	}
    }

    ////////////////////////////////////////////////////////////////////////
    // Constructors
    ////////////////////////////////////////////////////////////////////////
     
    /**
     * constructor for a {@link PolicyNamesPIP} instance, specifying both the
     * pipid and the {@link #trust_dir}.
     * @param pipid ID for this PIP
     * @param trustDir directory containing info files
     * @see #PolicyNamesPIP(String)
     * @throws IOException in case of I/O errors
     */
    public PolicyNamesPIP(String pipid, String trustDir) throws IOException {
	super(pipid);

	// Set internal trust_dir
	trust_dir=trustDir;

	// Initialize cache
	cache = new PolicyNamesPIPCache(trustDir);
    }

    /**
     * constructor for a {@link PolicyNamesPIP} instance using default {@link
     * #TRUST_DIR}.
     * @param pipid ID for this PIP
     * @see #PolicyNamesPIP(String,String)
     * @throws IOException in case of I/O errors
     */
    public PolicyNamesPIP(String pipid)	throws IOException {
	this(pipid, TRUST_DIR);
    }


    ////////////////////////////////////////////////////////////////////////
    // Main PIP method
    ////////////////////////////////////////////////////////////////////////
     
    /**
     * {@inheritDoc}
     * This PIP adds a {@value #ATTR_CA_POLICY_NAMES} attribute to the
     * corresponding subjects. The value(s) of this attribute are the short
     * names of all the {@value PolicyNamesPIPCache#FILE_SFX} files that match
     * the value of the {@value ATTR_X509_ISSUER} attribute.
     * @param request the incoming request.
     * @throws PIPProcessingException in case of errors.
     * @return boolean: true when attribute has been populated, false otherwise.
     */
    public boolean populateRequest(Request request)
	throws PIPProcessingException
    {
	long t0=System.nanoTime();
	boolean pipprocessed=false;
	String issuerdn=null;

	// Get all subjects from the request, should be at least one, warn
	// when there are more than 1
	Set<Subject> subjects = request.getSubjects();
	if (subjects.isEmpty())	{
	    log.error("Request has no subjects");
	    throw new PIPProcessingException("No subject found in request");
	}
	if (subjects.size()>1)
	    log.warn("Request has "+subjects.size()+
		     " subjects, taking first match");

	// Loop over all subjects
	for (Subject subject : subjects) {
	    // Loop over all attributes, looking for ATTR_X509_ISSUER
	    Set<Attribute> attributes = subject.getAttributes();
	    for (Attribute attr: attributes) {
		if (ATTR_X509_ISSUER.equals(attr.getId())) {
		    // Take first value (it should be singlevalued)
		    Object tmp = attr.getValues().iterator().next();
		    issuerdn = (tmp!=null ? tmp.toString() : null);
		    break;
		}
	    }

	    // Did we find the issuer attribute?
	    if (issuerdn==null)	{
		log.info("Subject has no or invalid "+ATTR_X509_ISSUER+
			 " attribute set");
		continue;
	    }

	    // Look for the issuerdn in the .info files
	    String[] policynames=new String[0];
	    try {
		policynames=findSubjectDN(issuerdn);
	    } catch (IOException e)	{
		log.error("I/O error reading info files: "+e.getMessage());
		throw new PIPProcessingException(
		    "I/O error reading info files: "+e.getMessage());
	    }

	    // Log total number of matching policies
	    log.debug("Found "+policynames.length+" matching policies");

	    // Check that we found any names
	    if (policynames.length==0)	{
		log.info("No matching info file for this subject");
		continue;
	    }

	    // Create new attribute and add the policy names
	    Attribute attr_policynames =
		new Attribute(attribute_name,
			      Attribute.DT_STRING);
	    Set<Object> values = attr_policynames.getValues();
	    for (int i=0; i<policynames.length; i++)
		values.add(policynames[i]);

	    // Add to the current subject
	    attributes.add(attr_policynames);
	    pipprocessed=true;
	    log.debug("Added attribute \""+attribute_name+"\"");
	}

	// Log statistics
	log.debug("PIP parsing took "+(System.nanoTime()-t0)/1000000.0+" msec");

	// Return true when attribute is set
	return pipprocessed;
    }


    ////////////////////////////////////////////////////////////////////////
    // Private methods
    ////////////////////////////////////////////////////////////////////////
     
    /**
     * Tries to find given subjectDN in the info files in {@link #trust_dir}.
     * @param dn String subject DN to look for
     * @return array of String with all the matching info files
     * @throws IOException upon reading errors in updating the
     * {@link PolicyNamesPIPCache}
     */
    private String[] findSubjectDN(String dn) throws IOException   {
	// Update the cache (when needed)
	updateCache();

	// Protect against empty cache
	if (cache == null)
	    return new String[0];

	return cache.matchIssuerDN(dn);
    }
    
    /**
     * Update the internal {@link PolicyNamesPIPCache} when needed
     * @throws IOException upon I/O errors in updating the
     * {@link PolicyNamesPIPCache}
     */
    private void updateCache() throws IOException    {
	if (updating)
	    return;

	// set lock: prevent other threads from updating
	updating=true;

	// Check whether cached list needs updating
	if (cache.getLifeTime() > update_interval)	{
	    // Make a new cache, using the old as input
	    PolicyNamesPIPCache newCache = new PolicyNamesPIPCache(cache);
	    // Replace the old cache
	    cache=newCache;
	}
	
	// Unset lock
	updating=false;
    }
}

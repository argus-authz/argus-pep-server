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
 *    Rens Visser <rensv@nikhef.nl>
 *    NIKHEF Amsterdam, the Netherlands
 *    <grid-mw-security@nikhef.nl>
 */

package org.glite.authz.pep.pip.provider;

import org.glite.authz.pep.pip.provider.policynamespip.UpdatingPolicyNamesCache;

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


    ////////////////////////////////////////////////////////////////////////
    // instance variables
    ////////////////////////////////////////////////////////////////////////
     
    /** Name of attribute set by PIP, default {@link #ATTR_CA_POLICY_NAMES}
     * @see #setAttributeName(String) */
    private String attribute_name = ATTR_CA_POLICY_NAMES;

    /** Contains the cached content of the info files in the trust dir. */
    private UpdatingPolicyNamesCache policyNamesCache = null;


    ////////////////////////////////////////////////////////////////////////
    // setter methods
    ////////////////////////////////////////////////////////////////////////
     
    /**
     * Sets the output attribute name.
     * @param attributeName name of attribute set by this PIP
     * @see #ATTR_CA_POLICY_NAMES
     */
    protected void setAttributeName(String attributeName)    {
	attribute_name=attributeName;
    }

    /**
     * Sets the update interval (in msec) after which info files cache will be
     * reprocessed.
     * @param msecs number of millisecs between updates
     * @see UpdatingPolicyNamesCache#setUpdateInterval(long)
     */
    protected void setUpdateInterval(long msecs)    {
	policyNamesCache.setUpdateInterval(msecs);
    }
   
    ////////////////////////////////////////////////////////////////////////
    // Constructors
    ////////////////////////////////////////////////////////////////////////
     
    /**
     * constructor for a {@link PolicyNamesPIP} instance, specifying the
     * pipid, the trust dir and the update interval.
     * @param pipid ID for this PIP
     * @param trustDir directory containing info files
     * @param updateInterval interval (msec) between info file cache updates
     * @see #PolicyNamesPIP(String)
     * @throws IOException in case of I/O errors
     */
    public PolicyNamesPIP(String pipid, String trustDir, long updateInterval) throws IOException {
	super(pipid);

	// Initialize cache
	policyNamesCache = new UpdatingPolicyNamesCache(trustDir, updateInterval);
    }

    /**
     * constructor for a {@link PolicyNamesPIP} instance, specifying the
     * pipid and the trust dir, using a default {@link
     * UpdatingPolicyNamesCache#UPDATEINTERVAL}.
     * @param pipid ID for this PIP
     * @see #PolicyNamesPIP(String,String)
     * @throws IOException in case of I/O errors
     */
    public PolicyNamesPIP(String pipid, String trustDir) throws IOException {
	super(pipid);

	// Initialize cache
	policyNamesCache = new UpdatingPolicyNamesCache(trustDir);
    }

    /**
     * constructor for a {@link PolicyNamesPIP} instance, specifying the
     * pipid and using the default {@link #TRUST_DIR} and default {@link
     * UpdatingPolicyNamesCache#UPDATEINTERVAL}.
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
		policynames=policyNamesCache.findIssuerDN(issuerdn);
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
}

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
 * Mischa Salle <msalle@nikhef.nl>
 * NIKHEF Amsterdam, the Netherlands
 * <grid-mw-security@nikhef.nl>
 */

package org.glite.authz.pep.pip.provider;

import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.pep.pip.PIPProcessingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.Before;
import org.junit.After;
import org.hamcrest.CoreMatchers;

/**
 * JUnit framework tests for {@link PolicyNamesPIP}
 * @author Mischa Sall&eacute;
 */
public class PolicyNamesPIPTest {
    PolicyNamesPIP pip;

    private final Logger log = LoggerFactory.getLogger(PolicyNamesPIP.class);

    private final static String GoodDN = "/C=NL/O=Example/OU=PDP/CN=Test CA";
    
    private final static String BadDN = "/C=John Doe";

    /**
     * Setup a new {@link PolicyNamesPIP_PIP} PIP and set the accepted attributes
     * to all of them
     */
    @Before
    public void initialize() throws Exception {
	log.debug("Creating PIP");
	pip = new PolicyNamesPIP("PolicyNamesPIP", getClass().getResource("/certificates").getFile());
        pip.start();
    }

    /** Stop the {@link PolicyNamesPIP} PIP */
    @After
    public void finalize() throws Exception {
	log.debug("Stopping PIP");
	if (pip!=null)	{
	    pip.stop();
	} else	{
	    log.warn("PIP already stopped it seems...");
	}
    }

    /**
     * Helper method for handling tests that throw a PIPProcessingException
     * @param request input request
     * @param element String which should match the stacktrace message
     * @return boolean: true when PIP has applied, false otherwise
     */
    protected boolean throwsPIPProcessingException(Request request, String element) {
	    boolean applied= false;
	    try {
		log.debug("Request="+request);
		applied= pip.populateRequest(request);
		fail("must throw PIPProcessingException");
	    } catch (PIPProcessingException e) {
		// expected
		String message= e.getMessage();
		assertNotNull("Got a null error message", message);
		log.debug("EXPECTED: " + message);
		log.debug("GOT ("+message.indexOf(element)+"): " + element);
		assertThat(message, CoreMatchers.containsString(element));
	    } catch (Exception e) {
		e.printStackTrace();
		fail("must throw only PIPProcessingException: " + e.getMessage());
	    }        
	    return applied;
    }

    /**
     * Creates a new request with specified issuerDN in the
     * {@link PolicyNamesPIP.ATTR_X509_ISSUER} attribute
     * @param issuerDN issuer DN to use
     * @return Request
     */
    protected Request createRequest(String issuerDN) {
	Request request= new Request();
	Subject subject= new Subject();
	Attribute attr = new Attribute(PolicyNamesPIP.ATTR_X509_ISSUER);
	attr.getValues().add(issuerDN);
	subject.getAttributes().add(attr);
	request.getSubjects().add(subject);
        return request;
    }

    /**
     * Creates an empty request (no subjects)
     * @return Request
     */
    protected Request createEmptyRequest() {
        Request request= new Request();
        return request;
    }


    /** Test with empty directory */
    @Test
    public void testNoDir() throws Exception {
	log.info("test with unset trust_dir");
	PolicyNamesPIP pip = new PolicyNamesPIP("PolicyNamesPIP2", "");
	assertTrue("expected non-null pip", pip!=null);
    }

    /** Test empty request (no subjects) */
    @Test
    public void testNoSubject() {
	log.info("test request without subject");
        Request request= createEmptyRequest();
	throwsPIPProcessingException(request, "No subject found in request");
    }
    
    /** Test empty subject */
    @Test
    public void testEmptySubject() throws Exception {
	log.info("test request with empty subject");
        Request request= createEmptyRequest();
	Subject subject = new Subject();
	request.getSubjects().add(subject);
	boolean result= pip.populateRequest(request);
	assertFalse("populateRequest should have failed", result);
    }

    /** Test with null target attribute */
    @Test
    public void testNullAttribute() throws Exception {
	log.info("test with null target attribute");
	pip.setAttributeName(null);
	Request request= createRequest(GoodDN);
	boolean result= pip.populateRequest(request);
	assertTrue("populateRequest should have succeeded", result);
    }

    /** Test with negative update interval */
    @Test
    public void testNegativeUpdateInterval() throws Exception {
	log.info("test with negative update interval");
	pip.setUpdateInterval(-1);
	Request request= createRequest(GoodDN);
	boolean result= pip.populateRequest(request);
	assertTrue("populateRequest should have succeeded", result);
    }

    /** Test with null issuer DN */
    @Test
    public void testNullIssuerDN() throws Exception {
	log.info("test request with null issuer DN");
	Request request= createRequest(null);
	boolean result= pip.populateRequest(request);
	assertFalse("populateRequest should have failed", result);
    }

    /** Test with non-existing issuer DN */
    @Test
    public void testBasic() throws Exception {
	log.info("test request with invalid subject");
	Request request= createRequest(BadDN);
	boolean result= pip.populateRequest(request);
	assertFalse("populateRequest should have failed", result);
    }
    
    /** Test with a valid issuer DN */
    @Test
    public void testGood() throws Exception {
	log.info("test request with valid subject");
	Request request= createRequest(GoodDN);
	boolean result= pip.populateRequest(request);
	assertTrue("populateRequest should have succeeded", result);
    }
}

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
// NIKHEF Amsterdam, the Netherlands
// <grid-mw-security@nikhef.nl>

package org.glite.authz.pep.pip.provider;

import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.pep.pip.provider.X509ExtractorPIP.AcceptedAttr;
import org.glite.authz.pep.pip.PIPProcessingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.Before;
import org.junit.After;

/**
 * JUnit framework tests for {@link X509ExtractorPIP}
 * @author Mischa Sall&eacute;
 */
public class X509ExtractorPIPTest {
    X509ExtractorPIP pip;

    private final Logger log = LoggerFactory.getLogger(X509ExtractorPIP.class);

    /** Invalid PEM string */
    private final String PEM_invalid =
	    "-----BEGIN CERTIFICATE-----\n" +
	    "AAP\n" +
	    "-----END CERTIFICATE-----";

    /** Valid certificate with OIDs */
    private final String PEM_OIDs =
	    "-----BEGIN CERTIFICATE-----\n" +
	    "MIIB6zCCAZWgAwIBAgIBADANBgkqhkiG9w0BAQsFADA/MQswCQYDVQQGEwJOTDEQ\n" +
	    "MA4GA1UECgwHRXhhbXBsZTEMMAoGA1UECwwDUERQMRAwDgYDVQQDDAdUZXN0IENB\n" +
	    "MB4XDTE2MDcxMjA5MzMzMloXDTE3MDcxMjA5MzMzMlowQDELMAkGA1UEBhMCTkwx\n" +
	    "EDAOBgNVBAoMB0V4YW1wbGUxDDAKBgNVBAsMA1BEUDERMA8GA1UEAwwISmFuZSBE\n" +
	    "b2UwXDANBgkqhkiG9w0BAQEFAANLADBIAkEA0nnFLj2A5AWo3aURcqYj8z0nKiNf\n" +
	    "JcC8IxvytCT5A+L1saDWoMI6t5zq56xpTx2pKbW3Zn1uXSmaCyOOYoyVDQIDAQAB\n" +
	    "o3sweTAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIEsDAZBgNVHSAEEjAQMA4G\n" +
	    "DCsGAQQB0UJjvTKHZzAfBgNVHSMEGDAWgBSXMNi1n/HbRpm2IiCr6qhxMgIrDjAd\n" +
	    "BgNVHQ4EFgQUkZ8musmlcRef7AGSM9YzIJwOC3UwDQYJKoZIhvcNAQELBQADQQCr\n" +
	    "PioKQGQ68c1HGmgOSFis3D4pn0ubIYdNzb0utwFoVq9e5Z2KMmEMbTejir7US6HI\n" +
	    "j4V59lg9OOa2k/4KVhgv\n" +
	    "-----END CERTIFICATE-----";

    /** Valid certificate without OIDs */
    private final String PEM_Basic = 
	    "-----BEGIN CERTIFICATE-----\n" +
	    "MIIB0DCCAXqgAwIBAgIBATANBgkqhkiG9w0BAQsFADA/MQswCQYDVQQGEwJOTDEQ\n" +
	    "MA4GA1UECgwHRXhhbXBsZTEMMAoGA1UECwwDUERQMRAwDgYDVQQDDAdUZXN0IENB\n" +
	    "MB4XDTE2MDcxMjA5MzMzMloXDTE3MDcxMjA5MzMzMlowQDELMAkGA1UEBhMCTkwx\n" +
	    "EDAOBgNVBAoMB0V4YW1wbGUxDDAKBgNVBAsMA1BEUDERMA8GA1UEAwwISm9obiBE\n" +
	    "b2UwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAr73mM0qnRotyC+DVuqJO5xMGMpl+\n" +
	    "5Qkgjoaj/9puWxMxQUQecb8BkIrSM3oXo2hHusdaepKwFPXeGhdCcfu7awIDAQAB\n" +
	    "o2AwXjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIEsDAfBgNVHSMEGDAWgBSX\n" +
	    "MNi1n/HbRpm2IiCr6qhxMgIrDjAdBgNVHQ4EFgQUzquZdCWA+TscTXGDpqyPMb9C\n" +
	    "Lx8wDQYJKoZIhvcNAQELBQADQQC19Z+ZdneP3Vde+iTZzmSGEpuBTmge3It9nRVu\n" +
	    "nyGD2FVgslvASc9bkInmN0krXv/5/R6mkmToBcCWZeWMOu0t\n" +
	    "-----END CERTIFICATE-----";

    /** Valid certificate with NULL issuer DN */
    private final String PEM_EmptyIssuer =
	    "-----BEGIN CERTIFICATE-----\n" +
	    "MIICbTCCAVWgAwIBAgIBADANBgkqhkiG9w0BAQsFADAAMB4XDTE2MDcxMjA5NTc1\n" +
	    "MVoXDTE3MDcxMjA5NTc1MVowPzELMAkGA1UEBhMCTkwxEDAOBgNVBAoMB0V4YW1w\n" +
	    "bGUxDDAKBgNVBAsMA1BEUDEQMA4GA1UEAwwHSmltIERvZTBcMA0GCSqGSIb3DQEB\n" +
	    "AQUAA0sAMEgCQQCipCxNgFypFBQ6a8CaZ2Q2QOKSzO6IrdwlUvHfW8JSH16GcQvF\n" +
	    "PFe6jq8W6AIXcsFitrrpUHdGmTZ/yVz++mmhAgMBAAGjezB5MAwGA1UdEwEB/wQC\n" +
	    "MAAwDgYDVR0PAQH/BAQDAgSwMBkGA1UdIAQSMBAwDgYMKwYBBAHRQmO9ModnMB8G\n" +
	    "A1UdIwQYMBaAFNPKOSg8pl7uYwu+hAuWhwwCl+37MB0GA1UdDgQWBBRYqLz8hfnZ\n" +
	    "Et625WBPeEG/1yzQFjANBgkqhkiG9w0BAQsFAAOCAQEAExOSIqXn1i5YgmUIu1RV\n" +
	    "lSazdky56KI0NmilGe9H6auaoKSTjroydc9br2B7l0Yqx9gJGmqFSS1Fvfn+wyJn\n" +
	    "EMo2o2Eq90H5VTRYJeCYzzUzv9YZ6+yshoed9T2gclGm9TYZ17exT0iCziu4v8CO\n" +
	    "GqKuFa83T5IULFUo5tX7Z2DmTdSenKRy3qT1OjK5/kc2dGDIczW7POCsAnay+z6o\n" +
	    "z3X6u7BAp0IZmrxZjGQVMOFZwNI0isHjYlO0a8zYps3N3ih70vquAxiOO3BKVvGQ\n" +
	    "IsBm9bHCHs/vVSHxbwY422zHCedGA9wbboUwH3AE3uFvUvj0Drqb5XoA4cGjNHAi\n" +
	    "xA==\n" +
	    "-----END CERTIFICATE-----";

    /** Valid certificate without OIDs, base64 DER instead of PEM */
    private final String Base64Der_Basic1 = 
	    "MIIBuTCCAWOgAwIBAgIENl1jpTANBgkqhkiG9w0BAQsFADBAMQswCQYDVQQGEwJO\n" +
	    "TDEQMA4GA1UECgwHRXhhbXBsZTEMMAoGA1UECwwDUERQMREwDwYDVQQDDAhKb2hu\n" +
	    "IERvZTAeFw0xNjA3MjIwOTM2MzJaFw0xNjA3MjMwOTM2MzJaMFQxCzAJBgNVBAYT\n" +
	    "Ak5MMRAwDgYDVQQKDAdFeGFtcGxlMQwwCgYDVQQLDANQRFAxETAPBgNVBAMMCEpv\n" +
	    "aG4gRG9lMRIwEAYDVQQDDAk5MTIwOTAwMjEwXDANBgkqhkiG9w0BAQEFAANLADBI\n" +
	    "AkEA1LhdT2Rz3dZXDyOaNacQUxnzfjXBJVG0kw8SvLiIhGNJiHCApy6Tq8+Nyn6Y\n" +
	    "kCU6lCInKbJma4LCUOa2M9bTfQIDAQABozEwLzAOBgNVHQ8BAf8EBAMCBaAwHQYI\n" +
	    "KwYBBQUHAQ4BAf8EDjAMMAoGCCsGAQUFBxUBMA0GCSqGSIb3DQEBCwUAA0EADWJX\n" +
	    "zRwHQK2+P4FY4GiKlUgCZybooNdmxLvLU/LgTPNIiq2wp4elNPddGeaSFF7WuwIB\n" +
	    "GoI96LVXYjBe4oAJYA==\n";
    
    private final String Base64Der_Basic2 = 
	    "MIIB0DCCAXqgAwIBAgIBATANBgkqhkiG9w0BAQsFADA/MQswCQYDVQQGEwJOTDEQ\n" +
	    "MA4GA1UECgwHRXhhbXBsZTEMMAoGA1UECwwDUERQMRAwDgYDVQQDDAdUZXN0IENB\n" +
	    "MB4XDTE2MDcyMjA5MzYzMloXDTE3MDcyMjA5MzYzMlowQDELMAkGA1UEBhMCTkwx\n" +
	    "EDAOBgNVBAoMB0V4YW1wbGUxDDAKBgNVBAsMA1BEUDERMA8GA1UEAwwISm9obiBE\n" +
	    "b2UwXDANBgkqhkiG9w0BAQEFAANLADBIAkEApgnp1Ft/K7PQ9Vn5itXKQtD3rQgr\n" +
	    "CcKinZBejCekCjddDol7o7wyg/l39fwy+BpGCAdvFaS8ifYCGkco+S/C/QIDAQAB\n" +
	    "o2AwXjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIEsDAfBgNVHSMEGDAWgBQJ\n" +
	    "vvNGlM5StPQo6n9IMC02ROLtOjAdBgNVHQ4EFgQUvM8URbacLmge1FRAPZX2OYrO\n" +
	    "kM0wDQYJKoZIhvcNAQELBQADQQBAjci71TX4K4G4AhA8Top2U99vqjxQ2RPX0/L7\n" +
	    "xwbuFtBgcWolsp4eH0ZYwp1sMpdc7l3kZBOdA6y4C49ljLe/\n";


    /**
     * Setup a new {@link X509ExtractorPIP} PIP and set the accepted attributes
     * to all of them
     */
    @Before
    public void initialize() throws Exception {
	log.debug("Creating PIP");
        pip = new X509ExtractorPIP("X509ExtractorPIP");
	pip.setAcceptedAttrIDs(
	    new AcceptedAttr[]{
		AcceptedAttr.ACCEPT_ATTR_X509_ISSUER,
		AcceptedAttr.ACCEPT_ATTR_CA_POLICY_OID
	    });
        pip.start();
    }

    /** Stop the {@link X509ExtractorPIP} PIP */
    @After
    public void finalize() throws Exception {
	log.debug("Stopping PIP");
        pip.stop();
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
		log.debug("EXPECTED: " + message);
		log.debug("GOT ("+message.indexOf(element)+"): " + element);
		assertTrue("PIPProcessingException message does not contain: " + element, message.indexOf(element) >= 0);
	    } catch (Exception e) {
		e.printStackTrace();
		fail("must throw only PIPProcessingException: " + e.getMessage());
	    }        
	    return applied;
    }

    /**
     * Creates a basic request containing a key-info subject attribute using the
     * PEM as input
     * @param pem input PEM string
     * @return Request
     */
    protected Request createRequest(String pem) {
        Request request= new Request();
	Subject subject= new Subject();
	Attribute attr = new Attribute("urn:oasis:names:tc:xacml:1.0:subject:key-info");
	attr.getValues().add(pem);
	subject.getAttributes().add(attr);
	request.getSubjects().add(subject);
        return request;
    }

    /**
     * Creates a basic request containing a key-info subject attribute using the
     * PEM as input
     * @param cert1,cert2 input strings
     * @return Request
     */
    protected Request createDerRequest(String cert1, String cert2) {
        Request request= new Request();
	Subject subject= new Subject();
	Attribute attr = new Attribute("urn:oasis:names:tc:xacml:1.0:subject:key-info");
	attr.getValues().add(cert1);
	attr.getValues().add(cert2);
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

    /** Test invalid PEM string */
    @Test
    public void testValidRequestInvalidPEM() throws Exception {
	log.info("test valid request with invalid PEM");
        Request request= createRequest(PEM_invalid);
	boolean result= pip.populateRequest(request);
	assertFalse("populateRequest should have failed", result);
    }
   
    /** Test valid PEM with null issuer DN */
    @Test
    public void testValidRequestEmptyIssuer() throws Exception {
	log.info("test valid request with OIDs");
        Request request= createRequest(PEM_EmptyIssuer);
	boolean result= pip.populateRequest(request);
	Attribute[] attr = request.getSubjects().toArray(new Subject[0])[0].getAttributes().toArray(new Attribute[0]);
	assertTrue("populateRequest should have succeeded", result);
	assertTrue("subject should have 3 attributes, found "+attr.length, attr.length==3);
    }

    /** Test valid PEM without OIDs */
    @Test
    public void testValidRequestBasic() throws Exception {
	log.info("test valid request with no OIDs");
        Request request= createRequest(PEM_Basic);
	boolean result= pip.populateRequest(request);
	Attribute[] attr = request.getSubjects().toArray(new Subject[0])[0].getAttributes().toArray(new Attribute[0]);
	assertTrue("populateRequest should have succeeded", result);
	assertTrue("subject should have 2 attributes, found "+attr.length, attr.length==2);
    }
    
    /** Test valid PEM with OIDs */
    @Test
    public void testValidRequestOIDs() throws Exception {
	log.info("test valid request with OIDs");
        Request request= createRequest(PEM_OIDs);
	boolean result= pip.populateRequest(request);
	Attribute[] attr = request.getSubjects().toArray(new Subject[0])[0].getAttributes().toArray(new Attribute[0]);
	assertTrue("populateRequest should have succeeded", result);
	assertTrue("subject should have 3 attributes, found "+attr.length, attr.length==3);
    }
    
    /** Test multiple valid Base64 DER (without OIDs) */
    @Test
    public void testValidRequestBasicDER() throws Exception {
	log.info("test valid request using Base64 DER input");
        Request request= createDerRequest(Base64Der_Basic1, Base64Der_Basic2);
	boolean result= pip.populateRequest(request);
	Attribute[] attr = request.getSubjects().toArray(new Subject[0])[0].getAttributes().toArray(new Attribute[0]);
	assertTrue("populateRequest should have succeeded", result);
	assertTrue("subject should have 2 attributes, found "+attr.length, attr.length==2);
    }
    
    /** Test multiple valid Base64 DER (without OIDs) */
    @Test
    public void testValidRequestBasicDERInverted() throws Exception {
	log.info("test valid request using Base64 DER input in inverted order");
        Request request= createDerRequest(Base64Der_Basic2, Base64Der_Basic1);
	boolean result= pip.populateRequest(request);
	Attribute[] attr = request.getSubjects().toArray(new Subject[0])[0].getAttributes().toArray(new Attribute[0]);
	assertTrue("populateRequest should have succeeded", result);
	assertTrue("subject should have 2 attributes, found "+attr.length, attr.length==2);
    }
}

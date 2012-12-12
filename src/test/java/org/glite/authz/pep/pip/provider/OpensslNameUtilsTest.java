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
package org.glite.authz.pep.pip.provider;

import junit.framework.TestCase;
import eu.emi.security.authn.x509.impl.OpensslNameUtils;

/**
 * Test caNl OpensslNameUtils conversion functionalities
 */
public class OpensslNameUtilsTest extends TestCase {

    static String opensslDN= "/C=ch/O=SWITCH/CN=Valery Tschopp";
    static String rfc2253DN= "CN=Valery Tschopp,O=SWITCH,C=ch";
    
    /** {@inheritDoc} */
    protected void setUp() throws Exception {
        super.setUp();
    }

    /** {@inheritDoc} */
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    @SuppressWarnings("deprecation")
    public void testRFC2253FromOpenSSL() {
        System.out.println(" input: " + opensslDN);
        String subjectDN= OpensslNameUtils.opensslToRfc2253(opensslDN);
        assertEquals(rfc2253DN, subjectDN);
        System.out.println("output: " + subjectDN);
    }
    
    public void testOpenSSLFromRFC2253() {
        System.out.println(" input: " + rfc2253DN);
        String subjectDN= OpensslNameUtils.convertFromRfc2253(rfc2253DN,false);
        assertEquals(opensslDN, subjectDN);
        System.out.println("output: " + subjectDN);
    }
    

//    
//    public void testX500Principal() {
//        X500Principal opensslX500Principal= new X500Principal(opensslDN);
//        System.out.println(opensslX500Principal.getName());
//    }
//    
//    public void testX509Name() {
//        X509Name opensslX509Name= new X509Name(opensslDN);
//        X509Name rfcX509Name= new X509Name(rfc2253DN);
//        System.out.println(opensslX509Name.toString());
//        System.out.println(rfcX509Name.toString());
//    }
    
}

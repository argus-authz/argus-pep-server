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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import javax.security.auth.x500.X500Principal;

import org.glite.authz.pep.obligation.dfpmap.X509MatchStrategy;
import org.junit.Test;

import eu.emi.security.authn.x509.impl.OpensslNameUtils;

/**
 * Test caNl OpensslNameUtils conversion functionalities
 */
public class OpensslNameUtilsTest {

    static String opensslDN= "/C=ch/O=SWITCH/CN=Valery Tschopp";
    static String rfc2253DN= "CN=Valery Tschopp,O=SWITCH,C=ch";
    
    static String slashedOpensslDN= "/DC=ch/DC=cern/OU=computers/CN=cmspilot02/vocms080.cern.ch";
    static String escapedSlashedOpensslDN= "/DC=ch/DC=cern/OU=computers/CN=cmspilot02\\/vocms080.cern.ch";
    static String slashedRfc2253DN = "CN=cmspilot02/vocms080.cern.ch,OU=computers,DC=cern,DC=ch";

    @Test
    @SuppressWarnings("deprecation")
    public void testRFC2253FromOpenSSL() {
        System.out.println(" input: " + opensslDN);
        String subjectDN= OpensslNameUtils.opensslToRfc2253(opensslDN);
        assertEquals(rfc2253DN, subjectDN);
        System.out.println("output: " + subjectDN);
    }

    @Test
    public void testOpenSSLFromRFC2253() {
        System.out.println(" input: " + rfc2253DN);
        String subjectDN= OpensslNameUtils.convertFromRfc2253(rfc2253DN,false);
        assertEquals(opensslDN, subjectDN);
        System.out.println("output: " + subjectDN);
    }

    @Test
    public void testSlashedOpensslDN() {
      System.out.println(" input: " + slashedOpensslDN);
      assertTrue((new X509MatchStrategy()).isMatch(slashedOpensslDN, new X500Principal(slashedRfc2253DN)));
      System.out.println("output: " + slashedRfc2253DN);
    }

    @Test
    public void testEscapedSlashedOpensslDN() {
      System.out.println(" input: " + escapedSlashedOpensslDN);
      assertTrue((new X509MatchStrategy()).isMatch(escapedSlashedOpensslDN, new X500Principal(slashedRfc2253DN)));
      System.out.println("output: " + slashedRfc2253DN);
    }
}

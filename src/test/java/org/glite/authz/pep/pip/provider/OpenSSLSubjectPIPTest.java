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

import org.glite.authz.common.model.Action;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Resource;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.profile.AuthorizationProfileConstants;
import org.glite.authz.pep.pip.PIPException;
import org.glite.authz.pep.pip.PolicyInformationPoint;

import junit.framework.TestCase;

/**
 *
 */
public class OpenSSLSubjectPIPTest extends TestCase {

    static String rid= "switch";

    static String aid= "switch";

    static String opensslDN= "/C=ch/O=SWITCH/CN=Valery Tschopp";

    static String opensslIssuingCA= "/C=ch/O=SWITCH/OU=Grid/CN=Grid Issuing CA";

    static String opensslRootCA= "/C=ch/O=SWITCH/OU=Grid/CN=Grid Root CA";

    static String rfc2253DN= "CN=Valery Tschopp,O=SWITCH,C=ch";
    
    static String rfc2253IssuingCA= "CN=Grid Issuing CA,OU=Grid,O=SWITCH,C=ch";
    
    static String rfc2253RootCA= "CN=Grid Root CA,OU=Grid,O=SWITCH,C=ch";

    PolicyInformationPoint pip_;

    /** {@inheritDoc} */
    protected void setUp() throws Exception {
        super.setUp();
        pip_= new OpenSSLSubjectPIP("OPENSSL_PIP");
        System.out.println("OpenSSL subject attribute IDs to convert: " + OpenSSLSubjectPIP.DEFAULT_OPENSSL_SUBJECT_ATTRIBUTE_IDS);
        System.out.println("OpenSSL subject attribute datatypes to convert: " + OpenSSLSubjectPIP.DEFAULT_OPENSSL_SUBJECT_ATTRIBUTE_DATATYPES);
        pip_.start();
    }

    /** {@inheritDoc} */
    protected void tearDown() throws Exception {
        super.tearDown();
        pip_.stop();
    }

    public void testOpenSSLSubjectPIP() throws PIPException {
        // Subject
        Subject openSSLSubject= new Subject();
        Attribute subjectId= new Attribute(AuthorizationProfileConstants.ID_ATTRIBUTE_SUBJECT_ID,
                                           AuthorizationProfileConstants.DATATYPE_STRING);
        subjectId.getValues().add(opensslDN);
        openSSLSubject.getAttributes().add(subjectId);
        Attribute subjectIssuer= new Attribute(AuthorizationProfileConstants.ID_ATTRIBUTE_SUBJECT_ISSUER,
                                               AuthorizationProfileConstants.DATATYPE_STRING);
        subjectIssuer.getValues().add(opensslIssuingCA);
        subjectIssuer.getValues().add(opensslRootCA);
        openSSLSubject.getAttributes().add(subjectIssuer);
        // Resource
        Resource resource= new Resource();
        Attribute resourceId= new Attribute(AuthorizationProfileConstants.ID_ATTRIBUTE_RESOURCE_ID);
        resourceId.getValues().add(rid);
        resource.getAttributes().add(resourceId);
        // Action
        Action action= new Action();
        Attribute actionId= new Attribute(AuthorizationProfileConstants.ID_ATTRIBUTE_ACTION_ID);
        actionId.getValues().add(aid);
        action.getAttributes().add(actionId);
        // Request
        Request request= new Request();
        request.getSubjects().add(openSSLSubject);
        request.getResources().add(resource);
        request.setAction(action);

        System.out.println("before: " + request);

        boolean applied= pip_.populateRequest(request);
        assertTrue(applied);

        System.out.println("after: " + request);

        // check for converted DN in the request
        for (Subject subject : request.getSubjects()) {
            for (Attribute attribute : subject.getAttributes()) {
                if (AuthorizationProfileConstants.DATATYPE_X500_NAME.equals(attribute.getDataType())) {
                    if (AuthorizationProfileConstants.ID_ATTRIBUTE_SUBJECT_ID.equals(attribute.getId())) {
                        assertTrue("OpenSSL DN to RFC2253 convertion failed: " + attribute,attribute.getValues().contains(rfc2253DN));
                    }
                    else if (AuthorizationProfileConstants.ID_ATTRIBUTE_SUBJECT_ISSUER.equals(attribute.getId())) {
                        assertTrue("OpenSSL DN to RFC2253 convertion failed: " + attribute, attribute.getValues().contains(rfc2253RootCA) && attribute.getValues().contains(rfc2253IssuingCA));
                    }
                }
            }
        }
    }
}

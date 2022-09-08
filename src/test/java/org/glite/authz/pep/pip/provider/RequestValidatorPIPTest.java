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

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.glite.authz.common.model.Action;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Resource;
import org.glite.authz.common.model.Subject;
import org.glite.authz.pep.pip.PIPProcessingException;
import org.glite.authz.pep.pip.PolicyInformationPoint;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 *
 */
public class RequestValidatorPIPTest {

    PolicyInformationPoint pip;

    @Before
    public void setUp() throws Exception {
        pip = new RequestValidatorPIP("VALIDATOR_PIP");
        pip.start();
    }

    @After
    public void tearDown() throws Exception {
        pip.stop();
    }

    protected boolean throwsPIPProcessingException(Request request, String element) {
        boolean applied= false;
        try {
            System.out.println(request);
            applied= pip.populateRequest(request);
            fail("must throw PIPProcessingException");
        } catch (PIPProcessingException e) {
            // expected
            String message= e.getMessage();
            System.out.println("EXPECTED: " + message);
            assertTrue("PIPProcessingException message does not contain: " + element, message.indexOf(element) > 0);
        } catch (Exception e) {
            e.printStackTrace();
            fail("must throw only PIPProcessingException: " + e.getMessage());
        }        
        return applied;
    }

    protected Request createValidRequest() {
        Request request= new Request();
        Subject subject= new Subject();
        Attribute subAttribute= new Attribute("x-urn:junit:subject-id");
        subAttribute.getValues().add("hello");
        subject.getAttributes().add(subAttribute);
        subAttribute= new Attribute("x-urn:junit:subject-issuer");
        subAttribute.getValues().add("hello-issuer");
        subAttribute.getValues().add("hello-ca");
        request.getSubjects().add(subject);
        Resource resource= new Resource();
        Attribute resAttribute= new Attribute("x-urn:junit:resource-id");
        resAttribute.getValues().add("titi");
        resource.getAttributes().add(resAttribute);
        request.getResources().add(resource);
        Action action= new Action();
        Attribute actAttribute= new Attribute("x-urn:junit:action-id");
        actAttribute.getValues().add("toto");
        action.getAttributes().add(actAttribute);
        request.setAction(action);        
        return request;
    }

    @Test
    public void testValidRequest() throws Exception {
        Request request= createValidRequest();
        pip.populateRequest(request);
    }

    @Test
    public void testNoSubject() {
        Request request= createValidRequest();
        request.getSubjects().clear();
        throwsPIPProcessingException(request, "any Subject");
    }

    @Test
    public void testNoResource() {
        Request request= createValidRequest();
        request.getResources().clear();
        throwsPIPProcessingException(request, "any Resource");
    }

    @Test
    public void testNoAction() {
        Request request= createValidRequest();
        request.setAction(null);
        throwsPIPProcessingException(request, "an Action");

    }

    @Test
    public void testNoActionAttribute() {
        Request request= createValidRequest();
        request.getAction().getAttributes().clear();
        throwsPIPProcessingException(request, "Action without any attribute");
    }

    @Test
    public void testNoSubjectAttribute() {
        Request request= createValidRequest();
        for (Subject subject : request.getSubjects() ) {
            subject.getAttributes().clear();
            break;
        }
        throwsPIPProcessingException(request, "Subject without any attribute");
    }

    @Test
    public void testNoResourceAttribute() {
        Request request= createValidRequest();
        for (Resource resource : request.getResources() ) {
            resource.getAttributes().clear();
            break;
        }
        throwsPIPProcessingException(request, "Resource without any attribute");
    }

    @Test
    public void testNullActionAttribute() {
        Request request= createValidRequest();
        for (Attribute attribute: request.getAction().getAttributes()) {
            attribute.getValues().add(null);
            break;
        }
        throwsPIPProcessingException(request, "with a null value");
    }

    @Test
    public void testNullSubjectAttribute() {
        Request request= createValidRequest();
        for (Subject subject : request.getSubjects() ) {
            for (Attribute attribute: subject.getAttributes()) {
                attribute.getValues().add(null);
                break;
            }
            break;
        }
        throwsPIPProcessingException(request, "with a null value");
    }

    @Test
    public void testNullResourceAttribute() {
        Request request= createValidRequest();
        for (Resource resource : request.getResources() ) {
            for (Attribute attribute: resource.getAttributes()) {
                attribute.getValues().add(null);
                break;
            }
            break;
        }
        throwsPIPProcessingException(request, "with a null value");
    }

    @Test
    public void testEmptyActionAttribute() {
        Request request= createValidRequest();
        for (Attribute attribute: request.getAction().getAttributes()) {
            attribute.getValues().add("    ");
            break;
        }
        throwsPIPProcessingException(request, "with an empty (stripped) value");
    }

    @Test
    public void testEmptySubjectAttribute() {
        Request request= createValidRequest();
        for (Subject subject : request.getSubjects() ) {
            for (Attribute attribute: subject.getAttributes()) {
                attribute.getValues().add("");
                break;
            }
            break;
        }
        throwsPIPProcessingException(request, "with an empty (stripped) value");
    }

    @Test
    public void testEmptyResourceAttribute() {
        Request request= createValidRequest();
        for (Resource resource : request.getResources() ) {
            for (Attribute attribute: resource.getAttributes()) {
                attribute.getValues().add(" \t");
                break;
            }
            break;
        }
        throwsPIPProcessingException(request, "with an empty (stripped) value");
    }
}

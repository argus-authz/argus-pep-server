/*
 * Copyright (c) Members of the EGEE Collaboration. 2011.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * $Id$
 */
package org.glite.authz.pep.pip.provider;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import junit.framework.TestCase;

import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.profile.AuthorizationProfileConstants;

/**
 * AuthorizationProfilePIPTest
 * 
 * @author Valery Tschopp &lt;valery.tschopp&#64;switch.ch&gt;
 */
public class AbstractX509PIPTest extends TestCase {

    Subject subject;

    String voName= "JUNIT_VO_NAME";

    String wrongDN= "C=org,O=ACME,CN=John Doe";

    String correctDN= "CN=John Doe,O=ACME,C=org";

    List<String> wrongIssuers= Arrays.asList("C=org,O=ACME,OU=Issuing CA,CN=ACME Issuing CA",
                                             "C=org,O=ACME,OU=Root CA,CN=ACME CA");

    List<String> correctIssuers= Arrays.asList("CN=ACME Issuing CA,OU=Issuing CA,O=ACME,C=org",
                                               "CN=ACME CA,OU=Root CA,O=ACME,C=org");

    /*
     * (non-Javadoc)
     * 
     * @see junit.framework.TestCase#setUp()
     */
    protected void setUp() throws Exception {
        super.setUp();
        subject= new Subject();
        Attribute subjectId= new Attribute(Attribute.ID_SUB_ID,
                                           Attribute.DT_X500_NAME);
        subjectId.getValues().add(wrongDN);
        subject.getAttributes().add(subjectId);
        Attribute subjectIssuer= new Attribute(AuthorizationProfileConstants.ID_ATTRIBUTE_SUBJECT_ISSUER,
                                               Attribute.DT_X500_NAME);
        subjectIssuer.getValues().addAll(wrongIssuers);
        subject.getAttributes().add(subjectIssuer);
    }

    /*
     * (non-Javadoc)
     * 
     * @see junit.framework.TestCase#tearDown()
     */
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    public void testUpdateSubjectCertificateAttributes() {
        Collection<Attribute> certAttributes= processCertChain();
        System.out.println("Incoming Subject: " + subject);
        updateSubjectCertificateAttributes(subject, certAttributes);
        for (Attribute attribute : subject.getAttributes()) {
            if (attribute.getId().equals(Attribute.ID_SUB_ID)) {
                for (Object object : attribute.getValues()) {
                    String value= (String) object;
                    assertEquals(correctDN, value);
                }
            }
            else if (attribute.getId().equals(AuthorizationProfileConstants.ID_ATTRIBUTE_SUBJECT_ISSUER)) {
                for (Object object : attribute.getValues()) {
                    assertTrue(correctIssuers.contains(object));
                }

            }
            else if (attribute.getId().equals(AuthorizationProfileConstants.ID_ATTRIBUTE_VIRTUAL_ORGANIZATION)) {
                for (Object object : attribute.getValues()) {
                    assertEquals(voName, object.toString());
                }
            }

        }
        System.out.println("Updated Subject: " + subject);
    }

    private Collection<Attribute> processCertChain() {
        List<Attribute> certAttributes= new ArrayList<Attribute>();
        Attribute subjectId= new Attribute(Attribute.ID_SUB_ID,
                                           Attribute.DT_X500_NAME);
        subjectId.getValues().add(correctDN);
        certAttributes.add(subjectId);
        Attribute subjectIssuer= new Attribute(AuthorizationProfileConstants.ID_ATTRIBUTE_SUBJECT_ISSUER,
                                               Attribute.DT_X500_NAME);
        subjectIssuer.getValues().addAll(correctIssuers);
        certAttributes.add(subjectIssuer);
        Attribute vo= new Attribute(AuthorizationProfileConstants.ID_ATTRIBUTE_VIRTUAL_ORGANIZATION,
                                    Attribute.DT_STRING);
        vo.getValues().add(voName);
        certAttributes.add(vo);
        return certAttributes;
    }

    private void updateSubjectCertificateAttributes(Subject subject,
            Collection<Attribute> certAttributes) {
        for (Attribute certAttribute : certAttributes) {
            boolean alreadyExists= false;
            String certAttributeId= certAttribute.getId();
            String certAttributeDataType= certAttribute.getDataType();
            for (Attribute subjectAttribute : subject.getAttributes()) {
                if (subjectAttribute.getId().equals(certAttributeId)
                        && subjectAttribute.getDataType().equals(certAttributeDataType)) {
                    alreadyExists= true;
                    System.out.println("WARN: Subject " + subjectAttribute
                            + " already contains values, replace them with "
                            + certAttribute);
                    subjectAttribute.getValues().clear();
                    subjectAttribute.getValues().addAll(certAttribute.getValues());
                }
            }
            if (!alreadyExists) {
                System.out.println("DEBUG: Add " + certAttribute
                        + " to Subject");
                subject.getAttributes().add(certAttribute);
            }
        }
    }
}

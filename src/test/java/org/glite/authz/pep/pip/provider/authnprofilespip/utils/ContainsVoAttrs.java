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

package org.glite.authz.pep.pip.provider.authnprofilespip.utils;

import java.util.Set;

import org.glite.authz.common.model.Attribute;
import org.glite.authz.pep.pip.provider.authnprofilespip.AuthenticationProfilePIPConstants;
import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;

public class ContainsVoAttrs extends TypeSafeMatcher<Set<Attribute>> 
implements AuthenticationProfilePIPConstants{
  
   
  @Override
  public void describeTo(Description description) {
    description.appendText("contains VO attributes, i.e. with id in "+VO_ATTRS_IDS);
  }

  @Override
  protected boolean matchesSafely(Set<Attribute> elements) {
    return elements.stream().anyMatch(a->VO_ATTRS_IDS.contains(a.getId()));
  }

}

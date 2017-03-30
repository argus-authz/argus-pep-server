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

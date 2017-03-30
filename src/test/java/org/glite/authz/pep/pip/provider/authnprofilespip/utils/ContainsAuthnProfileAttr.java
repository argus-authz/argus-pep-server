package org.glite.authz.pep.pip.provider.authnprofilespip.utils;

import java.util.Set;

import org.glite.authz.common.model.Attribute;
import org.glite.authz.pep.pip.provider.authnprofilespip.AuthenticationProfilePIPConstants;
import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;

public class ContainsAuthnProfileAttr extends TypeSafeMatcher<Set<Attribute>>
    implements AuthenticationProfilePIPConstants {

  private final String profileValue;

  public ContainsAuthnProfileAttr(String value) {
    profileValue = value;
  }

  public ContainsAuthnProfileAttr() {
    profileValue = null;
  }

  private boolean attributeMatches(Attribute a) {
    if (a.getId().equals(X509_AUTHN_PROFILE.getId())) {
      if (profileValue != null) {
        String value = (String) a.getValues().iterator().next();
        return profileValue.equals(value);
      }
      return true;
    }
    return false;
  }

  @Override
  public void describeTo(Description description) {
    String msg =
        String.format("a set of attributes containing an authentication profile attribute");

    description.appendText(msg);

    if (profileValue != null) {
      description.appendText(" with value: " + profileValue);
    }
  }

  @Override
  protected boolean matchesSafely(Set<Attribute> elements) {
    return elements.stream().anyMatch(this::attributeMatches);
  }

}

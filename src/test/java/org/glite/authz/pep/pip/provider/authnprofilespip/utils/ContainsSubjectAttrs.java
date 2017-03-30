package org.glite.authz.pep.pip.provider.authnprofilespip.utils;

import java.util.Set;

import org.glite.authz.common.model.Attribute;
import org.glite.authz.pep.pip.provider.authnprofilespip.AuthenticationProfilePIPConstants;
import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;

public class ContainsSubjectAttrs extends TypeSafeMatcher<Set<Attribute>>
    implements AuthenticationProfilePIPConstants {

  @Override
  public void describeTo(Description description) {
    description
      .appendText("a set of attributes with at least one X.509 subject attribute, i.e. with id "
          + "in " + X509_SUBJECT_ATTRS_IDS);
  }

  @Override
  protected boolean matchesSafely(Set<Attribute> attributes) {

    return attributes.stream().anyMatch(a -> X509_SUBJECT_ATTRS_IDS.contains(a.getId()));

  }
}

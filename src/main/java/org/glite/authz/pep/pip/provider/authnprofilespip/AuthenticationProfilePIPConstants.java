package org.glite.authz.pep.pip.provider.authnprofilespip;

import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.DATATYPE_STRING;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.DATATYPE_X500_NAME;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_GROUP;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_PRIMARY_GROUP;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_PRIMARY_ROLE;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_ROLE;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_SUBJECT_ID;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_SUBJECT_ISSUER;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_VIRTUAL_ORGANIZATION;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_X509_SUBJECT_ISSUER;
import static org.glite.authz.common.profile.GLiteAuthorizationProfileConstants.DATATYPE_FQAN;
import static org.glite.authz.common.profile.GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_FQAN;
import static org.glite.authz.common.profile.GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_PRIMARY_FQAN;
import static org.glite.authz.pep.pip.provider.authnprofilespip.AuthenticationProfileUtils.newHashSet;

import java.util.Set;

import org.glite.authz.common.model.Attribute;

public interface AuthenticationProfilePIPConstants {
  Attribute X509_ISSUER = new Attribute(ID_ATTRIBUTE_X509_SUBJECT_ISSUER, DATATYPE_X500_NAME);

  Attribute X509_SUBJECT = new Attribute(ID_ATTRIBUTE_SUBJECT_ID, DATATYPE_X500_NAME);

  Attribute SUBJECT_ISSUER = new Attribute(ID_ATTRIBUTE_SUBJECT_ISSUER, DATATYPE_X500_NAME);

  Attribute VIRTUAL_ORGANIZATION =
      new Attribute(ID_ATTRIBUTE_VIRTUAL_ORGANIZATION, DATATYPE_STRING);

  Attribute VO_GROUP = new Attribute(ID_ATTRIBUTE_GROUP, DATATYPE_STRING);

  Attribute VO_PRIMARY_GROUP = new Attribute(ID_ATTRIBUTE_PRIMARY_GROUP, DATATYPE_STRING);

  Attribute VO_ROLE = new Attribute(ID_ATTRIBUTE_ROLE, DATATYPE_STRING);

  Attribute VO_PRIMARY_ROLE = new Attribute(ID_ATTRIBUTE_PRIMARY_ROLE, DATATYPE_STRING);

  Attribute VO_FQAN = new Attribute(ID_ATTRIBUTE_FQAN, DATATYPE_FQAN);

  Attribute VO_PFQAN = new Attribute(ID_ATTRIBUTE_PRIMARY_FQAN, DATATYPE_FQAN);

  static final Set<String> VO_ATTRS_IDS =
      newHashSet(VIRTUAL_ORGANIZATION.getId(), VO_GROUP.getId(), VO_PRIMARY_GROUP.getId(),
          VO_ROLE.getId(), VO_PRIMARY_ROLE.getId(), VO_FQAN.getId(), VO_PFQAN.getId());

  static final Set<String> X509_SUBJECT_ATTRS_IDS =
      newHashSet(X509_SUBJECT.getId(), X509_ISSUER.getId(), SUBJECT_ISSUER.getId());
}

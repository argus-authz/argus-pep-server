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
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_X509_AUTHN_PROFILE;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_X509_SUBJECT_ISSUER;
import static org.glite.authz.common.profile.GLiteAuthorizationProfileConstants.DATATYPE_FQAN;
import static org.glite.authz.common.profile.GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_FQAN;
import static org.glite.authz.common.profile.GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_PRIMARY_FQAN;
import static org.glite.authz.pep.pip.provider.authnprofilespip.AuthenticationProfileUtils.newHashSet;

import java.util.Set;

import org.glite.authz.common.model.Attribute;

/**
 * Useful constants for {@link AuthenticationProfilePIP}.
 *
 */
public interface AuthenticationProfilePIPConstants {
  
  /** The attribute used to resolve the EEC issuer subject **/
  Attribute X509_ISSUER = new Attribute(ID_ATTRIBUTE_X509_SUBJECT_ISSUER, DATATYPE_X500_NAME);

  /** The attribute used to resolve the EEC subject **/
  Attribute X509_SUBJECT = new Attribute(ID_ATTRIBUTE_SUBJECT_ID, DATATYPE_X500_NAME);

  /** The attribute used to hold the X.509 authentication profile **/
  Attribute X509_AUTHN_PROFILE = new Attribute(ID_ATTRIBUTE_X509_AUTHN_PROFILE, DATATYPE_STRING);

  /** The attribute used to hold the subjects of all the issuers in the certificate chain **/
  Attribute SUBJECT_ISSUER = new Attribute(ID_ATTRIBUTE_SUBJECT_ISSUER, DATATYPE_X500_NAME);

  /** The attribute used to hold the virtual organization **/
  Attribute VIRTUAL_ORGANIZATION =
      new Attribute(ID_ATTRIBUTE_VIRTUAL_ORGANIZATION, DATATYPE_STRING);

  /** The attribute used to hold VO group information **/
  Attribute VO_GROUP = new Attribute(ID_ATTRIBUTE_GROUP, DATATYPE_STRING);

  /** The attribute used to hold VO primary group information **/
  Attribute VO_PRIMARY_GROUP = new Attribute(ID_ATTRIBUTE_PRIMARY_GROUP, DATATYPE_STRING);

  /** The attribute used to hold VO role information **/
  Attribute VO_ROLE = new Attribute(ID_ATTRIBUTE_ROLE, DATATYPE_STRING);

  /** The attribute used to hold VO primary role information **/
  Attribute VO_PRIMARY_ROLE = new Attribute(ID_ATTRIBUTE_PRIMARY_ROLE, DATATYPE_STRING);

  /** The attribute used to hold FQAN information **/
  Attribute VO_FQAN = new Attribute(ID_ATTRIBUTE_FQAN, DATATYPE_FQAN);
  
  /** The attribute used to hold primary FQAN information **/
  Attribute VO_PFQAN = new Attribute(ID_ATTRIBUTE_PRIMARY_FQAN, DATATYPE_FQAN);

  /** The set of known attribute ids for VO related attributes **/
  static final Set<String> VO_ATTRS_IDS =
      newHashSet(VIRTUAL_ORGANIZATION.getId(), VO_GROUP.getId(), VO_PRIMARY_GROUP.getId(),
          VO_ROLE.getId(), VO_PRIMARY_ROLE.getId(), VO_FQAN.getId(), VO_PFQAN.getId());

  /** The set of known attribute ids for X.509 certificate related attributes **/
  static final Set<String> X509_SUBJECT_ATTRS_IDS = newHashSet(X509_SUBJECT.getId(),
      X509_ISSUER.getId(), SUBJECT_ISSUER.getId(), X509_AUTHN_PROFILE.getId());

}

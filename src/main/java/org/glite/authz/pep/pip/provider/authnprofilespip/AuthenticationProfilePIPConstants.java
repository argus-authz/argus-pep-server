/*
 * Copyright (c) Members of the EGEE Collaboration. 2006-2010. See http://www.eu-egee.org/partners/
 * for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package org.glite.authz.pep.pip.provider.authnprofilespip;

import static java.util.stream.Collectors.toSet;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.DATATYPE_STRING;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.DATATYPE_X500_NAME;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_GROUP;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_PRIMARY_GROUP;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_PRIMARY_ROLE;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_ROLE;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_SUBJECT_ID;
import static org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_SUBJECT_ISSUER;
import static org.glite.authz.common.profile.GLiteAuthorizationProfileConstants.DATATYPE_FQAN;
import static org.glite.authz.common.profile.GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_FQAN;
import static org.glite.authz.common.profile.GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_PRIMARY_FQAN;

import java.util.Set;

import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.profile.CommonXACMLAuthorizationProfileConstants;
import org.glite.authz.common.profile.GLiteAuthorizationProfileConstants;

import com.google.common.collect.Sets;

/**
 * Useful constants for {@link AuthenticationProfilePIP}.
 *
 */
public interface AuthenticationProfilePIPConstants {

  /** The attribute used to resolve the EEC issuer subject (common XACML profile) **/
  Attribute DCI_SEC_X509_ISSUER =
      new Attribute(CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_X509_SUBJECT_ISSUER,
          DATATYPE_X500_NAME);

  /** The attribute used to resolve the EEC issuer subject (gLite profile) **/
  Attribute GLITE_X509_ISSUER = new Attribute(
      GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_X509_SUBJECT_ISSUER, DATATYPE_X500_NAME);

  /** The attribute used to resolve the EEC subject **/
  Attribute X509_SUBJECT = new Attribute(ID_ATTRIBUTE_SUBJECT_ID, DATATYPE_X500_NAME);

  /** The attribute used to hold the X.509 authentication profile (common XACML profile) **/
  Attribute DCI_SEC_X509_AUTHN_PROFILE =
      new Attribute(CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_X509_AUTHN_PROFILE, 
          DATATYPE_STRING);

  /** The attribute used to hold the X.509 authentication profile (gLite XACML profile) **/
  Attribute GLITE_X509_AUTHN_PROFILE = 
      new Attribute(GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_X509_AUTHN_PROFILE, 
          DATATYPE_STRING);
  
  /** The attribute used to hold the subjects of all the issuers in the certificate chain (common XACML profile) **/
  Attribute DCI_SEC_SUBJECT_ISSUER = new Attribute(ID_ATTRIBUTE_SUBJECT_ISSUER, DATATYPE_X500_NAME);

  /** The attribute used to hold the subjects of all the issuers in the certificate chain (gLite XACML profile) **/
  Attribute GLITE_SUBJECT_ISSUER = new Attribute(GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_SUBJECT_ISSUER,
      DATATYPE_X500_NAME);
  
  /** The attribute used to hold the virtual organization  (common XACML profile) **/
  Attribute DCI_SEC_VIRTUAL_ORGANIZATION = new Attribute(
      CommonXACMLAuthorizationProfileConstants.ID_ATTRIBUTE_VIRTUAL_ORGANIZATION, DATATYPE_STRING);

  /** The attribute used to hold the virtual organization  (glite XACML profile) **/
  Attribute GLITE_VIRTUAL_ORGANIZATION = new Attribute(
      GLiteAuthorizationProfileConstants.ID_ATTRIBUTE_VIRTUAL_ORGANIZATION, DATATYPE_STRING);

  /** The attribute used to hold VO group information **/
  Attribute DCI_SEC_VO_GROUP = new Attribute(ID_ATTRIBUTE_GROUP, DATATYPE_STRING);

  /** The attribute used to hold VO primary group information **/
  Attribute DCI_SEC_VO_PRIMARY_GROUP = new Attribute(ID_ATTRIBUTE_PRIMARY_GROUP, DATATYPE_STRING);

  /** The attribute used to hold VO role information **/
  Attribute DCI_SEC_VO_ROLE = new Attribute(ID_ATTRIBUTE_ROLE, DATATYPE_STRING);

  /** The attribute used to hold VO primary role information **/
  Attribute DCI_SEC_VO_PRIMARY_ROLE = new Attribute(ID_ATTRIBUTE_PRIMARY_ROLE, DATATYPE_STRING);

  /** The attribute used to hold FQAN information **/
  Attribute GLITE_VO_FQAN = new Attribute(ID_ATTRIBUTE_FQAN, DATATYPE_FQAN);

  /** The attribute used to hold primary FQAN information **/
  Attribute GLITE_VO_PFQAN = new Attribute(ID_ATTRIBUTE_PRIMARY_FQAN, DATATYPE_FQAN);

  /** The set of known attribute ids for VO related attributes **/
  static final Set<String> VO_ATTRS_IDS = Sets.newHashSet(DCI_SEC_VIRTUAL_ORGANIZATION.getId(),
      DCI_SEC_VO_GROUP.getId(), DCI_SEC_VO_PRIMARY_GROUP.getId(), DCI_SEC_VO_ROLE.getId(),
      DCI_SEC_VO_PRIMARY_ROLE.getId(), GLITE_VO_FQAN.getId(), GLITE_VO_PFQAN.getId());

  /** The set of known attribute ids for X.509 certificate related attributes **/
  static final Set<String> X509_SUBJECT_ATTRS_IDS =
      Sets.newHashSet(X509_SUBJECT.getId(), DCI_SEC_X509_ISSUER.getId(),
          DCI_SEC_SUBJECT_ISSUER.getId(), DCI_SEC_X509_AUTHN_PROFILE.getId(),
          GLITE_X509_ISSUER.getId(), GLITE_X509_AUTHN_PROFILE.getId());

  /** The attributes used to resolve VO name in the request **/
  static final Set<Attribute> VO_NAME_ATTRS =
      Sets.newHashSet(DCI_SEC_VIRTUAL_ORGANIZATION,  GLITE_VIRTUAL_ORGANIZATION);
  
  /** The attributes ids used to resolve VO name in the request **/
  static final Set<String> VO_NAME_ATTRS_ID =
      VO_NAME_ATTRS.stream().map(a -> a.getId()).collect(toSet());
  
  /** The attributes used to resolve the X.509 certificate issuer **/
  static final Set<Attribute> X509_ISSUER_ATTRS = 
      Sets.newHashSet(DCI_SEC_X509_ISSUER, GLITE_X509_ISSUER);
  
  /** The attribute ids used to resolve X.509 certificate issuer **/ 
  static final Set<String> X509_ISSUER_ATTRS_IDS =
      X509_ISSUER_ATTRS.stream().map(a -> a.getId()).collect(toSet());
  
  /** The attribute ids for X.509 authn profile attributes **/
  static final Set<String> X509_AUTHN_PROFILE_ATTRS_IDS = 
      Sets.newHashSet(DCI_SEC_X509_AUTHN_PROFILE.getId(), GLITE_X509_AUTHN_PROFILE.getId());
}

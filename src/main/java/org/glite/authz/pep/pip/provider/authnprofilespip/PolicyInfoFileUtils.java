package org.glite.authz.pep.pip.provider.authnprofilespip;

import static eu.emi.security.authn.x509.impl.OpensslNameUtils.opensslToRfc2253;

import java.util.HashSet;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

public class PolicyInfoFileUtils {

  @SuppressWarnings("deprecation")
  public static Set<X500Principal> convertCASubjects(String subjectDN) {

    Set<X500Principal> caSet = new HashSet<>();

    for (String dn : subjectDN.split("\\s*,\\s*")) {
      String key = cleanPropertyValue(dn);
      String canonicalDn = opensslToRfc2253(key);
      X500Principal issuer = new X500Principal(canonicalDn);
      caSet.add(issuer);
    }
    return caSet;
  }

  public static String cleanPropertyValue(String value) {

    return value.replace("\\", "")
      .replace("\"", "")
      .trim();
  }

}
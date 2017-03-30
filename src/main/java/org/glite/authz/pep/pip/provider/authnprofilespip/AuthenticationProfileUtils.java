package org.glite.authz.pep.pip.provider.authnprofilespip;

import static eu.emi.security.authn.x509.impl.OpensslNameUtils.opensslToRfc2253;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

/**
 * Utility methods for authentication profiles
 */
public class AuthenticationProfileUtils {
  
  public static <T> Set<T> newHashSet(T... elements){
    return new HashSet<>(Arrays.asList(elements));
  }


  public static X500Principal opensslDnToX500Principal(String dn) {
    @SuppressWarnings("deprecation")
    String canonicalDn = opensslToRfc2253(dn);
    return new X500Principal(canonicalDn);
  }


  public static Set<X500Principal> convertCASubjects(String subjectDnLine) {

    Set<X500Principal> caSet = new HashSet<>();

    for (String dn : subjectDnLine.split("\\s*,\\s*")) {
      String cleanedDn = cleanPropertyValue(dn);
      caSet.add(opensslDnToX500Principal(cleanedDn));
    }
    return caSet;
  }

  public static String cleanPropertyValue(String value) {

    return value.replace("\\", "").replace("\"", "").trim();
  }

}

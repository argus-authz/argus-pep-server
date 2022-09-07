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

package org.glite.authz.pep.pip.provider.authnprofilespip;

import static eu.emi.security.authn.x509.impl.OpensslNameUtils.opensslToRfc2253;

import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import com.google.common.collect.Sets;
import com.opencsv.CSVParser;
import com.opencsv.CSVParserBuilder;
import com.opencsv.CSVReader;
import com.opencsv.CSVReaderBuilder;
import com.opencsv.exceptions.CsvException;

/**
 * Utility methods for authentication profiles
 */
public class AuthenticationProfileUtils {

  @SuppressWarnings("deprecation")
  public static Set<String> convertCASubjects(String subjectDnLine) {

    Set<String> caSet = Sets.newHashSet();

    if (subjectDnLine == null || subjectDnLine.isEmpty()) {
      return caSet;
    }

    CSVParser parser = new CSVParserBuilder().withSeparator(',').build();

    CSVReader reader =
        new CSVReaderBuilder(new StringReader(subjectDnLine)).withCSVParser(parser).build();

    List<String[]> lines = new ArrayList<>();
    try {
      lines = reader.readAll();
    } catch (IOException | CsvException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } finally {
      try {
        reader.close();
      } catch (IOException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
      }
    }

    for (String dn : lines.get(0)) {

      caSet.add(opensslToRfc2253(cleanPropertyValue(dn)));
    }
    return caSet;
  }

  public static String cleanPropertyValue(String value) {

    return value.replace("\\", "").replace("\"", "").trim();
  }

}

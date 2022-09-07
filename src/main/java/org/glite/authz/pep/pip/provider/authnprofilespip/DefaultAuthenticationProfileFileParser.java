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

import static java.lang.String.format;
import static org.glite.authz.pep.pip.provider.authnprofilespip.AuthenticationProfileUtils.convertCASubjects;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;
import java.util.Set;

import org.glite.authz.pep.pip.provider.authnprofilespip.error.ParseError;

public class DefaultAuthenticationProfileFileParser implements AuthenticationProfileFileParser {

  public AuthenticationProfile parse(String policyFileName) {

    inputFileSanityChecks(policyFileName);

    Properties infoFile = new Properties();

    try {
      infoFile.load(new FileInputStream(policyFileName));
    } catch (IOException e) {
      throw new ParseError("Error reading policy file: " + e.getMessage(), e);
    }

    String alias = infoFile.getProperty("alias");

    if (alias == null || alias.isEmpty()) {
      throw new ParseError("Missing value for 'alias' property");
    }

    String subjectdn = infoFile.getProperty("subjectdn");

    Set<String> caSubjects = convertCASubjects(subjectdn);

    return new AuthenticationProfileImpl(alias, caSubjects);
  }

  private void inputFileSanityChecks(String inputFileName) {

    if (inputFileName == null || inputFileName.isEmpty()) {
      throw new IllegalArgumentException("null value for input file");
    }
    File input = new File(inputFileName);
    if (!input.exists()) {
      throw new IllegalArgumentException(
        format("File %s does not exist", inputFileName));
    }
    if (!input.isFile()) {
      throw new IllegalArgumentException(
        format("File %s is not a regular file", inputFileName));
    }
    if (!input.canRead()) {
      throw new IllegalArgumentException(
        format("File %s is not readable", inputFileName));
    }
  }
}
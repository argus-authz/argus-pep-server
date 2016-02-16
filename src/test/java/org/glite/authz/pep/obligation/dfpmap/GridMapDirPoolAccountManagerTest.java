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

package org.glite.authz.pep.obligation.dfpmap;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.httpclient.URIException;
import org.apache.commons.io.FileUtils;

import eu.emi.security.authn.x509.impl.OpensslNameUtils;
import junit.framework.TestCase;

/**
 * JUnit for pool account management and mapping for bug
 * https://savannah.cern.ch/bugs/?66574
 */
public class GridMapDirPoolAccountManagerTest extends TestCase {

  File gridmapdir = null;

  static int N_POOL = 3;

  GridMapDirPoolAccountManager gridmapPool = null;

  List<String> prefixes = Arrays.asList("dteam", "dteamprod", "user1test",
    "user2test", "a", "aa", "a-", "a_0a", "Z.", "lte-dteam");

  List<String> invalids = Arrays.asList("-invalid", ".invalid", "_invalid",
    "0invalid", "0", "001", "_");

  private File createTempGridMapDir() throws IOException {

    File temp = File.createTempFile("gridmapdir", ".junit");
    if (!(temp.delete())) {
      throw new IOException(
        "Could not delete temp file: " + temp.getAbsolutePath());
    }
    if (!(temp.mkdir())) {
      throw new IOException(
        "Could not create temp directory: " + temp.getAbsolutePath());
    }
    temp.deleteOnExit();
    // populate with pool accounts
    for (String prefix : prefixes) {
      for (int i = 1; i <= N_POOL; i++) {
        File f = new File(temp, prefix + "0" + i);
        f.createNewFile();
        f.deleteOnExit();
      }
    }
    // create invalid files
    for (String invalid : invalids) {
      for (int i = 1; i <= N_POOL; i++) {
        File f = new File(temp, invalid + "0" + i);
        f.createNewFile();
        f.deleteOnExit();
      }
    }
    return temp;
  }

  private boolean deleteTempGridMapDir(final File path) {

    boolean lRetVal = false;
    try {
      FileUtils.deleteDirectory(path);
      lRetVal = true;
    } catch (IOException e) {
      lRetVal = false;
    }
    return lRetVal;
  }

  @Override
  protected void setUp() throws Exception {

    super.setUp();
    gridmapdir = createTempGridMapDir();

    gridmapPool = new GridMapDirPoolAccountManager(gridmapdir, true);
  }

  @Override
  protected void tearDown() throws Exception {

    super.tearDown();
    assertTrue("Failed to delete temp gridmapdir: " + gridmapdir,
      deleteTempGridMapDir(gridmapdir));
  }

  public void testPoolAccountNamesPrefixed() {

    System.out.println("------------testPoolAccountNamesPrefixed------------");
    String prefix = "dteam";
    List<String> accountNames = gridmapPool.getPoolAccountNames(prefix);
    System.out.println("accountNames(" + prefix + "): " + accountNames);
    assertTrue("Empty pool account names for prefix: " + prefix,
      accountNames.size() > 0);
    for (String accountName : accountNames) {
      System.out.println("checking: " + accountName);
      assertTrue(accountName + " doesn't match",
        accountName.matches(prefix + "\\d+"));
    }
    System.out.println("TEST PASSED");
  }

  public void testPoolAccountNamesPrefixes() {

    System.out.println("------------testPoolAccountNamesPrefixes------------");
    List<String> accountNames = gridmapPool.getPoolAccountNamePrefixes();
    System.out.println("accountNamePrefixes: " + accountNames);
    for (String accountName : accountNames) {
      assertTrue(accountName + " not in prefix list",
        prefixes.contains(accountName));
    }

    System.out.println("TEST PASSED");
  }

  public void testPoolAccountNames() {

    System.out.println("------------testPoolAccountNames------------");
    List<String> accountNames = gridmapPool.getPoolAccountNames();
    System.out.println("poolAccountNames: " + accountNames);
    assertTrue("Empty pool account names", accountNames.size() > 0);
    assertEquals(prefixes.size() * N_POOL, accountNames.size());
    System.out.println("TEST PASSED");
  }

  public void testCreateMapping() {

    System.out.println("------------testCreateMapping------------");
    String prefix = "dteam";
    String identifier = "%2fcn%3djohn%20doe:dteam";
    String accountName = gridmapPool.createMapping(prefix, identifier);
    System.out
      .println("Identifier '" + identifier + "' mapped to: " + accountName);
    assertTrue(accountName + " doesn't match dteam pool",
      accountName.matches(prefix + "\\d+"));
    System.out.println("TEST PASSED");
  }

  public void testMapToAccountPoolDteam() throws Exception {

    System.out.println("------------testMapToAccountPoolDteam------------");
    String prefix = "dteam";
    String subject = "CN=Robin";
    X500Principal principal = new X500Principal(subject);
    String accountName = gridmapPool.mapToAccount(prefix, principal, prefix,
      null);
    System.out.println("Principal '" + principal + "' with account prefix '"
      + prefix + "' mapped to: " + accountName);
    assertTrue(accountName + " doesn't match dteam pool",
      accountName.matches(prefix + "\\d+"));
    System.out.println("TEST PASSED");
  }

  public void testMapToAccountPoolLTEDteam() throws Exception {

    System.out.println("------------testMapToAccountPoolLTEDteam------------");
    System.out.println("BUG FIX: https://savannah.cern.ch/bugs/?66574");
    String prefix = "lte-dteam";
    List<String> subjects = Arrays.asList("CN=John-John Doe", "CN=Batman",
      "CN=John-John Doe", "CN=Robin", "CN=John-John Doe");
    for (String subject : subjects) {
      X500Principal principal = new X500Principal(subject);
      String accountName = gridmapPool.mapToAccount(prefix, principal, prefix,
        null);
      System.out.println("principal '" + principal + "' with account prefix '"
        + prefix + "' mapped to: " + accountName);
      assertTrue(accountName + " doesn't match " + prefix + " pool",
        accountName.matches(prefix + "\\d+"));
    }
    System.out.println("TEST PASSED");
  }

  public void testSubjectIdentifierFileTimestampUpdate() throws Exception {

    System.out.println(
      "------------testSubjectIdentifierFileTimestampUpdate------------");
    System.out
      .println("BUG FIX: https://savannah.cern.ch/bugs/index.php?83281");
    System.out
      .println("BUG FIX: https://savannah.cern.ch/bugs/index.php?84846");
    String prefix = "dteam";
    List<String> subjects = Arrays.asList("CN=Batman", "CN=Batman", "CN=Batman",
      "CN=Robin", "CN=Robin", "CN=Robin", "CN=John-John Doe",
      "CN=John-John Doe", "CN=John-John Doe", "CN=John-John Doe",
      "CN=John-John Doe");
    long lastmodified = System.currentTimeMillis();
    for (String subject : subjects) {
      // touch granularity in 1 sec!!!
      Thread.sleep(1000);
      X500Principal principal = new X500Principal(subject);
      String accountName = gridmapPool.mapToAccount(prefix, principal, prefix,
        null);
      System.out.println("Principal '" + principal + "' with account prefix '"
        + prefix + "' mapped to: " + accountName);
      assertTrue(accountName + " doesn't match " + prefix + " pool",
        accountName.matches(prefix + "\\d+"));

      String subjectIdentifier = gridmapPool.buildSubjectIdentifier(principal,
        prefix, null);
      String subjectIdentifierFilePath = gridmapPool
        .buildSubjectIdentifierFilePath(subjectIdentifier);
      File subjectIdentifierFile = new File(subjectIdentifierFilePath);
      System.out.println("Subject identifier file: " + subjectIdentifierFile);
      System.out.println("Lastmodified: " + lastmodified + " < "
        + subjectIdentifierFile.lastModified());
      assertTrue("Timestamp not updated",
        lastmodified < subjectIdentifierFile.lastModified());
      lastmodified = subjectIdentifierFile.lastModified();
    }

    System.out.println("TEST PASSED");

  }

  public void testSubjectIdentifierFilenameWithSecGroups() throws URIException {

    System.out.println(
      "------------testSubjectIdentifierFilenameWithSecGroups------------");
    System.out.println("BUG FIX: https://savannah.cern.ch/bugs/?83317");
    String group = "lte-dteam";
    List<String> groups = Arrays.asList("cms", "LTE", "DTEAM");
    X500Principal principal = new X500Principal(
      "CN=John-John Doe,DC=Test,DC=users");
    System.out.println("Principal: " + principal);
    System.out.println("Group: " + group);
    System.out.println("Groups: " + groups);
    String leaseFilename = gridmapPool.buildSubjectIdentifier(principal, group,
      groups);
    System.out.println("Lease filename: " + leaseFilename);
    assertTrue("Wrong lease filename generated",
      leaseFilename.contains("lte-dteam"));
    assertTrue("Wrong lease filename generated", leaseFilename.contains("cms"));
    assertTrue("Wrong lease filename generated", leaseFilename.contains("LTE"));
    assertTrue("Wrong lease filename generated",
      leaseFilename.contains("DTEAM"));
    System.out.println("TEST PASSED");
  }

  public void testSubjectIdentifierFilenameWithoutSecGroups()
    throws URIException {

    System.out.println(
      "------------testSubjectIdentifierFilenameWithoutSecGroups------------");
    System.out.println("BUG FIX: https://savannah.cern.ch/bugs/?83317");
    String group = "lte-dteam";
    List<String> groups = Arrays.asList("cms", "LTE", "dteam");
    X500Principal principal = new X500Principal(
      "CN=John-John Doe,DC=Test,DC=users");
    System.out.println("Principal: " + principal);
    System.out.println("Group: " + group);
    System.out.println("Groups: " + groups);
    gridmapPool.setUseSecondaryGroupNamesForMapping(false);
    String leaseFilename = gridmapPool.buildSubjectIdentifier(principal, group,
      groups);
    System.out.println("Lease filename: " + leaseFilename);
    assertTrue("Wrong lease filename generated",
      leaseFilename.contains("lte-dteam"));
    assertFalse("Wrong lease filename generated",
      leaseFilename.contains("cms"));
    assertFalse("Wrong lease filename generated",
      leaseFilename.contains("LTE"));
    assertFalse("Wrong lease filename generated",
      leaseFilename.contains("DTEAM"));
    System.out.println("TEST PASSED");
  }

  public void testSubjectIdentifierEncoding() throws URIException {

    System.out.println("------------testSubjectIdentifierEncoding------------");
    System.out
      .println("BUG FIX: https://savannah.cern.ch/bugs/index.php?83419");
    X500Principal principal = new X500Principal(
      "CN=John-John Doe,DC=Test,DC=users");
    System.out.println("Principal: " + principal);
    String rfc2253Subject = principal.getName();
    String openSSLSubject = OpensslNameUtils.convertFromRfc2253(rfc2253Subject,
      false);
    System.out.println("Subject: " + openSSLSubject);
    String encodedSubject = gridmapPool.encodeSubjectIdentifier(openSSLSubject);
    System.out.println("Encoded subject: " + encodedSubject);
    assertFalse("Subject not correctly encoded", encodedSubject.contains("-"));
    assertFalse("Subject not correctly encoded", encodedSubject.contains("/"));
    assertFalse("Subject not correctly encoded", encodedSubject.contains("="));
    assertFalse("Subject not correctly encoded", encodedSubject.contains(" "));
    System.out.println("TEST PASSED");
  }

}

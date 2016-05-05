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
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.fqan.FQAN;
import org.glite.authz.pep.obligation.ObligationProcessingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import junit.framework.TestCase;

/**
 * JUnit test case for DN/FQAN account mapping
 */
public class AccountMapperTest extends TestCase {

  private Logger log = LoggerFactory.getLogger(AccountMapperTest.class);

  private int N_POOL = 5;

  private String[] poolAccountNamePrefixes = { "atlas", "smscg", "switch",
    "cmsplt", "cms" };

  private String[] fixedAccountNames = { "dteam", "robin", "batman" };

  PoolAccountManager poolAccountManager = null;

  File gridMapDir = null;

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
    for (String prefix : poolAccountNamePrefixes) {
      for (int i = 1; i <= N_POOL; i++) {
        String pool = prefix + "00" + i;
        File f = new File(temp, pool);
        log.trace("create " + pool + " pool account");
        f.createNewFile();
        f.deleteOnExit();
      }
    }
    // populate with fix accounts
    for (String name : fixedAccountNames) {
      File f = new File(temp, name);
      log.trace("create " + name + " account");
      f.createNewFile();
      f.deleteOnExit();
    }
    return temp;
  }

  /**
   * Returns the {@link InputStream} for the given filePath by searching in the
   * classpath and on the file system.
   * 
   * @param filePath
   *          Path to the file (absolute or within classpath)
   * @return The file InputStream
   * @throws FileNotFoundException
   *           if the filePath can't be found in classpath or on the file system
   */
  protected InputStream getFileInputStream(final String filePath)
    throws FileNotFoundException {

    // first search file in classpath, then as absolute filename
    log.debug("Load file from classpath: {}", filePath);
    InputStream is = getClass().getResourceAsStream(filePath);
    if (is == null) {
      log.debug("Not in classpath, load file from file: {}", filePath);
      is = new FileInputStream(filePath);
    }
    return is;
  }

  /** {@inheritDoc} */
  @Override
  protected void setUp() throws Exception {

    super.setUp();
    gridMapDir = createTempGridMapDir();
    poolAccountManager = new GridMapDirPoolAccountManager(gridMapDir, true);
  }

  /** {@inheritDoc} */
  @Override
  protected void tearDown() throws Exception {

    super.tearDown();
    TestUtils.deleteTempGridMapDir(gridMapDir);
  }

  protected DFPM createDFPM(final String filePath)
    throws ConfigurationException, FileNotFoundException {

    DFPM dfpm = new OrderedDFPM();
    InputStream is = getFileInputStream(filePath);
    Reader reader = new InputStreamReader(is);
    DFPMFileParser mappingFileParser = new DFPMFileParser();
    mappingFileParser.parse(dfpm, reader);
    return dfpm;
  }

  protected PosixAccount mapToPosixAccount(final X500Principal subjectDN,
    final FQAN primaryFQAN, final List<FQAN> secondaryFQANs,
    final boolean preferDNForLoginName,
    final boolean preferDNForPrimaryGroupName,
    final boolean noPrimaryGroupNameIsError) throws FileNotFoundException,
      ConfigurationException, ObligationProcessingException {

    DFPM accountIndicatorDFPM = createDFPM("/grid-mapfile");
    DFPM groupDFPM = createDFPM("/group-mapfile");

    DFPMMatchStrategy<X500Principal> dnMatchStrategy = new X509MatchStrategy();
    DFPMMatchStrategy<FQAN> fqanMatchStrategy = new FQANMatchStrategy();

    AccountIndicatorMappingStrategy aimStrategy = new DNPrimaryFQANAccountIndicatorMappingStrategy(
      accountIndicatorDFPM, dnMatchStrategy, fqanMatchStrategy,
      preferDNForLoginName);

    GroupNameMappingStrategy gnmStrategy = new DNFQANGroupNameMappingStrategy(
      groupDFPM, dnMatchStrategy, fqanMatchStrategy,
      preferDNForPrimaryGroupName);

    AccountMapper accountMapper = new AccountMapper(aimStrategy, gnmStrategy,
      poolAccountManager, noPrimaryGroupNameIsError);

    PosixAccount account = accountMapper.mapToAccount(subjectDN, primaryFQAN,
      secondaryFQANs);
    return account;
  }

  public void testAccountMappingDN_WithFAQNs() throws Exception {

    X500Principal subjectDN = new X500Principal("OU=Grid User,CN=Batman");
    FQAN primaryFQAN = new FQAN("/dteam", "prod");
    List<FQAN> secondaryFQANs = Arrays.asList(new FQAN("/atlas"),
      new FQAN("/switch"));
    System.out.println("----------------------------------");

    System.out.println("mapping (DN/FQANs) subject: " + subjectDN + " FQAN: "
      + primaryFQAN + " FQANs: " + secondaryFQANs);
    PosixAccount account = mapToPosixAccount(subjectDN, primaryFQAN,
      secondaryFQANs, true, true, false);
    System.out.println("mapped to POSIX account: " + account);
    assertTrue("batman".equals(account.getLoginName()));
    assertTrue("batman".equals(account.getPrimaryGroup()));
    assertTrue(account.getSecondaryGroups().contains("dteam"));
    assertTrue(account.getSecondaryGroups().contains("atlas"));
    assertTrue(account.getSecondaryGroups().contains("switch"));
  }

  public void testAccountMappingDN_NoFQAN() throws Exception {

    X500Principal subjectDN = new X500Principal("OU=Grid User,CN=Batman");
    FQAN primaryFQAN = null;
    List<FQAN> secondaryFQANs = null;
    System.out.println("----------------------------------");

    System.out.println("mapping (DN only) subject: " + subjectDN + " FQAN: "
      + primaryFQAN + " FQANs: " + secondaryFQANs);
    PosixAccount account = mapToPosixAccount(subjectDN, primaryFQAN,
      secondaryFQANs, true, true, false);
    System.out.println("mapped to POSIX account: " + account);
    assertTrue("batman".equals(account.getLoginName()));
    assertTrue("batman".equals(account.getPrimaryGroup()));
    assertTrue(account.getSecondaryGroups().isEmpty());
  }

  public void testAccountMappingDN_NoFQAN_NoError() throws Exception {

    X500Principal subjectDN = new X500Principal("OU=Grid User,CN=Robin");
    FQAN primaryFQAN = null;
    List<FQAN> secondaryFQANs = null;
    System.out.println("----------------------------------");

    System.out.println("mapping (DN only/No error) subject: " + subjectDN
      + " FQAN: " + primaryFQAN + " FQANs: " + secondaryFQANs);
    PosixAccount account = mapToPosixAccount(subjectDN, primaryFQAN,
      secondaryFQANs, true, true, false);
    System.out.println("mapped to POSIX account: " + account);
    assertTrue("robin".equals(account.getLoginName()));
    assertNull(account.getPrimaryGroup());
    assertTrue(account.getSecondaryGroups().isEmpty());
  }

  public void testAccountMappingDN_NoFQAN_NoPrmaryGroupError()
    throws Exception {

    X500Principal subjectDN = new X500Principal("OU=Grid User,CN=Robin");
    FQAN primaryFQAN = null;
    List<FQAN> secondaryFQANs = null;
    System.out.println("----------------------------------");

    System.out.println("mapping (DN only/No primary group error) subject: "
      + subjectDN + " FQAN: " + primaryFQAN + " FQANs: " + secondaryFQANs);
    try {
      PosixAccount account = mapToPosixAccount(subjectDN, primaryFQAN,
        secondaryFQANs, true, true, true);
      fail("No primary group should failed: account=" + account);
    } catch (ObligationProcessingException e) {
      // expected
      System.out.println("EXPECTED ERROR: " + e.getMessage());
    }
  }

  public void testAccountMappingFQAN_dteam() throws Exception {

    X500Principal subjectDN = new X500Principal("OU=Grid User,CN=Batman");
    FQAN primaryFQAN = new FQAN("/dteam", "prod");
    List<FQAN> secondaryFQANs = Arrays.asList(new FQAN("/atlas"),
      new FQAN("/switch"));
    System.out.println("----------------------------------");

    System.out.println("mapping (FQAN/DN) subject: " + subjectDN + " FQAN: "
      + primaryFQAN + " FQANs: " + secondaryFQANs);
    PosixAccount account = mapToPosixAccount(subjectDN, primaryFQAN,
      secondaryFQANs, false, false, false);
    System.out.println("mapped to POSIX account: " + account);
    assertTrue("dteam".equals(account.getLoginName()));
    assertTrue("dteam".equals(account.getPrimaryGroup()));
    assertTrue(account.getSecondaryGroups().contains("batman"));
    assertTrue(account.getSecondaryGroups().contains("atlas"));
    assertTrue(account.getSecondaryGroups().contains("switch"));

  }

  public void testAccountMappingFQAN_atlasPool() throws Exception {

    X500Principal subjectDN = new X500Principal("OU=Grid User,CN=Batman");
    FQAN primaryFQAN = new FQAN("/atlas");
    List<FQAN> secondaryFQANs = Arrays.asList(new FQAN("/dteam"),
      new FQAN("/switch"));

    System.out.println("----------------------------------");
    System.out.println("mapping (FQAN/DN) subject: " + subjectDN + " FQAN: "
      + primaryFQAN + " FQANs: " + secondaryFQANs);
    PosixAccount account = mapToPosixAccount(subjectDN, primaryFQAN,
      secondaryFQANs, false, false, false);
    System.out.println("mapped to POSIX account: " + account);
    assertTrue(account.getLoginName().startsWith("atlas"));
    assertTrue("atlas".equals(account.getPrimaryGroup()));
    assertTrue(account.getSecondaryGroups().contains("batman"));
    assertTrue(account.getSecondaryGroups().contains("dteam"));
    assertTrue(account.getSecondaryGroups().contains("switch"));

  }

  public void testAccountMappingFQAN_NoPrmaryGroupError() throws Exception {

    X500Principal subjectDN = new X500Principal("OU=Grid User,CN=Robin");
    FQAN primaryFQAN = new FQAN("/tata", "prod");
    List<FQAN> secondaryFQANs = Arrays.asList(new FQAN("/titi"),
      new FQAN("/toto"));
    System.out.println("----------------------------------");

    System.out.println("mapping (FQAN/DN/No primary group error) subject: "
      + subjectDN + " FQAN: " + primaryFQAN + " FQANs: " + secondaryFQANs);
    try {
      PosixAccount account = mapToPosixAccount(subjectDN, primaryFQAN,
        secondaryFQANs, false, false, true);
      fail("No primary group should failed: account=" + account);
    } catch (ObligationProcessingException e) {
      // expected
      System.out.println("EXPECTED ERROR: " + e.getMessage());
    }
  }

  public void testAccountMappingNoDN_NoFQAN() throws Exception {

    X500Principal subjectDN = null;
    FQAN primaryFQAN = null;
    List<FQAN> secondaryFQANs = null;
    System.out.println("----------------------------------");

    System.out.println("mapping (Nothing) subject: " + subjectDN + " FQAN: "
      + primaryFQAN + " FQANs: " + secondaryFQANs);
    try {
      PosixAccount account = mapToPosixAccount(subjectDN, primaryFQAN,
        secondaryFQANs, false, false, false);
      fail("No subject should failed: account=" + account);
    } catch (ObligationProcessingException e) {
      // expected
      System.out.println("EXPECTED ERROR: " + e.getMessage());
    }
  }

  public void testAccountMappingUnknown() throws Exception {

    X500Principal subjectDN = new X500Principal("OU=Grid User,CN=Unknown");
    FQAN primaryFQAN = new FQAN("/tata");
    List<FQAN> secondaryFQANs = Arrays.asList(new FQAN("/titi"),
      new FQAN("/toto"));
    System.out.println("----------------------------------");

    System.out.println("mapping (Unknown user) subject: " + subjectDN
      + " FQAN: " + primaryFQAN + " FQANs: " + secondaryFQANs);
    try {
      PosixAccount account = mapToPosixAccount(subjectDN, primaryFQAN,
        secondaryFQANs, false, false, false);
      fail("Unknown subject/FQANs should failed: account=" + account);
    } catch (ObligationProcessingException e) {
      // expected
      System.out.println("EXPECTED ERROR: " + e.getMessage());
    }
  }

  public void testSecondaryGroupMappingEncoding() throws Exception {

    X500Principal subjectDN = new X500Principal("OU=Test User,CN=Tester");
    FQAN primaryFQAN = new FQAN("/cms", "pilot");
    List<FQAN> secondaryFQANs = Arrays.asList(new FQAN("/cms"));

    System.out.println("mapping (DN/FQANs) subject: " + subjectDN + " FQAN: "
      + primaryFQAN + " FQANs: " + secondaryFQANs);

    PosixAccount account = mapToPosixAccount(subjectDN, primaryFQAN,
      secondaryFQANs, true, true, false);

    System.out.println("mapped to POSIX account: " + account);

    assertTrue(account.getLoginName().startsWith("cmsplt"));
    assertTrue("zh".equals(account.getPrimaryGroup()));
    assertTrue(account.getSecondaryGroups().isEmpty());

    File subjectIdentifierFile = followHardLink(account);

    String subjIdFileName = subjectIdentifierFile.getName();
    String suffix = buildSubjectIdentifierFileSuffix(account);

    assertTrue(subjIdFileName.endsWith(suffix));
  }

  public void testEmptySecondaryGroupMappingEncoding() throws Exception {

    X500Principal subjectDN = new X500Principal("OU=Test User,CN=Tester");
    FQAN primaryFQAN = new FQAN("/cms");
    List<FQAN> secondaryFQANs = null;

    System.out.println("mapping (DN/FQANs) subject: " + subjectDN + " FQAN: "
      + primaryFQAN + " FQANs: " + secondaryFQANs);

    PosixAccount account = mapToPosixAccount(subjectDN, primaryFQAN,
      secondaryFQANs, true, true, false);

    System.out.println("mapped to POSIX account: " + account);

    assertTrue(account.getLoginName().matches("cms(\\d+)"));
    assertTrue("zh".equals(account.getPrimaryGroup()));
    assertTrue(account.getSecondaryGroups().isEmpty());

    File subjectIdentifierFile = followHardLink(account);

    String subjIdFileName = subjectIdentifierFile.getName();
    String suffix = buildSubjectIdentifierFileSuffix(account);

    assertTrue(subjIdFileName.endsWith(suffix));
  }
  
  public void testEmptySecondaryGroupsWithPrimaryFqanInSecondaryFqans() throws Exception {

    X500Principal subjectDN = new X500Principal("OU=Test User,CN=Tester");
    FQAN primaryFQAN = new FQAN("/cms");
    List<FQAN> secondaryFQANs = Arrays.asList(primaryFQAN);

    System.out.println("mapping (DN/FQANs) subject: " + subjectDN + " FQAN: "
      + primaryFQAN + " FQANs: " + secondaryFQANs);

    PosixAccount account = mapToPosixAccount(subjectDN, primaryFQAN,
      secondaryFQANs, true, true, false);

    System.out.println("mapped to POSIX account: " + account);

    assertTrue(account.getLoginName().matches("cms(\\d+)"));
    assertTrue("zh".equals(account.getPrimaryGroup()));
    assertTrue(account.getSecondaryGroups().isEmpty());

    File subjectIdentifierFile = followHardLink(account);

    String subjIdFileName = subjectIdentifierFile.getName();
    String suffix = buildSubjectIdentifierFileSuffix(account);

    assertTrue(subjIdFileName.endsWith(suffix));
  }

  private File followHardLink(final PosixAccount poolAccount) {

    UnixFile accountFile = UnixFile.forExistingFile(new File(
      gridMapDir.getAbsolutePath() + "/" + poolAccount.getLoginName()));

    long ino = accountFile.ino();
    File subjectFile = null;

    for (File f : gridMapDir.listFiles()) {
      if (UnixFile.forExistingFile(f).ino() == ino
        && !f.getName().equals(poolAccount.getLoginName())) {
        subjectFile = f;
        break;
      }
    }

    return subjectFile;
  }

  private String buildSubjectIdentifierFileSuffix(
    final PosixAccount poolAccount) {

    StringBuilder suffixBuilder = new StringBuilder("user:");
    List<String> groups = new ArrayList<String>();
    groups.add(poolAccount.getPrimaryGroup());
    groups.addAll(poolAccount.getSecondaryGroups());

    Iterator<String> it = groups.iterator();
    while (it.hasNext()) {
      suffixBuilder.append(it.next());
      if (it.hasNext()) {
        suffixBuilder.append(":");
      }
    }

    return suffixBuilder.toString();
  }

}

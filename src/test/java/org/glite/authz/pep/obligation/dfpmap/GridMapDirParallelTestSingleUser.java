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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CyclicBarrier;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.io.FileUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class GridMapDirParallelTestSingleUser {

  static int N_THREAD = 20;

  final int N_POOL = 20;

  File gridmapdir = null;

  GridMapDirPoolAccountManager gridmapPool = null;
  Map<Long, String> resultMap = null;

  final String mAccountPrefix = "tst";
  final String mSubject = "C=IT, O=IGI, CN=test0";

  private File createTempGridMapDir() throws IOException {

    File temp = File.createTempFile("test-gridmapdir", ".junit");
    if (!(temp.delete())) {
      throw new IOException(
        "Could not delete temp file: " + temp.getAbsolutePath());
    }

    if (!(temp.mkdir())) {
      throw new IOException(
        "Could not create temp directory: " + temp.getAbsolutePath());
    }

    temp.deleteOnExit();

    for (int idx = 1; idx <= N_POOL; idx++) {
      String lFileName = String.format("%s%03d", mAccountPrefix, idx);
      File f = new File(temp, lFileName);
      f.createNewFile();
      f.deleteOnExit();
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

  @Before
  public void setUp() throws Exception {

    gridmapdir = createTempGridMapDir();
    gridmapPool = new GridMapDirPoolAccountManager(gridmapdir, true);
  }

  @After
  public void tearDown() throws Exception {

    assertTrue("Failed to delete temp gridmapdir: " + gridmapdir,
      deleteTempGridMapDir(gridmapdir));
  }

  @Test
  public void testParallelMappingForSingleUser() {

    X500Principal lSubjectDn = new X500Principal(mSubject);
    CyclicBarrier lBarrier = new CyclicBarrier(N_THREAD, new Runnable() {

      public void run() {

        System.out.println("All thread are arrived at barrier");
      }
    });

    System.out.println("testParallelMapping: START");
    List<Thread> lThreadList = new ArrayList<Thread>();
    resultMap = new LinkedHashMap<Long, String>();

    for (int idx = 0; idx < N_THREAD; idx++) {
      Thread lThread = new ThreadTester(gridmapPool, lBarrier, mAccountPrefix,
        lSubjectDn, null, null);
      lThreadList.add(lThread);
    }

    for (Thread lThread : lThreadList) {
      lThread.start();
    }

    try {
      for (Thread lThread : lThreadList) {
        lThread.join();
      }
    } catch (InterruptedException e) {
      System.out.println("Thread join interrupted.");
    }

    String lAccount = null;

    for (Map.Entry<Long, String> lEntry : resultMap.entrySet()) {
      String lRetVal = lEntry.getValue();

      assertNotNull(lRetVal);

      if (lAccount == null) {
        lAccount = lRetVal;
      }

      assertTrue(lRetVal.equals(lAccount));
    }

    System.out.println("testParallelMapping: END");

  }

  public class ThreadTester extends Thread implements Runnable {

    private GridMapDirPoolAccountManager mGridMapPool;
    private CyclicBarrier mBarrier;
    private String mAccountNamePrefix;
    private X500Principal mSubjectDN;
    private String mPrimaryGroup;
    private List<String> mSecondaryGroups;

    public ThreadTester(final GridMapDirPoolAccountManager pGridMapPool,
      final CyclicBarrier pBarrier, final String pAccountNamePrefix,
      final X500Principal pSubjectDN, final String pPrimaryGroup,
      final List<String> pSecondaryGroups) {
      this.mGridMapPool = pGridMapPool;
      this.mBarrier = pBarrier;
      this.mAccountNamePrefix = pAccountNamePrefix;
      this.mSubjectDN = pSubjectDN;
      this.mPrimaryGroup = pPrimaryGroup;
      this.mSecondaryGroups = pSecondaryGroups;
    }

    @Override
    public void run() {

      String lRetVal = null;

      try {
        Long lThreadId = this.getId();

        System.out
          .println(String.format("Thread [%d] waits on barrier", lThreadId));
        mBarrier.await();
        System.out.println(
          String.format("Thread [%d] has cross the barrier", lThreadId));

        lRetVal = mGridMapPool.mapToAccount(this.mAccountNamePrefix,
          this.mSubjectDN, this.mPrimaryGroup, this.mSecondaryGroups);

        System.out.println(String.format(
          "Thread [%d] mapped to pool account [%s]", lThreadId, lRetVal));
        resultMap.put(lThreadId, lRetVal);

      } catch (Exception e) {
        e.printStackTrace();
      }
    }
  }

}

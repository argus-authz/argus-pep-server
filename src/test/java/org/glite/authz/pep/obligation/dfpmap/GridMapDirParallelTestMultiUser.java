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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.io.FileUtils;

import junit.framework.Assert;
import junit.framework.TestCase;

public class GridMapDirParallelTestMultiUser extends TestCase {

  public static final int NUM_THREADS = 10;
  public static final int NUM_ACCOUNTS = 20;
  public static final int NUM_ITERATIONS = 1;

  File gridmapdir = null;

  GridMapDirPoolAccountManager poolAccountManager = null;

  final CyclicBarrier startBarrier = new CyclicBarrier(NUM_THREADS + 1);

  final String accountPrefix = "tst";
  final String subjectPrefix = "C=IT, O=IGI, CN=test";
  X500Principal[] principals = new X500Principal[NUM_THREADS];

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

    for (int idx = 1; idx <= NUM_ACCOUNTS; idx++) {
      String lFileName = String.format("%s%02d", accountPrefix, idx);
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

  @Override
  protected void setUp() throws Exception {

    super.setUp();
    gridmapdir = createTempGridMapDir();

    poolAccountManager = new GridMapDirPoolAccountManager(gridmapdir, true);

    for (int i = 0; i < NUM_THREADS; i++) {
      String subject = String.format("%s%d", subjectPrefix, i);
      principals[i] = new X500Principal(subject);
    }

  }

  @Override
  protected void tearDown() throws Exception {

    super.tearDown();
    assertTrue("Failed to delete temp gridmapdir: " + gridmapdir,
      deleteTempGridMapDir(gridmapdir));
  }

  public void testParallelMappingForMultipleUsers() {

    for (int iter = 0; iter < NUM_ITERATIONS; iter++) {

      ExecutorService executorService = Executors
        .newFixedThreadPool(NUM_THREADS + 1);

      Map<String, Future<String>> futures = new HashMap<String, Future<String>>();

      for (int i = 0; i < NUM_THREADS; i++) {

        Future<String> result = executorService
          .submit(new Worker(poolAccountManager, startBarrier, accountPrefix,
            principals[i], null, null));

        futures.put(principals[i].getName(), result);
      }

      try {
        startBarrier.await();

      } catch (InterruptedException e) {

      } catch (BrokenBarrierException e) {

      }

      executorService.shutdown();

      Set<String> poolAccounts = new HashSet<String>();

      for (Future<String> res : futures.values()) {
        try {
          poolAccounts.add(res.get());
        } catch (InterruptedException e) {
        } catch (ExecutionException e) {
          throw new RuntimeException(e);
        }
      }

      Assert.assertTrue("Wrong number of distinct pool account returned",
        poolAccounts.size() == NUM_THREADS);

    }

  }

  public static class Worker implements Callable<String> {

    private final GridMapDirPoolAccountManager manager;
    private final CyclicBarrier startBarrier;
    private final String accountNamePrefix;
    private final X500Principal subject;
    private final String primaryGroup;
    private final List<String> secondaryGroups;

    public Worker(GridMapDirPoolAccountManager mgr, CyclicBarrier barrier,
      String accountPrefix, X500Principal s, String primaryGroup,
      List<String> secondaryGroups) {

      this.manager = mgr;
      this.startBarrier = barrier;
      this.accountNamePrefix = accountPrefix;
      this.subject = s;
      this.primaryGroup = primaryGroup;
      this.secondaryGroups = secondaryGroups;

    }

    public String call() throws Exception {

      try {
        startBarrier.await();
      } catch (InterruptedException e) {

      }
      
      return manager.mapToAccount(accountNamePrefix, subject, primaryGroup,
        secondaryGroups);

    }

  }
}

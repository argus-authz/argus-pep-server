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

import static org.junit.Assert.assertTrue;

import java.io.File;
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
import java.util.concurrent.TimeUnit;

import javax.security.auth.x500.X500Principal;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class GridMapDirParallelTestMultiUser {

  public static final int NUM_THREADS = 30;
  public static final int NUM_ACCOUNTS = 30;
  public static final int NUM_ITERATIONS = 10;

  File gridmapdir = null;

  GridMapDirPoolAccountManager poolAccountManager = null;

  final CyclicBarrier startBarrier = new CyclicBarrier(NUM_THREADS + 1);

  final String accountPrefix = "tst";
  final String subjectPrefix = "C=IT, O=IGI, CN=test";
  X500Principal[] principals = new X500Principal[NUM_THREADS];

  @Before
  public void setUp() throws Exception {

    gridmapdir = TestUtils.createTempGridMapDir(accountPrefix, NUM_ACCOUNTS);
    
    PoolAccountResolver resolver = new CachingPoolAccountResolver(gridmapdir,
      10, TimeUnit.SECONDS);

    GridmapDirGetMappingStrategy lockFreeMappingStragy = LockFreeMappingStrategy
      .forGridmapDir(gridmapdir)
      .withShuffleAccounts(true)
      .withPoolAccountResolver(resolver)
      .withMaxLookupIterations(2).build();

    poolAccountManager = new GridMapDirPoolAccountManager(lockFreeMappingStragy,
      gridmapdir, true);

    for (int i = 0; i < NUM_THREADS; i++) {
      String subject = String.format("%s%d", subjectPrefix, i);
      principals[i] = new X500Principal(subject);
    }

  }

  @After
  protected void tearDown() throws Exception {

    assertTrue("Failed to delete temp gridmapdir: " + gridmapdir,
      TestUtils.deleteTempGridMapDir(gridmapdir));
  }

  @Test
  public void testParallelMappingForMultipleUsers() {

    for (int iter = 0; iter < NUM_ITERATIONS; iter++) {

      System.out.println("#####################");
      System.out.println("ITERATION "+iter);
      System.out.println("#####################");
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

      assertTrue("Wrong number of distinct pool account returned",
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
      String result = manager.mapToAccount(accountNamePrefix, subject, primaryGroup,
        secondaryGroups);
      
     
      return result; 

    }

  }
}

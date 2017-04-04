package org.glite.authz.pep.pip.provider.authnprofilespip;

import static eu.emi.security.authn.x509.impl.OpensslNameUtils.opensslToRfc2253;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ConcurrentAuthenticationProfilePolicyLoadTests extends TestSupport {

  public static final Logger LOG =
      LoggerFactory.getLogger(ConcurrentAuthenticationProfilePolicyLoadTests.class);

  private AuthenticationProfileRepository profileRepo;
  private AuthenticationProfilePolicySetRepository policySetRepo;

  private AuthenticationProfilePDP pdp;

  private final int DECISION_RUNNER_COUNT = 10;
  private final int REPO_RELOADER_COUNT = 2;

  private final int ALL_THREADS_COUNT = DECISION_RUNNER_COUNT + REPO_RELOADER_COUNT;
  private final int ITERATION_COUNT = 100;

  private CyclicBarrier barrier = new CyclicBarrier(ALL_THREADS_COUNT, () -> {
    LOG.info("All thread at barrier! GO!");
  });

  // This is initialized to -2 since the first loading of the policy set  (and the clock count 
  // increase) happens when the repository is first created
  private AtomicInteger logicalClock = new AtomicInteger(-2);  
  

  @Before
  public void setup() throws IOException {

    profileRepo = new TrustAnchorsDirectoryAuthenticationProfileRepository(TRUST_ANCHORS_DIR,
        ALL_POLICIES_FILTER);

    AuthenticationProfilePolicySetBuilder builder = new SynchronizingVoCaApParser(
        new VoCaApInfoFileParser(IGTF_WLCG_VO_CA_AP_FILE, profileRepo));

    policySetRepo = new DefaultAuthenticationProfilePolicySetRepository(builder);

    pdp = new DefaultAuthenticationProfilePDP(profileRepo, policySetRepo);

  }

  private void testRun() {
    List<Thread> threads = new ArrayList<>();

    for (int i = 0; i < DECISION_RUNNER_COUNT; i++) {
      threads.add(new Thread(new DecisionRunner(barrier, logicalClock, pdp), "dr-" + i));
    }

    for (int i = 0; i < REPO_RELOADER_COUNT; i++) {
      threads.add(new Thread(new ReloaderThread(barrier, policySetRepo, logicalClock), "rr-" + i));
    }

    threads.forEach(t -> t.start());
    threads.forEach(t -> {
      try {
        t.join();
      } catch (InterruptedException e) {
        throw new IllegalStateException(e);
      }
    });
  }

  @Test
  public void testSyncCorrectness() {

    for (int i = 0; i < ITERATION_COUNT; i++) {
      testRun();
    }
    
    assertThat(logicalClock.intValue(), equalTo(2 * ITERATION_COUNT * REPO_RELOADER_COUNT));
  }



  class SynchronizingVoCaApParser implements AuthenticationProfilePolicySetBuilder {

    private AuthenticationProfilePolicySetBuilder builder;

    public SynchronizingVoCaApParser(AuthenticationProfilePolicySetBuilder builder) {
      this.builder = builder;
    }

    @Override
    public AuthenticationProfilePolicySet build() {

      AuthenticationProfilePolicySet result = null;
      try {
        result = builder.build();
      } finally {
        logicalClock.getAndIncrement();
        logicalClock.getAndIncrement();
      }
      return result;
    }
  }

  static class ReloaderThread implements Runnable {

    private Logger log = LoggerFactory.getLogger(ReloaderThread.class);

    final CyclicBarrier barrier;
    final AuthenticationProfilePolicySetRepository repo;
    final AtomicInteger clock;

    public ReloaderThread(CyclicBarrier barrier, AuthenticationProfilePolicySetRepository repo,
        AtomicInteger clock) {
      this.barrier = barrier;
      this.repo = repo;
      this.clock = clock;
    }

    @Override
    public void run() {
      try {
        barrier.await();
        log.info("Clock value before reload: {}", clock.intValue());
        repo.reloadRepositoryContents();
        log.info("Clock value after reload: {}", clock.intValue());
      } catch (InterruptedException | BrokenBarrierException e) {
        throw new IllegalStateException(e);
      }
    }
  }


  static class DecisionRunner implements Runnable {

    private Logger log = LoggerFactory.getLogger(DecisionRunner.class);

    final CyclicBarrier barrier;
    final AtomicInteger clock;
    final AuthenticationProfilePDP pdp;

    public DecisionRunner(CyclicBarrier barrier, AtomicInteger clock,
        AuthenticationProfilePDP pdp) {
      this.barrier = barrier;
      this.clock = clock;
      this.pdp = pdp;
    }

    private void checkClock() {
      int value = clock.intValue();
      log.debug("Clock value: {}", value);
      
      // If the DecisionRunner sees an odd value it means is in the same critical section
      // as the RepoUpdater, so we have a race condition
      if ((value % 2) != 0) {
        throw new IllegalStateException("Logical clock returned odd value to DecisionRunner!");
      }
    }

    @SuppressWarnings("deprecation")
    @Override
    public void run() {
      try {

        barrier.await();
        checkClock();

        if (!pdp.isCaAllowed(opensslToRfc2253(CLASSIC_CA)).isAllowed()){
          throw new IllegalStateException("Decision runner got wrong decision");
        }
        
      } catch (InterruptedException | BrokenBarrierException e) {
        throw new IllegalStateException(e);
      } finally {
        checkClock();
      }
    }

  }

}

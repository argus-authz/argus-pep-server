package org.glite.authz.pep.pip.provider.authnprofilespip;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import net.jcip.annotations.ThreadSafe;

/**
 * 
 * A basic, realoding implementation for {@link AuthenticationProfilePolicySetRepository}, which can 
 * refresh its contents in a thread-safe manner.
 *
 */
@ThreadSafe
public class DefaultAuthenticationProfilePolicySetRepository
    implements AuthenticationProfilePolicySetRepository {
  
  protected final ReadWriteLock rwLock = new ReentrantReadWriteLock();
  
  protected final Lock readLock = rwLock.readLock();
  protected final Lock writeLock = rwLock.writeLock();
  
  private AuthenticationProfilePolicySet policySet;
  private final AuthenticationProfilePolicySetBuilder builder;
  
  public DefaultAuthenticationProfilePolicySetRepository(AuthenticationProfilePolicySetBuilder builder) {
   this.builder = builder;
   buildPolicySet();
  }
  
  protected void buildPolicySet(){
    writeLock.lock();
    try{
      policySet = builder.build();
    }finally {
      writeLock.unlock();
    }
  }
  
  @Override
  public AuthenticationProfilePolicySet getAuthenticationProfilePolicySet() {
    readLock.lock();
    try{
      return policySet;
    }finally {
      readLock.unlock();
    }
  }

  @Override
  public void reloadRepositoryContents() {
    buildPolicySet();
  }

}

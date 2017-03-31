package org.glite.authz.pep.pip.provider.authnprofilespip;

/**
 * 
 * A {@link Lifecycle} can be started and stopped.
 *
 */
public interface Lifecycle {
  
  /**
   * Starts this {@link Lifecycle}
   */
  void start();
  
  /**
   * Stops this {@link Lifecycle}
   */
  void stop();
  
}

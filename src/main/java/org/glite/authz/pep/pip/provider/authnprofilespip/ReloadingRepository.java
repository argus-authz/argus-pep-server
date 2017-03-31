package org.glite.authz.pep.pip.provider.authnprofilespip;

/**
 * 
 * A {@link ReloadingRepository} can reload its contents
 *
 */
public interface ReloadingRepository {
  
  /**
   * Triggers repository content reloading
   */
  void reloadRepositoryContents();
  
}

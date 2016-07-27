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

import org.jruby.ext.posix.FileStat;

/**
 * A File class helper that links together Java file with stat information and
 * useful PosixUtil methods.
 *
 */
public class UnixFile {

  private UnixFile(File f) {

    file = f;
  }

  private final File file;
  private FileStat stat;
  
  public static UnixFile forNonExistingFile(File f){
    
    UnixFile uf = new UnixFile(f);
    return uf;
  }

  public static UnixFile forExistingFile(File f) {

    UnixFile uf = new UnixFile(f);
    uf.stat();

    return uf;
  }


  public String getAbsolutePath() {

    return file.getAbsolutePath();
  }

  public boolean exists() {

    return file.exists();
  }

  private void assertStatNotNull(){
    if (stat == null){
      String msg = String.format("stat not available for '%s'", getAbsolutePath());
      throw new NullPointerException(msg);
    }
  }
  
  public long ino() {
    assertStatNotNull();
    return stat.ino();
  }

  public int nlink() {
    assertStatNotNull();
    return stat.nlink();
  }

  public void stat() {

    stat = PosixUtil.getFileStat(file.getAbsolutePath());
  }

  public boolean inodeEquals(UnixFile other) {
    assertStatNotNull();
    other.assertStatNotNull();
    return this.ino() == other.ino();
  }

  public String getName() {

    return file.getName();
  }

  public File getFile() {

    return file;
  }

  public boolean delete() {

    return file.delete();
  }

  public void touch() {

    PosixUtil.touchFile(file);
  }

  @Override
  public String toString() {

    return "UnixFile [path=" + getAbsolutePath() + ", ino=" + ino() + ", nlink="
      + nlink() + "]";
  }

}

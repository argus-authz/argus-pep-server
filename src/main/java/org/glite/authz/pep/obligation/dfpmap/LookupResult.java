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

class LookupResult {

  enum LookupResultStatus {
    SUCCESS,
    CORRUPTED_POOL_ACCOUNT,
    NOT_FOUND,
    CONTINUE,
    LINK_ERROR
  }

  LookupResult.LookupResultStatus status;
  UnixFile account;

  private LookupResult(LookupResult.LookupResultStatus s, UnixFile account) {
    this.status = s;
    this.account = account;
  }

  private LookupResult(LookupResult.LookupResultStatus s) {
    this(s, null);
  }

  public boolean isContinue() {

    return status == LookupResult.LookupResultStatus.CONTINUE;
  }

  public boolean isSuccess() {

    return status == LookupResult.LookupResultStatus.SUCCESS;
  }

  public boolean isCorruptedPoolAccount() {

    return status == LookupResult.LookupResultStatus.CORRUPTED_POOL_ACCOUNT;
  }

  public boolean isNotFound() {

    return status == LookupResult.LookupResultStatus.NOT_FOUND;
  }

  public boolean isLinkError() {

    return status == LookupResult.LookupResultStatus.LINK_ERROR;
  }

  public static LookupResult continueLookup() {

    return new LookupResult(LookupResult.LookupResultStatus.CONTINUE);
  }

  public static LookupResult corruptedPoolAccount() {

    return new LookupResult(LookupResult.LookupResultStatus.CORRUPTED_POOL_ACCOUNT);
  }

  public static LookupResult success(UnixFile account) {

    return new LookupResult(LookupResult.LookupResultStatus.SUCCESS, account);
  }

  public static LookupResult notFound() {

    return new LookupResult(LookupResult.LookupResultStatus.NOT_FOUND);
  }

  public static LookupResult linkError() {

    return new LookupResult(LookupResult.LookupResultStatus.LINK_ERROR);
  }
}
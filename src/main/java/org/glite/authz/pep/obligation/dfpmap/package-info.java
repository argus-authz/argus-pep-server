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

/** 
 * An obligation handler that maps a subject to a POSIX account.
 * 
 * Currently this package supports the mapping of a subject to an account based on an X.509 subject ID, a primary FQAN,
 * and a set of secondary FQANs.
 * 
 * DFPM stands for DN/FQAN to POSIX Mapping.
 */
package org.glite.authz.pep.obligation.dfpmap;
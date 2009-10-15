/*
 * Copyright 2009 Members of the EGEE Collaboration.
 * See http://www.eu-egee.org/partners for details on the copyright holders. 
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/** 
 * A policy enforcement point daemon.  This daemon takes the Hessian 1 authorization request protocol supported 
 * by the policy enforcement point client and turns them in to XACML over SAML requests that may then be sent to a PDP.  
 * See the package {@code org.glite.authz.common.model} package for the Hessian data model used by this request.
 * 
 * @see <a href="http://hessian.caucho.com/doc/hessian-1.0-spec.xtp">Hessian 1 specification</a>
 * @see <a href="http://switch.ch/grid/support/documents/">SOAP Profile for XACML-SAML</a>
 */
package org.glite.authz.pep.server;
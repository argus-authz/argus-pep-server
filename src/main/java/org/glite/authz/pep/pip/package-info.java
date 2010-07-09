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
 * Base classes for implementing policy information points (PIPs).
 * 
 * Policy information points are used by the PDP and PEP components to collect additional data that may be used when 
 * rendering an authorization decisions.  Such data may be retrieved from external sources (e.g. a relational database)
 * or may be derived from data already present in the request.
 */
package org.glite.authz.pep.pip;
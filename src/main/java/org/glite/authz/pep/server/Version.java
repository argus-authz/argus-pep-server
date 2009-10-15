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

package org.glite.authz.pep.server;

import net.jcip.annotations.ThreadSafe;

/** Utility class for getting and printing the service name and version number. */
@ThreadSafe
public class Version {

    /**
     * Main entry point to program.
     * 
     * @param args command line arguments
     */
    public static void main(String[] args) {
        System.out.println(getServiceIdentifier());
    }
    
    /**
     * Gets the service name and version number.
     * 
     * @return the service name and version number
     */
    public static String getServiceIdentifier(){
        return getServiceName() + " version " + getServiceVersion();
    }
    
    /**
     * Gets the name of this service.
     * 
     * @return name of this service
     */
    public static String getServiceName(){
        Package pkg = Version.class.getPackage();
        return pkg.getImplementationTitle();
    }
    
    /**
     * Gets the version number of this service.
     * 
     * @return version number of this service
     */
    public static String getServiceVersion(){
        Package pkg = Version.class.getPackage();
        return pkg.getImplementationVersion();
    }
}
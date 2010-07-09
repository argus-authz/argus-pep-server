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
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import junit.framework.TestCase;

/**
 * JUnit for pool account management and mapping for bug https://savannah.cern.ch/bugs/?66574
 */
public class GridMapDirPoolAccountManagerTest extends TestCase {

    File gridmapdir = null;

    static int N_POOL = 3;

    GridMapDirPoolAccountManager gridmapPool = null;

    List<String> prefixes = Arrays.asList("dteam", "dteamprod", "user1test", "user2test", "a", "aa", "1a", "1aa");

    List<String> invalids = Arrays.asList("invalid", "001temp", "0", "001");

    private File createTempGridMapDir() throws IOException {
        File temp = File.createTempFile("gridmapdir", ".junit");
        if (!(temp.delete())) {
            throw new IOException("Could not delete temp file: " + temp.getAbsolutePath());
        }
        if (!(temp.mkdir())) {
            throw new IOException("Could not create temp directory: " + temp.getAbsolutePath());
        }
        temp.deleteOnExit();
        // populate with pool accounts
        for (String prefix : prefixes) {
            for (int i = 1; i <= N_POOL; i++) {
                File f = new File(temp, prefix + "0" + i);
                f.createNewFile();
                f.deleteOnExit();
            }
        }
        // create invalid files
        for (String invalid : invalids) {
            for (int i = 1; i <= N_POOL; i++) {
                File f = new File(temp,invalid);
                f.createNewFile();
                f.deleteOnExit();
            }
        }
        return temp;
    }

    public boolean deleteTempGridMapDir(File path) {
        if (path.exists()) {
            File[] files = path.listFiles();
            for (int i = 0; i < files.length; i++) {
                if (files[i].isDirectory()) {
                    deleteTempGridMapDir(files[i]);
                } else {
                    files[i].delete();
                }
            }
        }
        return (path.delete());
    }

    /** {@inheritDoc} */
    protected void setUp() throws Exception {
        super.setUp();
        gridmapdir = createTempGridMapDir();
        // System.out.println("setUp: temp gridmapdir: " + gridmapdir);
        gridmapPool = new GridMapDirPoolAccountManager(gridmapdir);
    }

    /** {@inheritDoc} */
    protected void tearDown() throws Exception {
        super.tearDown();
        // System.out.println("tearDown: delete temp gridmapdir: " + gridmapdir);
        assertTrue("Failed to delete temp gridmapdir: " + gridmapdir, deleteTempGridMapDir(gridmapdir));
    }

    public void testPoolAccountNamesPrefixed() {
        String prefix = "dteam";
        List<String> accountNames = gridmapPool.getPoolAccountNames(prefix);
        for (String accountName : accountNames) {
            System.out.println("checking: " + accountName);
            assertTrue(accountName + " doesn't match", accountName.matches(prefix + "\\d+"));
        }
    }

    public void testPoolAccountNamesPrefixes() {
        List<String> accountNames = gridmapPool.getPoolAccountNamePrefixes();
        for (String accountName : accountNames) {
            System.out.println(accountName);
            assertTrue(accountName + " not in prefix list", prefixes.contains(accountName));
        }

    }

    public void testPoolAccountNames() {
        List<String> accountNames = gridmapPool.getPoolAccountNames();
        for (String accountName : accountNames) {
            System.out.println("pool account: " + accountName);
        }
        assertEquals(prefixes.size() * N_POOL, accountNames.size());
    }

    public void testCreateMapping() {
        String prefix = "dteam";
        String identifier = "%2fcn%3djohn%20doe:dteam";
        String accountName = gridmapPool.createMapping(prefix, identifier);
        System.out.println(identifier + " mapped to " + accountName);
        assertTrue(accountName + " doesn't match dteam pool", accountName.matches(prefix + "\\d+"));
    }

    public void testMapToAccount() throws Exception {
        String prefix = "dteam";
        String subject = "CN=John Doe";
        X500Principal principal = new X500Principal(subject);
        String accountName = gridmapPool.mapToAccount(prefix, principal, prefix, null);
        assertTrue(accountName + " doesn't match dteam pool", accountName.matches(prefix + "\\d+"));
    }
}

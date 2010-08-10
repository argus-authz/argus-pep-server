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
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.fqan.FQAN;

import junit.framework.TestCase;

/**
 *
 */
public class AccountMapperTest extends TestCase {

    private int N_POOL = 5;

    private String[] poolAccountNamePrefixes = { "atlas", "smscg", "switch", "test" };

    private String[] prodAccountNames = { "dteam","atlasprod", "smscgprod", "switchprod", "testprod" };

    PoolAccountManager poolAccountManager = null;

    File gridMapDir = null;

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
        for (String prefix : poolAccountNamePrefixes) {
            for (int i = 1; i <= N_POOL; i++) {
                String pool= prefix + "00" + i; 
                File f = new File(temp, pool);
                System.out.println("create " + pool + " account");
                f.createNewFile();
                f.deleteOnExit();
            }
        }
        // populate with fix accounts
        for (String name : prodAccountNames) {
            File f = new File(temp, name);
            System.out.println("create " + name + " account");
            f.createNewFile();
            f.deleteOnExit();
        }
        return temp;
    }

    protected boolean deleteTempDir(File path) {
        if (path.exists()) {
            File[] files = path.listFiles();
            for (int i = 0; i < files.length; i++) {
                if (files[i].isDirectory()) {
                    deleteTempDir(files[i]);
                } else {
                    files[i].delete();
                }
            }
        }
        return (path.delete());
    }

    /**
     * Returns the {@link InputStream} for the given filePath by searching in the classpath and on the file system.
     * 
     * @param filePath Path to the file (absolute or within classpath)
     * @return The file InputStream
     * @throws FileNotFoundException if the filePath can't be found in classpath or on the file system
     */
    protected InputStream getFileInputStream(String filePath) throws FileNotFoundException {
        // first search file in classpath, then as absolute filename
        System.out.println("Load file from classpath: " + filePath);
        InputStream is = getClass().getResourceAsStream(filePath);
        if (is == null) {
            System.out.println("Not in classpath, load file from file:" + filePath);
            is = new FileInputStream(filePath);
        }
        return is;
    }

    /** {@inheritDoc} */
    protected void setUp() throws Exception {
        super.setUp();
        gridMapDir = createTempGridMapDir();
        poolAccountManager = new GridMapDirPoolAccountManager(gridMapDir);
    }

    /** {@inheritDoc} */
    protected void tearDown() throws Exception {
        super.tearDown();
        deleteTempDir(gridMapDir);
    }

    public void testMapping() throws Exception {
        DFPM accountIndicatorDFPM = createDFPM("/grid-mapfile");
        DFPM groupDFPM = createDFPM("/group-mapfile");

        DFPMMatchStrategy<X500Principal> dnMatchStrategy = new X509MatchStrategy();
        DFPMMatchStrategy<FQAN> fqanMatchStrategy = new FQANMatchStrategy();

        AccountIndicatorMappingStrategy aimStrategy = new DNPrimaryFQANAccountIndicatorMappingStrategy(
                accountIndicatorDFPM, dnMatchStrategy, fqanMatchStrategy, true);
        GroupNameMappingStrategy gnmStrategy = new FQANGroupNameMappingStrategy(groupDFPM, fqanMatchStrategy);

        AccountMapper accountMapper = new AccountMapper(aimStrategy, gnmStrategy, poolAccountManager);
        
        X500Principal subjectDN= new X500Principal("OU=Grid User,CN=John Doe");
        FQAN primaryFQAN= FQAN.parseFQAN("/dteam");
        List<FQAN> secondaryFQANs= null;
        
        System.out.println("mapping DN: " + subjectDN + " FQAN: " + primaryFQAN + " sec FQANs: " + secondaryFQANs);
        
        PosixAccount account= accountMapper.mapToAccount(subjectDN, primaryFQAN, secondaryFQANs);
        System.out.println("account: " + account);
    }

    protected DFPM createDFPM(String filePath) throws ConfigurationException, FileNotFoundException {
        DFPM dfpm = new OrderedDFPM();
        InputStream is = getFileInputStream(filePath);
        Reader reader = new InputStreamReader(is);
        DFPMFileParser mappingFileParser = new DFPMFileParser();
        mappingFileParser.parse(dfpm, reader);
        return dfpm;
    }

}

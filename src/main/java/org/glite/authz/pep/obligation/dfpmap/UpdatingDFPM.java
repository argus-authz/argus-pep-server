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
import java.io.FileReader;
import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;

import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.util.Files;
import org.glite.authz.common.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link DFPM} implementation that periodically re-reads a mapping file and, if changes have occurred, updates the
 * mapping. Such an update does not effect any
 */
public class UpdatingDFPM implements DFPM {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(UpdatingDFPM.class);

    /** Delegate that is refreshed every period. */
    private DFPM delegate;

    /** Timer used to run the background mapping file refresh. */
    private Timer taskTimer;
    
    /** Factory used to create empty {@link DFPM}s. */
    private final DFPMFactory dfpmFactory;

    /** Path to the mapping file that will be periodically reloaded. */
    private final String mappingFilePath;

    /**
     * Constructor.
     * 
     * @param factory factory that produces an empty {@link DFPM} into which data will be loaded
     * @param mappingFile mapping file that will be periodically read and loaded in to the created {@link DFPM}
     * @param refreshPeriod {@link DFPM} refresh period in milliseconds
     */
    public UpdatingDFPM(DFPMFactory factory, String mappingFile, long refreshPeriod) {
        if(factory == null){
            throw new IllegalArgumentException("mapping factory may not be null");
        }
        dfpmFactory = factory;
        
        mappingFilePath = Strings.safeTrimOrNullString(mappingFile);
        if(mappingFile == null){
            throw new IllegalArgumentException("mapping file may not be null");
        }
        try {
            Files.getReadableFile(mappingFilePath);
        } catch (IOException e) {
            log.error("Unable to read map file " + mappingFilePath, e);
            throw new IllegalArgumentException("Unable to read map file " + mappingFilePath, e);
        }
        
        if(refreshPeriod < 1){
            throw new IllegalArgumentException("Refresh period must be 1 or greater");
        }
        
        UpdateDFPMTask updateTask = new UpdateDFPMTask();
        updateTask.run();
        taskTimer = new Timer(true);
        taskTimer.scheduleAtFixedRate(updateTask, refreshPeriod, refreshPeriod);
    }

    /** {@inheritDoc} */
    public boolean isDNMapEntry(String key) {
        return delegate.isDNMapEntry(key);
    }

    /** {@inheritDoc} */
    public boolean isFQANMapEntry(String key) {
        return delegate.isFQANMapEntry(key);
    }

    /** {@inheritDoc} */
    public void clear() {
        delegate.clear();
    }

    /** {@inheritDoc} */
    public boolean containsKey(Object key) {
        return delegate.containsKey(key);
    }

    /** {@inheritDoc} */
    public boolean containsValue(Object value) {
        return delegate.containsValue(value);
    }

    /** {@inheritDoc} */
    public Set<java.util.Map.Entry<String, List<String>>> entrySet() {
        return delegate.entrySet();
    }

    /** {@inheritDoc} */
    public List<String> get(Object key) {
        return delegate.get(key);
    }

    /** {@inheritDoc} */
    public boolean isEmpty() {
        return delegate.isEmpty();
    }

    /** {@inheritDoc} */
    public Set<String> keySet() {
        return delegate.keySet();
    }

    /** {@inheritDoc} */
    public List<String> put(String key, List<String> value) {
        return delegate.put(key, value);
    }

    /** {@inheritDoc} */
    public void putAll(Map<? extends String, ? extends List<String>> map) {
        delegate.putAll(map);
    }

    /** {@inheritDoc} */
    public List<String> remove(Object key) {
        return delegate.remove(key);
    }

    /** {@inheritDoc} */
    public int size() {
        return delegate.size();
    }

    /** {@inheritDoc} */
    public Collection<List<String>> values() {
        return delegate.values();
    }

    /** Background task for updating a {@link DFPM}. */
    private class UpdateDFPMTask extends TimerTask {
        
        /** Local time the mapping file was last modified. */
        private long mappingFileLastModified;
        
        /** {@inheritDoc} */
        public void run() {
            try {
                log.trace("Refreshing mapping file: {}", mappingFilePath);
                File mappingFile = Files.getReadableFile(mappingFilePath);
                if(mappingFile.lastModified() <= mappingFileLastModified){
                    log.trace("Mapping file has not changed since last refresh, nothing need to be done.");
                    return;
                }
                
                DFPM dfpm = dfpmFactory.newInstance();

                DFPMFileParser mappingFileParser = new DFPMFileParser();
                mappingFileParser.parse(dfpm, new FileReader(mappingFile));
                mappingFileLastModified = mappingFile.lastModified();
                delegate = dfpm;
            } catch (IOException e) {
                log.error("Unable to read mapping file " + mappingFilePath
                        + " due to the following error.  DN/FQAN mapping will not be updated.", e);
            } catch (ConfigurationException e) {
                log.error(
                        "Unable to parse mapping file " + mappingFilePath + ".  DN/FQAN mapping will not be updated.",
                        e);
            }
        }
    }

    /** Factory used to create a new instance of a {@link DFPM}. */
    public static interface DFPMFactory {

        /**
         * Creates a new, empty {@link DFPM} instance.
         * 
         * @return new, empty {@link DFPM} instance
         */
        public DFPM newInstance();
    }
}
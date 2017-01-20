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
 *
 * Authors:
 * 2016-
 *    Mischa Salle <msalle@nikhef.nl>
 *    Rens Visser <rensv@nikhef.nl>
 *    NIKHEF Amsterdam, the Netherlands
 *    <grid-mw-security@nikhef.nl>
 */

package org.glite.authz.pep.pip.provider.policynamespip;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.HashSet;
import java.nio.file.Path;
import java.nio.file.DirectoryStream;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.attribute.FileTime;
import java.nio.charset.Charset;
import java.io.BufferedReader;
import java.net.URLDecoder;
import java.util.Calendar;

import java.io.IOException;
import java.text.ParseException;

import static java.lang.String.format;


/**
 * Helper class for {@link org.glite.authz.pep.pip.provider.PolicyNamesPIP}
 * providing a parsed cache of the subjectdn entries in the info files in the
 * trust directory.
 * @author Mischa Sall&eacute;
 */
public class PolicyNamesCache {
    /** Class logger instance */
    private static final Logger LOG = LoggerFactory.getLogger(PolicyNamesCache.class);


    ////////////////////////////////////////////////////////////////////////
    // constants
    ////////////////////////////////////////////////////////////////////////
 
    /** Extension of info file ({@value}) */
    public final static String FILE_SFX = ".info";
    
    /** Key in info file starting subject DNs ({@value}) */
    public final static String SUBJECT_KEY = "subjectdn";

    /** Maximum level of info file recursion ({@value}) */
    public final static int MAX_RECURSION = 10;


    ////////////////////////////////////////////////////////////////////////
    // instance variables
    ////////////////////////////////////////////////////////////////////////

    /** Cached list of {@value #FILE_SFX} file entries in the trustDir */
    private LinkedHashMap<Path,Entry> infoEntries = new LinkedHashMap<Path,Entry>();
    
    /** Cached list of {@value #FILE_SFX} file entries outside of the trustDir */
    private LinkedHashMap<Path,Entry> extInfoEntries = new LinkedHashMap<Path,Entry>();
   
    /** Previous cached list of {@value #FILE_SFX} file entries in the trustDir */
    private LinkedHashMap<Path,Entry> oldInfoEntries = null;
    
    /** Previous cached list of {@value #FILE_SFX} file entries outside of the
     * trustDir */
    private LinkedHashMap<Path,Entry> oldExtInfoEntries = null;
    
    /** Directory containing the {@value #FILE_SFX} files */
    private String trustDir = null;

    /**
     * Time when PolicyNamesCache was initialized
     * @see #getLifeTime
     */
    private long initTime = 0;

    /** Number of new entries in the current update */
    private int numEntriesNew;
    /** Number of failed entries in the current update */
    private int numEntriesFailed;
    /** Number of copied entries in the current update */
    private int numEntriesCopied;

    /**
     * Filter for filtering out .info file. Seems faster than using a glob in
     * newDirectoryStream() */
    final static DirectoryStream.Filter<Path> infoFileFilter=new DirectoryStream.Filter<Path>() {
	public boolean accept(Path path)   {
	    return (path.toString().endsWith(FILE_SFX));
	}
    };

    
    ////////////////////////////////////////////////////////////////////////
    // Constructors
    ////////////////////////////////////////////////////////////////////////

    /**
     * constructs new PolicyNamesCache based on given trustDir
     * @param trustDir directory containing info files
     * @throws IOException on read errors for trustDir or one of the info files
     * @see #PolicyNamesCache(PolicyNamesCache)
     */
    public PolicyNamesCache(String trustDir) throws IOException   {
	this.trustDir = trustDir;
	this.update();
    }

    /**
     * constructs new PolicyNamesCache based on old PolicyNamesCache
     * @param oldCache previous PolicyNamesCache
     * @throws IOException on read errors for trustDir or one of the info files
     * @see #PolicyNamesCache(String)
     */
    public PolicyNamesCache(PolicyNamesCache oldCache) throws IOException    {
	this.update(oldCache);
    }


    ////////////////////////////////////////////////////////////////////////
    // Public methods
    ////////////////////////////////////////////////////////////////////////
 
    /**
     * Returns the lifetime of this PolicyNamesCache in milliseconds.
     * @return msecs since initialization of this PolicyNamesCache
     */
    public long getLifeTime()  {
	return Calendar.getInstance().getTimeInMillis()-initTime;
    }

    /**
     * Tries to find given issuer DN in the cached info files in 
     * the {@link #trustDir}.
     * @param issuerDN String issuer DN to look for
     * @return array of String with all the matching info files
     */
    public String[] matchIssuerDN(String issuerDN) {
	// Protect against empty cache
	if (infoEntries == null)    {
	    return new String[0];
	}

	// Initialize an empty list of policynames
	ArrayList<String> policynames = new ArrayList<String>();

	// Loop over the cached list and look for match
	for (Entry entry: infoEntries.values())	{
	    if (entry.subDNs.contains(issuerDN))    {
		policynames.add(entry.name);
	    }
	}

	// Convert ArrayList to an array and return
	return policynames.toArray(new String[0]);
    }


    ////////////////////////////////////////////////////////////////////////
    // Private methods
    ////////////////////////////////////////////////////////////////////////

    /**
     * Updates the current cache not using existing one.
     * @throws IOException upon reading errors
     * @see #update(PolicyNamesCache)
     */
    private void update() throws IOException    {
	this.update(null);
    }

    /**
     * Update internal, cached list of parsed-out info files in the specified
     * trustDir.
     * @param oldCache previous PolicyNamesCache to be updated
     * @see #update()
     * @throws IOException upon reading errors
     */
    private void update(PolicyNamesCache oldCache) throws IOException    {
	long t0=System.nanoTime();

	// Set initialization time
	initTime = Calendar.getInstance().getTimeInMillis();

	// Reset indicator for any change
	numEntriesNew=numEntriesCopied=numEntriesFailed=0;

	// Force directories to be the same and update the old lists
	if (oldCache!=null) {
	    trustDir=oldCache.trustDir;
	    oldInfoEntries=oldCache.infoEntries;
	    oldExtInfoEntries=oldCache.extInfoEntries;
	}

	// Get current list of info files
	final List<Path> infoFiles = getInfoFiles(trustDir);

	// Loop over infoFiles
	int numInfoFiles=infoFiles.size();
	for (int i=0; i<numInfoFiles; i++)    {
	    try {
		handleEntry(infoFiles.get(i), oldInfoEntries, infoEntries, 0);
	    } catch (ParseException e)	{
		LOG.warn("Syntax error, skipping {}", infoFiles.get(i), e);
	    }
	}

	// Reprocess overall subDNs list when something changed
	if (numEntriesNew > 0) {
	    for (Entry entry: infoEntries.values()) {
		entry.updateSubDNs();
	    }
	    for (Entry entry: extInfoEntries.values())	{
		entry.updateSubDNs();
	    }
	}
	
	// Log statistics
	LOG.debug("Updated list ({}): {} msec ({} info files, {} valid, {} external dep(s), {} copied, {} failed, {} new)",
		  trustDir, (System.nanoTime()-t0)/1000000.0,
		  numInfoFiles, infoEntries.size(), extInfoEntries.size(),
		  numEntriesCopied, numEntriesFailed, numEntriesNew);
    }

    /**
     * Find all {@value #FILE_SFX} files in given trust dir.
     * @param trustDir directory containing {@value #FILE_SFX} files
     * @return ArrayList of Path
     * @throws IOException upon directory reading errors
     */
    private ArrayList<Path> getInfoFiles(String trustDir) throws IOException {
	// Protect against null trustDir
	if (trustDir==null)
	    throw new IOException("Trust dir is null");

	// Get all files as a stream
	DirectoryStream<Path> stream=null;
	try {
	    stream = Files.newDirectoryStream(Paths.get(trustDir), infoFileFilter);
	} catch(IOException e)	{
	    throw new IOException("Trust dir has problems: "+e.getMessage(), e);
	}

	// Initialize file array
	ArrayList<Path> files = new ArrayList<Path>();
	// Add all entries
	for (Path entry: stream)    {
	    files.add(entry);
	}

	return files;
    }

    /**
     * Creates a new entry or updates an existing one (by updating dependencies
     * where needed). The entry is first searched for in the oldList and used
     * when unchanged. Otherwise a new entry is parsed. Following that, the list
     * of 'external' dependencies (i.e. those outside the {@link #trustDir} or
     * not ending with {@value #FILE_SFX}) is handled, by recursively calling
     * ourselves.
     * @param path path of entry to handle
     * @param oldList either {@link #oldInfoEntries} or
     * {@link #oldExtInfoEntries} depending on the type of entry
     * @param newList either {@link #infoEntries} or {@link #extInfoEntries}
     * depending on the type of entry
     * @param recursion level of recursion (max. {@value #MAX_RECURSION})
     * @throws IOException when failing to read a info file
     * @throws ParseException on too many levels of recursion
     */
    private void handleEntry(Path path,
			     LinkedHashMap<Path,Entry> oldList,
			     LinkedHashMap<Path,Entry> newList,
			     int recursion)
	throws IOException, ParseException
    {
	// Protect against recursion
	if (recursion > MAX_RECURSION)	{
	    throw new ParseException(
		format("Too many levels of recursion (max. {}) in {}", MAX_RECURSION, path), recursion);
	}

	// Check existence of file
	if (Files.notExists(path))  {
	    LOG.warn("Skipping non-existing {}", path.getFileName().toString());
	    numEntriesFailed++;
	    return;
	}

	// Get the modification time of the path
	FileTime modified;
	if (Files.isSymbolicLink(path))	{
	    // Symlink: get both link and dest times and use whichever is later
	    FileTime mod_dest=Files.getLastModifiedTime(path);
	    FileTime mod_link=Files.getLastModifiedTime(path, LinkOption.NOFOLLOW_LINKS);
	    modified=(mod_dest.compareTo(mod_link)<0 ? mod_link : mod_dest);
	} else {
	    modified=Files.getLastModifiedTime(path);
	}

	// Try to get an old entry
	Entry entry=(oldList==null ? null : oldList.get(path));

	// If the entry doesn't exist yet or has changed, reparse it.
	if (entry==null || !entry.modified.equals(modified)) {
	    // Create new entry, pass in pre-obtained modified
	    try {
		entry=parseInfoFile(path, modified);
		numEntriesNew++;
	    } catch (ParseException e)	{
		LOG.warn("Syntax error, skipping {}", path.getFileName().toString());
		numEntriesFailed++;
		return;
	    }
	} else {
	    numEntriesCopied++;
	}

	// recursively verify or create its extDeps
	for (Path extpath: entry.extDeps)   {
	    if (!extInfoEntries.containsKey(extpath))	{
		handleEntry(extpath, oldExtInfoEntries, extInfoEntries, recursion+1);
	    }
	}

	// Put it in the new list
	newList.put(path,entry);
    }


    /**
     * Parse an {@value #FILE_SFX} file and obtain an internal {@link Entry}
     * containing all the subject DNs and dependency information.
     * @param path path of the info file
     * @param modified modification time of file
     * @return {@link Entry} describing this file
     * @throws IOException in case of I/O errors
     * @throws ParseException in case of subjectdn parsing errors
     */
    private Entry parseInfoFile(Path path, FileTime modified)
	throws ParseException, IOException
    {
	// First get the value of the subjectdn key, this can throw IOException
	String value = getSubjectDNvalue(path);

	// Did we find the KEY?
	if (value==null || value.isEmpty()) {
	    throw new ParseException(
		format("%s: No or empty %s key found", path.getFileName(), SUBJECT_KEY), 0);
	}

	// Create new Entry for this path, already setting the name and the like
	Entry entry=new Entry(path, modified);

	// Parse out the value of the key into the entry, this can throw
	// IOException or ParseException
	parseSubjectDnValue(entry, value);

	// Now return the entry
	return entry;
    }

    /**
     * Parses an {@value #FILE_SFX} file for the {@link #SUBJECT_KEY} key and
     * returns the value.
     * @param path Path of this info file
     * @return String with the value of the {@link #SUBJECT_KEY}
     * @throws IOException when reading the file failed
     */
    private String getSubjectDNvalue(Path path) throws IOException	{
	String name=path.toString();
	BufferedReader reader=null;
	StringBuilder linebuilder=new StringBuilder();
	String newline;
	String value=null;

	try {
	    reader=Files.newBufferedReader(path, Charset.defaultCharset());
	} catch (IOException e)	{
	    final String errorMsg = format("Cannot open %s: %s", name, e.getMessage());
	    LOG.error(errorMsg);
	    throw new IOException(errorMsg, e);
	}
	
	// initialize line
	try {
	    while ( (newline=reader.readLine()) != null )   {
		// Append to existing or empty line
		linebuilder.append(newline);

		// Handle continuation char
		int end=linebuilder.length()-1;
		if (end>=0 && linebuilder.charAt(end)=='\\')	{
		    linebuilder.deleteCharAt(end);
		    continue;
		}

		// Remove leading whitespace (easiest when converting to String)
		String line=linebuilder.toString().trim();
		// Only look at non-empty non-comment lines
		if (!line.isEmpty() && line.charAt(0)!='#')	{
		    // Split into key / value and look for subjectdn
		    int sep=line.indexOf('=');
		    if (sep>=0 && SUBJECT_KEY.equals(line.substring(0,sep).trim())) {
			value=line.substring(sep+1).trim();
			break;
		    }
		}

		// Continue with next line
		linebuilder.setLength(0);
	    }
	} catch (IOException e)	{
	    // Try to close, this might throw a new IOException. We're throwing
	    // one in any case.
	    final String errorMsg = format("Reading from %s failed: %s", name, e.getMessage());
	    LOG.error(errorMsg);
	    try {
		reader.close();
	    } catch (IOException f)	{
		// Ignore this
	    }
	    throw new IOException(errorMsg, e);
	}

	// Close reader
	try {
	    reader.close();
	} catch (IOException e)	{
	    // Ignore this
	}

	// All done
	return value;
    }

    /**
     * Parses out the different components of a subjectdn value as obtained by
     * {@link #getSubjectDNvalue(Path)} and puts the results into the given entry.
     * When a "file:" entry is found, it will add the correct path to the right
     * list of dependencies.
     * @param entry {@link Entry} to fill
     * @param value value of the subjectdn key
     * @throws ParseException on syntax errors in the value
     * @throws IOException on read errors with one of the info files
     */
    private void parseSubjectDnValue(Entry entry, String value)
	throws ParseException, IOException
    {
	// Now parse the value part
	int pos=0, pos2;
	while (true)	{
	    // Check what we have here
	    if (value.charAt(pos)=='"')	{
		// Found CA subject DN: look for end quote (pos==quote_1)
		pos2=value.indexOf('"', pos+1);
		if ( pos2 < 0 )	{
		    throw new ParseException(
			format("%s: Missing end-quote", entry.name), pos+1);
		}
		// Add url-decoded value to the subDN list
		entry.localSubDNs.add(URLDecoder.decode(value.substring(pos+1,pos2),"UTF-8"));
		// skip over end-quote
		pos2++;
	    } else if (value.substring(pos).startsWith("file:"))    {
		// Found file: look for end of filename
		for (pos2=pos+5;
		     pos2<value.length() && value.charAt(pos2)!=',' && value.charAt(pos2)!=' ' && value.charAt(pos2)!='\t';
		     pos2++);

		// Add value to the right dependency lists
		entry.addDependency(value.substring(pos+5,pos2));
	    } else {
		// Found unknown character at the start
		throw new ParseException(
		    format("%s: %s value invalid: %s", entry.name, SUBJECT_KEY, value), pos);
	    }

	    // Skip all trailing white-space and commas
	    boolean foundComma=false;
	    for (pos=pos2; pos<value.length(); pos++)    {
		// Keep track of whether we found a comma: need at least one
		if (value.charAt(pos)==',') {
		    foundComma=true;
		    continue;
		}
		if (value.charAt(pos)!=' ' && value.charAt(pos)!='\t')	{
		    break;
		}
	    }

	    // Did we hit the end-of-line or find a comment char?
	    if (pos==value.length() || value.charAt(pos)=='#')	{
		break;
	    }

	    // Not yet at end, did we see a comma?
	    if (!foundComma)	{
		throw new ParseException(
		    format("%s: Missing comma delimiter before new entry", entry.name), pos);
	    }
	}
    }


    ////////////////////////////////////////////////////////////////////////
    // Private class
    ////////////////////////////////////////////////////////////////////////

    /** Internal representation of info file entries */
    private class Entry	{
	/** full path of this info file */
	Path path;
	/** name of this info entry (basename of info file) */
	String name;
	/** last modification time of this info file */
	FileTime modified;
	/** dependencies in the trustDir */
	HashSet<Path> deps;
	/** dependencies outside of the trustDir */
	HashSet<Path> extDeps;
	/** set of subject DNs defined directly in this file */
	HashSet<String> localSubDNs;
	/** complete set of subject DNs for this info file */
	HashSet<String> subDNs;

	/**
	 * Constructor, setting name from path.
	 * @param path path of the info file
	 * @param modified modification time of file
	 */
	private Entry(Path path, FileTime modified) {
	    String name=path.getFileName().toString();
	    this.name = (name.endsWith(FILE_SFX)
		? name.substring(0, name.length()-FILE_SFX.length())
		: name);
	    this.path=path;
	    this.modified=modified;
	    this.deps=new HashSet<Path>();
	    this.extDeps=new HashSet<Path>();
	    this.localSubDNs=new HashSet<String>();
	}

	/**
	 * Resolves what type of dependency we have and add to the correct
	 * dependency list. A path outside the trustDir or a path not ending
	 * with {@link #FILE_SFX} is external.
	 * @param dependency Path of the dependency to find
	 */
	private void addDependency(String dependency) {
	    // First get correct Path for the filename
	    Path depPath;
	    if (dependency.charAt(0) == '/')	{
		// absolute path
		depPath=Paths.get(dependency).normalize();
	    } else if (dependency.indexOf('/')==-1) {
		// no directory components, could be non-.info file
		depPath=Paths.get(trustDir, dependency);
	    } else  {
		// relative path incl. at least 1 directory
		depPath=Paths.get(trustDir, dependency).normalize();
	    }
	    
	    // Add path to right dependency list
	    HashSet<Path> depList;
	    // If path is in trustDir *and* ends with the FILE_SFX,
	    // otherwise we consider it external
	    if (trustDir.equals(depPath.getParent().toString()) &&
		depPath.getFileName().toString().endsWith(FILE_SFX))	{
		depList=deps;
	    } else  {
		depList=extDeps;
	    }

	    // Add when not there yet
	    depList.add(depPath);
	}

	/**
	 * Recursively retrieves all subject DNs for this entry, either defined
	 * locally or indirectly via dependencies.
	 * @param recursion level of recursion (max. {@link #MAX_RECURSION})
	 * @return HashSet of String containing all the subject DNs
	 * @throws ParseException on too many levels of recursion
	 */
	private HashSet<String> getSubDNs(int recursion) throws ParseException	{
	    if (recursion>MAX_RECURSION)    {
		throw new ParseException(
		    format("Too many levels of recursion (max. %d) in %s", MAX_RECURSION, name), recursion);
	    }

	    // Create temporary list
	    HashSet<String> subDNsSet=new HashSet<String>();
	    
	    // Add all the local ones
	    subDNsSet.addAll(localSubDNs);

	    // Recursively add all DNs from the deps list
	    for (Path path: deps)   {
		Entry entry=infoEntries.get(path);
		if (entry!=null)    {
		    subDNsSet.addAll(entry.getSubDNs(recursion+1));
		} else	{
		    LOG.warn("Cannot find dep {} for {}", path, name);
		}
	    }
		
	    // Recursively add all DNs from the extDeps list
	    for (Path path: extDeps)	{
		Entry entry=extInfoEntries.get(path);
		if (entry!=null)    {
		    subDNsSet.addAll(entry.getSubDNs(recursion+1));
		} else	{
		    LOG.warn("Cannot find dep {} for {}", path, name);
		}
	    }

	    // Return resulting set as array of String
	    return subDNsSet;
	}

	/**
	 * Recursively updates the internal set of all subject DNs valid for
	 * this entry.
	 */
	private void updateSubDNs() {
	    try {
		this.subDNs=getSubDNs(0);
	    } catch (ParseException e)	{
		LOG.error("Syntax error in {}: {}", name, e.getMessage());
		this.subDNs=new HashSet<String>();
	    }
	}
    
    }
}

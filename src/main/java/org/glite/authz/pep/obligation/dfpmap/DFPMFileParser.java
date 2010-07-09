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

import java.io.IOException;
import java.io.LineNumberReader;
import java.io.Reader;
import java.util.List;
import java.util.UnknownFormatConversionException;

import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** A parser for map files. */
public class DFPMFileParser {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(DFPMFileParser.class);

    /**
     * Parses a map file and populates a given DN/FQAN to POSIX map with its content.
     * 
     * @param map the map to populate
     * @param mapFileReader reader of the map file
     * 
     * @throws ConfigurationException thrown if the map file can not be read
     */
    public void parse(final DFPM map, final Reader mapFileReader) throws ConfigurationException {
        LineNumberReader reader = new LineNumberReader(mapFileReader);

        try {
            String line = reader.readLine();
            do {
                parseLine(map, line, reader.getLineNumber());
                line = reader.readLine();
            } while (line != null);
        } catch (IOException e) {
            log.error("Unable to read map file", e);
            throw new ConfigurationException("Unable to read map file", e);
        }
    }

    /**
     * Parses a single line in of map file.
     * 
     * @param map map to populate
     * @param line the line to parse
     * @param lineNumber the current line number
     * 
     * @throws ConfigurationException thrown if the map file contains an invalid mapping entry
     */
    private void parseLine(DFPM map, String line, int lineNumber) throws ConfigurationException {
        String trimmedLine = Strings.safeTrimOrNullString(line);
        if (trimmedLine == null || trimmedLine.startsWith("#")) {
            log.trace("Line number {} is a comment, no processing performed", lineNumber);
            return;
        }

        int lastDQuote = trimmedLine.lastIndexOf("\"");

        String unescapedKey = Strings.safeTrimOrNullString(trimmedLine.substring(1, lastDQuote));
        if (unescapedKey == null) {
            String msg = "Error on map file line " + lineNumber + ".  Map file entry key may not be null or empty";
            log.error(msg);
            throw new ConfigurationException(msg);
        }
        String name = unescapeString(unescapedKey);

        List<String> values = Strings.toList(trimmedLine.substring(++lastDQuote), ",");
        if (values == null || values.isEmpty()) {
            String msg = "Error on map file line " + lineNumber + ".  Map file entry value may not be null or empty";
            log.error(msg);
            throw new ConfigurationException(msg);
        }

        log.debug("Line number {} maps {} to {}", new Object[] { lineNumber, name, values });
        map.put(name, values);
    }

    /**
     * Replaces escape sequences in a string. The standard Java escape sequences (b, f, n, r, t, u, \, ', ") are
     * supported as well as \xXX for hexadecimal character representation.
     * 
     * @param string the string to unescape
     * 
     * @return the unescaped string
     * 
     * @throws UnknownFormatConversionException thrown if an unsupported escape sequence is found
     */
    private String unescapeString(String string) throws UnknownFormatConversionException {
        char[] stringChars = string.toCharArray();
        StringBuilder unescapedString = new StringBuilder();
        char[] hexChars;

        for (int i = 0; i < stringChars.length; i++) {
            if (stringChars[i] != '\\') {
                unescapedString.append(stringChars[i]);
                continue;
            }

            switch (stringChars[i + 1]) {
                case 'b':
                    unescapedString.append('\b');
                    i++;
                    break;
                case 'f':
                    unescapedString.append('\f');
                    i++;
                    break;
                case 'n':
                    unescapedString.append('\n');
                    i++;
                    break;
                case 'r':
                    unescapedString.append('\r');
                    i++;
                    break;
                case 't':
                    unescapedString.append('\t');
                    i++;
                    break;
                case '\'':
                    unescapedString.append('\'');
                    i++;
                    break;
                case '"':
                    unescapedString.append('"');
                    i++;
                    break;
                case '\\':
                    unescapedString.append('\\');
                    i++;
                    break;
                case 'x':
                    hexChars = new char[2];
                    hexChars[0] = stringChars[i + 2];
                    hexChars[1] = stringChars[i + 3];
                    unescapedString.append((char) Integer.parseInt(new String(hexChars), 16));
                    i += 3;
                    break;
                case 'u':
                    hexChars = new char[4];
                    hexChars[0] = stringChars[i + 2];
                    hexChars[1] = stringChars[i + 3];
                    hexChars[2] = stringChars[i + 4];
                    hexChars[3] = stringChars[i + 5];
                    unescapedString.append((char) Integer.parseInt(new String(hexChars), 16));
                    i += 5;
                    break;
                default:
                    throw new UnknownFormatConversionException("Escape sequence '\\" + stringChars[i + 1]
                            + " in string '" + string + "' is not supported");
            }
        }

        return unescapedString.toString().trim();
    }
}
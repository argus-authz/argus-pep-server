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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.glite.authz.common.util.Strings;

/** Representation of a POSIX user account. */
public class PosixAccount implements Serializable {

    /** Serial version UID. */
    private static final long serialVersionUID = -6232923043396000457L;

    /** Account login name. */
    private String loginName;

    /** Primary group name for this account. */
    private String primaryGroup;

    /** Secondary group names for this account. */
    private List<String> secondaryGroups;

    /** Precomputed string representation of this object. */
    private String stringRepresentation;

    /**
     * Constructor.
     * 
     * @param login user name of the account
     * @param newPrimaryGroup name of the user's primary group
     * @param newSecondaryGroups names of the user's secondary groups
     */
    public PosixAccount(String login, String newPrimaryGroup, List<String> newSecondaryGroups) {
        this.loginName = Strings.safeTrimOrNullString(login);
        if (this.loginName == null) {
            throw new IllegalArgumentException("Login name may not be empty or null");
        }

        this.primaryGroup = newPrimaryGroup;

        if (newSecondaryGroups == null || newSecondaryGroups.isEmpty()) {
            secondaryGroups = Collections.emptyList();
        } else {
            secondaryGroups = Collections.unmodifiableList(new ArrayList<String>(newSecondaryGroups));
        }

        computeString();
    }

    /**
     * Gets the login name for the account.
     * 
     * @return login name for the account
     */
    public String getLoginName() {
        return loginName;
    }

    /**
     * Gets the primary group for this account.
     * 
     * @return primary group for this account
     */
    public String getPrimaryGroup() {
        return primaryGroup;
    }

    /**
     * Gets the secondary groups for this account.
     * 
     * @return secondary groups for this account, never null
     */
    public List<String> getSecondaryGroups() {
        return secondaryGroups;
    }

    /** {@inheritDoc} */
    public int hashCode() {
        int hash = 13;
        hash = 31 * hash + loginName.hashCode();
        hash = 31 * hash + primaryGroup.hashCode();
        hash = 31 * hash + secondaryGroups.hashCode();
        return hash;
    }

    /** {@inheritDoc} */
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }

        if (obj == this) {
            return true;
        }

        if (obj instanceof PosixAccount) {
            PosixAccount other = (PosixAccount) obj;
            return loginName.equals(other.loginName) && primaryGroup.equals(other.primaryGroup)
                    && secondaryGroups.equals(other.secondaryGroups);
        }

        return false;
    }

    /** {@inheritDoc} */
    public String toString() {
        return stringRepresentation;
    }

    /** Computes a string representation of this object. */
    private void computeString() {
        StringBuilder string = new StringBuilder("PosixAccount");
        string.append("{");
        string.append("name:").append(loginName).append(", ");
        string.append("primary group:").append(primaryGroup).append(", ");
        string.append("secondary groups:").append(secondaryGroups);
        string.append("}");
        stringRepresentation = string.toString();
    }
}
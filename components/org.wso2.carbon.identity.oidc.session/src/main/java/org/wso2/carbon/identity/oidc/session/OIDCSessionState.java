/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oidc.session;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

/**
 * This class holds OIDC session state information
 */
public class OIDCSessionState implements Serializable {

    private static final long serialVersionUID = -4439512201699017446L;

    private String authenticatedUser;
    private Set<String> sessionParticipants = new HashSet<>();
    private boolean isAuthenticated;
    private boolean addSessionState;
    private String sidClaim;

    /**
     * Returns authenticated user identifier
     *
     * @return authenticated user
     */
    public String getAuthenticatedUser() {
        return authenticatedUser;
    }

    /**
     * Sets authenticated user identifier
     *
     * @param authenticatedUser
     */
    public void setAuthenticatedUser(String authenticatedUser) {
        this.authenticatedUser = authenticatedUser;
    }

    /**
     * Returns a set of client ids authenticated to the user who participates in the same session
     *
     * @return a set of client ids
     */
    public Set<String> getSessionParticipants() {
        return sessionParticipants;
    }

    /**
     * Sets the client ids authenticated to the user who participates in the same session
     *
     * @param sessionParticipants
     */
    public void setSessionParticipants(Set<String> sessionParticipants) {
        this.sessionParticipants = sessionParticipants;
    }

    /**
     * Adds a client id of an application authenticated to the user who participates in the same session
     *
     * @param clientId client id of the application
     * @return true if successfully added and false if not added and is being duplicated
     */
    public boolean addSessionParticipant(String clientId) {
        return sessionParticipants.add(clientId);
    }

    /**
     * Returns the status of authenticated flag
     *
     * @return authenticated flag
     */
    public boolean isAuthenticated() {
        return isAuthenticated;
    }

    /**
     * Sets authenticated flag
     *
     * @param isAuthenticated
     */
    public void setAuthenticated(boolean isAuthenticated) {
        this.isAuthenticated = isAuthenticated;
    }

    /**
     * Returns the status of add session state flag
     *
     * @return add session state flag
     */
    public boolean isAddSessionState() {
        return addSessionState;
    }

    /**
     * Sets add session state flag. When this flag is set session_state parameter is returned in the OIDC
     * authentication response.
     *
     * @param addSessionState
     */
    public void setAddSessionState(boolean addSessionState) {
        this.addSessionState = addSessionState;
    }

    /**
     * Returns sid claim
     *
     * @return sid claim
     */
    public String getSidClaim() {
        return sidClaim;
    }

    /**
     * Sets sid claim
     *
     * @param sidClaim
     */
    public void setSidClaim(String sidClaim) {
        this.sidClaim = sidClaim;
    }
}

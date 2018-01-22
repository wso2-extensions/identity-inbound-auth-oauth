/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.bean;

import org.wso2.carbon.identity.core.bean.context.MessageContext;

import java.util.ArrayList;
import java.util.List;

/**
 * The object which will contain context information which are passed through OAuth2 client authentication process.
 * All information related to client authentication will be avaialble in this context including the authentication
 * status, authenticated client information and errors.
 */
public class OAuthClientAuthnContext extends MessageContext {

    private String clientId;
    private boolean isAuthenticated;
    private List<String> executedAuthenticators = new ArrayList<String>();
    private String errorMessage;
    private String errorCode;

    /**
     * Get authenticated client id.
     *
     * @return Authenticated client id.
     */
    public String getClientId() {

        return clientId;
    }

    /**
     * Set authenticated client id.
     *
     * @param clientId Authenticated client id.
     */
    public void setClientId(String clientId) {

        this.clientId = clientId;
    }

    /**
     * Get authentication status of the client.
     *
     * @return Authentication status of client.
     */
    public boolean isAuthenticated() {

        return isAuthenticated;
    }

    /**
     * Set authentication status of client.
     *
     * @param authenticated Whether the client is authenticated or not.
     */
    public void setAuthenticated(boolean authenticated) {

        isAuthenticated = authenticated;
    }

    /**
     * Get the list of executed authenticators for a particular request.
     *
     * @return List of authenticators.
     */
    public List getExecutedAuthenticators() {

        return executedAuthenticators;
    }

    /**
     * Get error message.
     *
     * @return Error message.
     */
    public String getErrorMessage() {

        return errorMessage;
    }

    /**
     * Set error message.
     *
     * @param errorMessage Error message.
     */
    public void setErrorMessage(String errorMessage) {

        this.errorMessage = errorMessage;
    }

    /**
     * Get error code.
     *
     * @return error code.
     */
    public String getErrorCode() {

        return errorCode;
    }

    /**
     * Set error code.
     *
     * @param errorCode Error code.
     */
    public void setErrorCode(String errorCode) {

        this.errorCode = errorCode;
    }

    /**
     * Add an authenticator.
     *
     * @param authenticatorName Authenticator name.
     */
    public void addAuthenticator(String authenticatorName) {

        this.executedAuthenticators.add(authenticatorName);
    }

    /**
     * Checks whether a previous authenticator is engaged towards this request.
     *
     * @return true if another authenticator is engaged previously. False if not.
     */
    public boolean isPreviousAuthenticatorEngaged() {

        return (this.executedAuthenticators.size() > 0);
    }

    /**
     * Returns whether multiple authenticators were executed or not
     * @return true if multiple authenticators were engaged, else false.
     */
    public boolean isMultipleAuthenticatorsEngaged() {

        return this.executedAuthenticators.size() > 1;
    }
}

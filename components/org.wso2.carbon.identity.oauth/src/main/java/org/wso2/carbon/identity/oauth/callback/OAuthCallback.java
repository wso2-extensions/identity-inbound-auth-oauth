/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.callback;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;

import javax.security.auth.callback.Callback;

/**
 * Represents a Authorization callback which represents an authorization action corresponding
 * to authorizing clients to access resources by a resource owners. This callback is used to check
 * whether the given resource owner is the rightful owner to grant authorization to the client to
 * access the given resource.
 */
public class OAuthCallback implements Callback {
    /**
     * Callback Type
     */
    private OAuthCallbackType callbackType;
    /**
     * Claimed resource owner
     */
    private AuthenticatedUser resourceOwner;
    /**
     * OAuth2 Grant Type
     */
    private String responseType;
    /**
     * OAuth2 grant type
     */
    private String grantType;
    /**
     * OAuth2 grant type
     */
    private org.wso2.carbon.identity.oauth.common.GrantType carbonGrantType;
    /**
     * Client who will be accessing the resource
     */
    private String client;
    /**
     * A set of strings represents the resource + action used in callback req.
     */
    private String[] requestedScope;
    /**
     * A set of strings represents the resource + action used in token req.
     */
    private String[] approvedScope;
    /**
     * Whether the callback is authorized
     */
    private boolean authorized;
    /**
     * Requested scope is invalid.
     */
    private boolean validScope;
    /**
     * validity period for
     */
    private long validityPeriod = OAuthConstants.UNASSIGNED_VALIDITY_PERIOD;
    /**
     * validity period for OAuthorization Code
     */
    private long authorizationCodeValidityPeriod = OAuthConstants.UNASSIGNED_VALIDITY_PERIOD;
    /**
     * validity period for Access Token
     */
    private long accessTokenValidityPeriod = OAuthConstants.UNASSIGNED_VALIDITY_PERIOD;

    /**
     * Creates an instance of the OAuthCallback
     *
     * @param resourceOwner Claimed resource owner
     * @param client        Client who will be accessing the resource
     * @param callbackType  the callback type
     */
    public OAuthCallback(AuthenticatedUser resourceOwner,
                         String client,
                         OAuthCallbackType callbackType) {
        this.resourceOwner = resourceOwner;
        this.client = client;
        this.callbackType = callbackType;
    }

    /**
     * Get the resource owner
     *
     * @return Identifier of the Resource Owner
     */
    public AuthenticatedUser getResourceOwner() {
        return resourceOwner;
    }

    /**
     * Returns the Client
     *
     * @return Identifier of the Resource Owner
     */
    public String getClient() {
        return client;
    }

    /**
     * Returns the callback type
     *
     * @return <Code>OAuthCallbackType</Code> of the callback type
     */
    public OAuthCallbackType getCallbackType() {
        return callbackType;
    }

    /**
     * Returns the Scope corresponding to the Authz Request
     *
     * @return <Code>String</Code> array representing the scope
     */
    public String[] getRequestedScope() {
        return requestedScope;
    }

    /**
     * Set the scope for callback request
     *
     * @param requestedScope <Code>String</Code> array representing the scope
     */
    public void setRequestedScope(String[] requestedScope) {
        this.requestedScope = requestedScope;
    }

    /**
     * Returns the Scope corresponding to the token Request
     *
     * @return <Code>String</Code> array representing the scope
     */
    public String[] getApprovedScope() {
        return approvedScope;
    }

    /**
     * Set the scope for token request
     *
     * @param approvedScope <Code>String</Code> array representing the scope
     */
    public void setApprovedScope(String[] approvedScope) {
        this.approvedScope = approvedScope;
    }

    /**
     * Returns the OAuth2 Grant Type
     *
     * @return
     */
    public String getResponseType() {
        return responseType;
    }

    /**
     * Sets the response type
     *
     * @param responseType
     */
    public void setResponseType(String responseType) {
        this.responseType = responseType;
    }

    /**
     * Whether the callback is authorized or not
     *
     * @return <Code>true</Code> if the callback is authorized, <code>false</code> otherwise.
     */
    public boolean isAuthorized() {
        return authorized;
    }

    /**
     * Set whether the callback is authorized or not.
     *
     * @param authorized <Code>true</Code> if callback is authorized, <code>false</code> otherwise.
     */
    public void setAuthorized(boolean authorized) {
        this.authorized = authorized;
    }

    /**
     * Whether the requested scope is invalid.
     *
     * @return <Code>true</Code> if scope is invalid, <code>false</code> otherwise.
     */
    public boolean isValidScope() {
        return validScope;
    }

    /**
     * set whether the scope is invalid or not
     *
     * @param invalidScope <code>true</code> if scope is invalid.
     */
    public void setValidScope(boolean invalidScope) {
        this.validScope = invalidScope;
    }

    /**
     * Returns the grant type
     *
     * @return Corresponding <Code>GrantType</Code> of the access token request
     */
    public String getGrantType() {
        return grantType;
    }

    /**
     * Set the Grant Type
     *
     * @param grantType Corresponding <Code>GrantType</Code> of the access token request
     */
    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    public org.wso2.carbon.identity.oauth.common.GrantType getCarbonGrantType() {
        return carbonGrantType;
    }

    public void setCarbonGrantType(org.wso2.carbon.identity.oauth.common.GrantType carbonGrantType) {
        this.carbonGrantType = carbonGrantType;
    }

    /**
     * Get the validity period
     *
     * @return validity period of the next token when applicable
     */
    public long getValidityPeriod() {
        return validityPeriod;
    }

    /**
     * Set the validity period
     *
     * @return validity period of the next token when applicable
     */
    public void setValidityPeriod(long validityPeriod) {
        this.validityPeriod = validityPeriod;
    }

    /**
     * Get the validity period
     *
     * @return validity period of the Authorization Code when applicable
     */
    public long getAuthorizationCodeValidityPeriod() {
        return authorizationCodeValidityPeriod;
    }
    /**
     * Set Authorization Code validity period
     *
     */
    public void setAuthorizationCodeValidityPeriod(long oauthoizationCodeValidityPeriod) {
        this.authorizationCodeValidityPeriod = oauthoizationCodeValidityPeriod;
    }
    /**
     * Get the validity period
     *
     * @return validity period of the Access Token when applicable
     */
    public long getAccessTokenValidityPeriod() {
        return accessTokenValidityPeriod;
    }
    /**
     * Set AccessToken validity period
     *
     */
    public void setAccessTokenValidityPeriod(long accessTokenValidityPeriod) {
        this.accessTokenValidityPeriod = accessTokenValidityPeriod;
    }

    /**
     * Used to evaluate the type of the callback
     */
    public enum OAuthCallbackType {
        ACCESS_DELEGATION_AUTHZ,
        SCOPE_VALIDATION_AUTHZ,
        ACCESS_DELEGATION_TOKEN,
        SCOPE_VALIDATION_TOKEN
    }
}

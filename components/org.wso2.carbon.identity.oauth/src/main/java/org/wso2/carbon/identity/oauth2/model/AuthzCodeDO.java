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

package org.wso2.carbon.identity.oauth2.model;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;

import java.sql.Timestamp;

/**
 * Results holder for Authz Code validation query
 */
public class AuthzCodeDO extends CacheEntry {

    private static final long serialVersionUID = 3308401412530535040L;

    private AuthenticatedUser authorizedUser;

    private String[] scope;

    private Timestamp issuedTime;

    private long validityPeriod;

    private String callbackUrl;

    private String consumerKey;

    private String authorizationCode;

    private String oauthTokenId;

    private String authzCodeId;

    private String state;

    private String pkceCodeChallenge;

    private String pkceCodeChallengeMethod;

    private String tokenBindingReference;

    public AuthzCodeDO(AuthenticatedUser authorizedUser, String[] scope, Timestamp issuedTime, long validityPeriod, String
            callbackUrl, String consumerKey, String authorizationCode, String authzCodeId) {
        this.authorizedUser = authorizedUser;
        this.scope = scope;
        this.issuedTime = issuedTime;
        this.validityPeriod = validityPeriod;
        this.callbackUrl = callbackUrl;
        this.consumerKey = consumerKey;
        this.authorizationCode = authorizationCode;
        this.authzCodeId = authzCodeId;
    }

    public AuthzCodeDO(AuthenticatedUser authorizedUser, String[] scope, Timestamp issuedTime, long validityPeriod, String
            callbackUrl, String consumerKey, String authorizationCode, String authzCodeId, String state) {
        this.authorizedUser = authorizedUser;
        this.scope = scope;
        this.issuedTime = issuedTime;
        this.validityPeriod = validityPeriod;
        this.callbackUrl = callbackUrl;
        this.consumerKey = consumerKey;
        this.authorizationCode = authorizationCode;
        this.authzCodeId = authzCodeId;
        this.state = state;
    }

    public AuthzCodeDO(AuthenticatedUser authorizedUser, String[] scope, Timestamp issuedTime, long validityPeriod, String
            callbackUrl, String consumerKey, String authorizationCode, String authzCodeId, String pkceCodeChallenge, String pkceCodeChallengeMethod) {
        this(authorizedUser, scope, issuedTime, validityPeriod, callbackUrl, consumerKey,authorizationCode,authzCodeId);
        this.pkceCodeChallenge = pkceCodeChallenge;
        this.pkceCodeChallengeMethod = pkceCodeChallengeMethod;
    }

    public AuthzCodeDO(AuthenticatedUser authorizedUser, String[] scope, Timestamp issuedTime, long validityPeriod, String
            callbackUrl, String consumerKey, String authorizationCode, String authzCodeId, String state, String pkceCodeChallenge, String pkceCodeChallengeMethod) {
        this(authorizedUser, scope, issuedTime, validityPeriod, callbackUrl, consumerKey,authorizationCode,authzCodeId, state);
        this.pkceCodeChallenge = pkceCodeChallenge;
        this.pkceCodeChallengeMethod = pkceCodeChallengeMethod;
    }

    public AuthzCodeDO(AuthenticatedUser authorizedUser, String[] scope, Timestamp issuedTime, long validityPeriod,
            String callbackUrl, String consumerKey, String authorizationCode, String authzCodeId, String state,
            String pkceCodeChallenge, String pkceCodeChallengeMethod, String tokenBindingReference) {

        this(authorizedUser, scope, issuedTime, validityPeriod, callbackUrl, consumerKey, authorizationCode,
                authzCodeId, state, pkceCodeChallenge, pkceCodeChallengeMethod);
        this.tokenBindingReference = tokenBindingReference;
    }

    public AuthzCodeDO() {
    }

    public AuthenticatedUser getAuthorizedUser() {
        return authorizedUser;
    }

    public String[] getScope() {
        return scope;
    }

    public Timestamp getIssuedTime() {
        return issuedTime;
    }

    public long getValidityPeriod() {
        return validityPeriod;
    }

    public String getCallbackUrl() {
        return callbackUrl;
    }

    public String getConsumerKey() {
        return consumerKey;
    }

    public String getAuthorizationCode() {
        return authorizationCode;
    }

    public String getOauthTokenId() {
        return oauthTokenId;
    }

    public void setOauthTokenId(String oauthTokenId) {
        this.oauthTokenId = oauthTokenId;
    }

    public String getAuthzCodeId() {
        return authzCodeId;
    }

    public void setAuthzCodeId(String authzCodeId) {
        this.authzCodeId = authzCodeId;
    }

    public void setAuthorizationCode(String authorizationCode) {
        this.authorizationCode = authorizationCode;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getPkceCodeChallenge() {
        return pkceCodeChallenge;
    }

    public void setPkceCodeChallenge(String pkceCodeChallenge) {
        this.pkceCodeChallenge = pkceCodeChallenge;
    }

    public String getPkceCodeChallengeMethod() {
        return pkceCodeChallengeMethod;
    }

    public void setPkceCodeChallengeMethod(String pkceCodeChallengeMethod) {
        this.pkceCodeChallengeMethod = pkceCodeChallengeMethod;
    }

    public String getTokenBindingReference() {

        return tokenBindingReference;
    }

    public void setTokenBindingReference(String tokenBindingReference) {

        this.tokenBindingReference = tokenBindingReference;
    }
}

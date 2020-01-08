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

package org.wso2.carbon.identity.oauth;

import java.net.URLDecoder;

/**
 * Parameters for OAuth service.
 */
public class Parameters {

    // oauth_signature
    private String oauthSignature = null;
    // oauth_nonce
    private String oauthNonce = null;
    // oauth_signature_method = HMAC-SHA1
    private String oauthSignatureMethod = null;
    // oauth_consumer_key
    private String oauthConsumerKey = null;
    // oauth_timestamp
    private String oauthTimeStamp = null;
    private String baseString = null;
    private String httpMethod = null;
    private String oauthCallback = null;
    private String scope = null;
    private String displayName = null;
    private String oauthToken = null;
    private String oauthTokenSecret = null;
    private String callbackConfirmed = null;
    private String authorizedbyUserName = null;
    private String authorizedbyUserPassword = null;
    private String oauthTokenVerifier = null;
    private String appName = null;
    private String version = null;
    private boolean accessTokenIssued;

    public boolean isAccessTokenIssued() {
        return accessTokenIssued;
    }

    public void setAccessTokenIssued(boolean accessTokenIssued) {
        this.accessTokenIssued = accessTokenIssued;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getAppName() {
        return appName;
    }

    public void setAppName(String appName) {
        this.appName = appName;
    }

    public String getOauthTokenVerifier() {
        return oauthTokenVerifier;
    }

    public void setOauthTokenVerifier(String oauthTokenVerifier) {
        this.oauthTokenVerifier = oauthTokenVerifier;
    }

    public String getAuthorizedbyUserPassword() {
        return authorizedbyUserPassword;
    }

    public void setAuthorizedbyUserPassword(String authorizedbyUserPassword) {
        this.authorizedbyUserPassword = authorizedbyUserPassword;
    }

    public String getAuthorizedbyUserName() {
        return authorizedbyUserName;
    }

    public void setAuthorizedbyUserName(String authorizedbyUserName) {
        this.authorizedbyUserName = authorizedbyUserName;
    }

    public String getOauthTokenSecret() {
        return oauthTokenSecret;
    }

    public void setOauthTokenSecret(String oauthTokenSecret) {
        this.oauthTokenSecret = oauthTokenSecret;
    }

    public String getCallbackConfirmed() {
        return callbackConfirmed;
    }

    public void setCallbackConfirmed(String callbackConfirmed) {
        this.callbackConfirmed = callbackConfirmed;
    }

    public String getOauthToken() {
        return oauthToken;
    }

    public void setOauthToken(String oauthToken) {
        this.oauthToken = oauthToken;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getOauthCallback() {
        return oauthCallback;
    }

    public void setOauthCallback(String oauthCallback) {
        this.oauthCallback = oauthCallback;
    }

    public String getBaseString() {
        return baseString;
    }

    public void setBaseString(String baseString) {
        this.baseString = baseString;
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    public void setHttpMethod(String httpMethod) {
        this.httpMethod = httpMethod;
    }

    public String getOauthSignature() {
        return oauthSignature;
    }

    public void setOauthSignature(String oauthSignature) {
        this.oauthSignature = oauthSignature;
    }

    public String getOauthNonce() {
        return oauthNonce;
    }

    public void setOauthNonce(String oauthNonce) {
        this.oauthNonce = oauthNonce;
    }

    public String getOauthSignatureMethod() {
        return oauthSignatureMethod;
    }

    public void setOauthSignatureMethod(String oauthSignatureMethod) {
        this.oauthSignatureMethod = oauthSignatureMethod;
    }

    public String getOauthConsumerKey() {
        if (oauthConsumerKey != null) {
            return URLDecoder.decode(oauthConsumerKey);
        } else {
            return oauthConsumerKey;
        }
    }

    public void setOauthConsumerKey(String oauthConsumerKey) {
        this.oauthConsumerKey = oauthConsumerKey;
    }

    public String getOauthTimeStamp() {
        return oauthTimeStamp;
    }

    public void setOauthTimeStamp(String oauthTimeStamp) {
        this.oauthTimeStamp = oauthTimeStamp;
    }
}

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

package org.wso2.carbon.identity.oauth.dto;

public class OAuthConsumerAppDTO {

    private String oauthConsumerKey;
    private String oauthConsumerSecret;
    private String applicationName;
    private String callbackUrl;
    private String oauthVersion;
    private String username;
    private String grantTypes = "";
    private boolean pkceSupportPlain;
    private boolean pkceMandatory;
    private boolean tbMandatory;
    private String state;
    private long userAccessTokenExpiryTime;
    private long applicationAccessTokenExpiryTime;
    private long refreshTokenExpiryTime;

    public boolean getTbMandatory() {
        return tbMandatory;
    }

    public void setTbMandatory(boolean tbMandatory) {
        this.tbMandatory = tbMandatory;
    }

    public long getUserAccessTokenExpiryTime() {
        return userAccessTokenExpiryTime;
    }

    public void setUserAccessTokenExpiryTime(long userAccessTokenExpiryTime) {
        this.userAccessTokenExpiryTime = userAccessTokenExpiryTime;
    }

    public long getApplicationAccessTokenExpiryTime() {
        return applicationAccessTokenExpiryTime;
    }

    public void setApplicationAccessTokenExpiryTime(long applicationAccessTokenExpiryTime) {
        this.applicationAccessTokenExpiryTime = applicationAccessTokenExpiryTime;
    }

    public long getRefreshTokenExpiryTime() {
        return refreshTokenExpiryTime;
    }

    public void setRefreshTokenExpiryTime(long refreshTokenExpiryTime) {
        this.refreshTokenExpiryTime = refreshTokenExpiryTime;
    }

    public String getApplicationName() {
        return applicationName;
    }

    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName;
    }

    public String getCallbackUrl() {
        return callbackUrl;
    }

    public void setCallbackUrl(String callbackUrl) {
        this.callbackUrl = callbackUrl;
    }

    public String getOauthConsumerKey() {
        return oauthConsumerKey;
    }

    public void setOauthConsumerKey(String oauthConsumerKey) {
        this.oauthConsumerKey = oauthConsumerKey;
    }

    public String getOauthConsumerSecret() {
        return oauthConsumerSecret;
    }

    public void setOauthConsumerSecret(String oauthConsumerSecret) {
        this.oauthConsumerSecret = oauthConsumerSecret;
    }

    public String getOAuthVersion() {
        return oauthVersion;
    }

    public void setOAuthVersion(String oAuthVersion) {
        this.oauthVersion = oAuthVersion;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getGrantTypes() {
        return grantTypes;
    }

    public void setGrantTypes(String grantTypes) {
        if(grantTypes != null) {
            this.grantTypes = grantTypes;
        }
    }

    public boolean getPkceSupportPlain() {
        return pkceSupportPlain;
    }

    public void setPkceSupportPlain(boolean pkceSupportPlain) {
        this.pkceSupportPlain = pkceSupportPlain;
    }

    public boolean getPkceMandatory() {
        return pkceMandatory;
    }

    public void setPkceMandatory(boolean pkceMandatory) {
        this.pkceMandatory = pkceMandatory;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getState() {
        return state;
    }
}


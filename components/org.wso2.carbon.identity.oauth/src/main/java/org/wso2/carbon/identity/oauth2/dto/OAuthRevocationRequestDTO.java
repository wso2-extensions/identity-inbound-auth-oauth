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

package org.wso2.carbon.identity.oauth2.dto;

import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;

public class OAuthRevocationRequestDTO {

    private String token;

    private String consumerKey;

    private String consumerSecret;

    private String authzUser;

    private String tokenType;

    private OAuthClientAuthnContext oAuthClientAuthnContext;

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getConsumerKey() {
        return consumerKey;
    }

    public void setConsumerKey(String consumerKey) {
        this.consumerKey = consumerKey;
    }

    public String getConsumerSecret() {
        return consumerSecret;
    }

    public void setConsumerSecret(String consumerSecret) {
        this.consumerSecret = consumerSecret;
    }

    public String getAuthzUser() {
        return authzUser;
    }

    public void setAuthzUser(String authzUser) {
        this.authzUser = authzUser;
    }

    @Deprecated
    public String getToken_type() {
        return getTokenType();
    }

    @Deprecated
    public void setToken_type(String tokenType) {
        setTokenType(tokenType);
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public String getTokenType() {
        return tokenType;
    }

    public OAuthClientAuthnContext getoAuthClientAuthnContext() {
        return oAuthClientAuthnContext;
    }

    public void setOauthClientAuthnContext(OAuthClientAuthnContext oAuthClientAuthnContext) {
        this.oAuthClientAuthnContext = oAuthClientAuthnContext;
    }

}
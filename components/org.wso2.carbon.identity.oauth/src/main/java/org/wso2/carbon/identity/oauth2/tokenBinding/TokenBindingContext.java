/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.oauth2.tokenBinding;

import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

/**
 * This class contains the output values of Token binding Handler.
 */
public class TokenBindingContext {

    private String tokenBindingHash;
    private boolean tokenBindingValidation;
    private String tokenBindingType;
    private String normalToken;
    private boolean tokenBindingSupportEnabled;

    public boolean isTokenBindingSupportEnabled() {
        return tokenBindingSupportEnabled;
    }

    public void setTokenBindingSupportEnabled(boolean tokenBindingSupportEnabled) {
        this.tokenBindingSupportEnabled = tokenBindingSupportEnabled;
    }

    public boolean isTokenBindingSupportExists() {
        return tokenBindingSupportExists;
    }

    public void setTokenBindingSupportExists(boolean tokenBindingSupportExists) {
        this.tokenBindingSupportExists = tokenBindingSupportExists;
    }

    private boolean tokenBindingSupportExists;

    public String getNormalToken() {
        return normalToken;
    }

    public void setNormalToken(String normalToken) {
        this.normalToken = normalToken;
    }

    public String getTokenBindingType() {
        return tokenBindingType;
    }

    public void setTokenBindingType(String tokenBindingType) {
        this.tokenBindingType = tokenBindingType;
    }

    public OAuthTokenReqMessageContext getTokReqMsgCtx() {
        return tokReqMsgCtx;
    }

    public void setTokReqMsgCtx(OAuthTokenReqMessageContext tokReqMsgCtx) {
        this.tokReqMsgCtx = tokReqMsgCtx;
    }

    public OAuthAuthzReqMessageContext getOauthAuthzMsgCtx() {
        return oauthAuthzMsgCtx;
    }

    public void setOauthAuthzMsgCtx(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) {
        this.oauthAuthzMsgCtx = oauthAuthzMsgCtx;
    }

    private OAuthTokenReqMessageContext tokReqMsgCtx;
    private OAuthAuthzReqMessageContext oauthAuthzMsgCtx;
    private String delimiter;
    private String boundToken;

    public String getBoundToken() {
        return boundToken;
    }

    public String getTokenBindingHash() {
        return tokenBindingHash;
    }

    public boolean isTokenBindingValidation() {
        return tokenBindingValidation;
    }

    public void setTokenBindingValidation(boolean tokenBindingValidation) {
        this.tokenBindingValidation = tokenBindingValidation;
    }

    public String getDelimiter() {
        return delimiter;
    }

    public void setDelimiter(String delimiter) {
        this.delimiter = delimiter;
    }

    public void setTokenBindingHash(String tokenBindingHash) {
        this.tokenBindingHash = tokenBindingHash;
    }

    public void setBoundToken(String boundToken) {
        this.boundToken = boundToken;
    }
}

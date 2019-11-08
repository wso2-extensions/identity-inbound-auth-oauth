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

import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;

/**
 * Results holder for bearer token validation query
 */
public class OAuth2TokenValidationResponseDTO {

    private String authorizedUser;

    private long expiryTime;

    private String[] scope;

    private boolean valid;

    private String errorMsg;

    private TokenBinding tokenBinding;

    private AuthorizationContextToken authorizationContextToken;

    public AuthorizationContextToken getAuthorizationContextToken() {
        return authorizationContextToken;
    }

    public void setAuthorizationContextToken(AuthorizationContextToken authorizationContextToken) {
        this.authorizationContextToken = authorizationContextToken;
    }

    public String getAuthorizedUser() {
        return authorizedUser;
    }

    public void setAuthorizedUser(String authorizedUser) {
        this.authorizedUser = authorizedUser;
    }

    public long getExpiryTime() {
        return expiryTime;
    }

    public void setExpiryTime(long expiryTime) {
        this.expiryTime = expiryTime;
    }

    public String[] getScope() {
        return scope;
    }

    public void setScope(String[] scope) {
        this.scope = scope;
    }

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public String getErrorMsg() {
        return errorMsg;
    }

    public void setErrorMsg(String errorMsg) {
        this.errorMsg = errorMsg;
    }

    public TokenBinding getTokenBinding() {

        return tokenBinding;
    }

    public void setTokenBinding(TokenBinding tokenBinding) {

        this.tokenBinding = tokenBinding;
    }

    public class AuthorizationContextToken {

        String tokenType;

        String tokenString;

        public AuthorizationContextToken(String tokenType, String tokenString) {
            this.tokenType = tokenType;
            this.tokenString = tokenString;
        }

        public String getTokenType() {
            return tokenType;
        }

        public String getTokenString() {
            return tokenString;
        }
    }
}

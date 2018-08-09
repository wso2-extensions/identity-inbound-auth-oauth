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

public class OAuth2TokenValidationRequestDTO {

    private OAuth2AccessToken accessToken;

    private TokenValidationContextParam[] context;

    /**
     * User's claims to be encoded in the AuthorizationContextToken returned in the OAuth2TokenValidationResponse
     */
    private String[] requiredClaimURIs;

    public TokenValidationContextParam[] getContext() {
        return context;
    }

    public void setContext(TokenValidationContextParam[] context) {
        this.context = context;
    }

    public OAuth2AccessToken getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(OAuth2AccessToken accessToken) {
        this.accessToken = accessToken;
    }

    public String[] getRequiredClaimURIs() {
        return requiredClaimURIs;
    }

    public void setRequiredClaimURIs(String[] requiredClaimURIs) {
        this.requiredClaimURIs = requiredClaimURIs;
    }

    public class TokenValidationContextParam {

        private String key;

        private String value;

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }

        public String getKey() {
            return key;
        }

        public void setKey(String key) {
            this.key = key;
        }
    }

    public class OAuth2AccessToken {

        private String tokenType;

        private String identifier;

        private String issuer;

        public String getTokenType() {
            return tokenType;
        }

        public void setTokenType(String tokenType) {
            this.tokenType = tokenType;
        }

        public String getIdentifier() {
            return identifier;
        }

        public void setIdentifier(String identifier) {
            this.identifier = identifier;
        }

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }
    }
}

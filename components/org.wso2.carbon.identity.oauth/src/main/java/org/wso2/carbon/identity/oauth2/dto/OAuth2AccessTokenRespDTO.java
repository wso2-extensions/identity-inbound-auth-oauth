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

import org.wso2.carbon.identity.oauth2.ResponseHeader;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class OAuth2AccessTokenRespDTO {
    String tokenType;
    String accessToken;
    String tokenId;
    String refreshToken;
    String callbackURI;
    boolean error;
    String errorCode;
    String errorMsg;
    long expiresIn;
    long expiresInMillis;
    ResponseHeader[] responseHeaders;
    String authorizedScopes;
    private String idToken;
    private Map<String, String> parameters;

    public ResponseHeader[] getResponseHeaders() {
        if (responseHeaders == null) {
            return new ResponseHeader[0];
        }
        return responseHeaders;
    }

    public void setResponseHeaders(ResponseHeader[] responseHeaders) {
        this.responseHeaders = responseHeaders;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getCallbackURI() {
        return callbackURI;
    }

    public void setCallbackURI(String callbackURI) {
        this.callbackURI = callbackURI;
    }

    public boolean isError() {
        return error;
    }

    public void setError(boolean error) {
        this.error = error;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }

    public String getErrorMsg() {
        return errorMsg;
    }

    public void setErrorMsg(String errorMsg) {
        this.errorMsg = errorMsg;
    }

    public long getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(long expiresIn) {
        this.expiresIn = expiresIn;
    }

    public long getExpiresInMillis() {
        return expiresInMillis;
    }

    public void setExpiresInMillis(long expiresInMillis) {
        this.expiresInMillis = expiresInMillis;
    }

    /**
     * @return the idToken
     */
    public String getIDToken() {
        return idToken;
    }

    /**
     * @param idToken the idToken to set
     */
    public void setIDToken(String idToken) {
        this.idToken = idToken;
    }

    public String getAuthorizedScopes() {
        return authorizedScopes;
    }

    public void setAuthorizedScopes(String authorizedScopes) {
        this.authorizedScopes = authorizedScopes;
    }

    public String getTokenId() {
        return tokenId;
    }

    public void setTokenId(String tokenId) {
        this.tokenId = tokenId;
    }

    /**
     * Add a custom parameter to the OAuth2 token response.
     *
     * @param key   parameter key
     * @param value parameter value
     */
    public void addParameter(String key, String value) {

        getParameterMap().put(key, value);
    }

    /**
     * Get the custom parameter value associated to the key.
     *
     * @param key parameter key
     * @return value associated with the key
     */
    public String getParameter(String key) {

        return getParameterMap().get(key);
    }

    /**
     * Get all custom parameters.
     *
     * @return a key value map of all custom parameters
     */
    public Map<String, String> getParameters() {

        return Collections.unmodifiableMap(getParameterMap());
    }

    private Map<String, String> getParameterMap() {

        if (parameters == null) {
            parameters = new HashMap<>();
        }
        return parameters;
    }
}

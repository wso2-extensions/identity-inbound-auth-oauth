/**
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com). All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.par.model;

/**
 * Captures the values for authorization request.
 */
public class ParAuthCodeResponse {

    private String authReqId = "authReqId"; // Authentication request identifier.
    private String clientId;
    private String callBackUrl;
    private String responseType;
    private String[] scopes;
    private String state;
    private String codeExchangerType;
    private String codeChallengeMethod;
    private long expiresIn = 60;
    private String requestUri;

    public String getAuthReqId() {
        return authReqId;
    }

    public String getClientId() {
        return clientId;
    }

    public String getCallBackUrl() {
        return callBackUrl;
    }

    public String getResponseType() {
        return responseType;
    }

    public String[] getScopes() {
        return scopes;
    }

    public String getState() {
        return state;
    }

    public String getCodeExchangerType() {
        return codeExchangerType;
    }

    public String getCodeChallengeMethod() {
        return codeChallengeMethod;
    }

    public long getExpiresIn() {
        return expiresIn;
    }

    public String getRequestUri() {
        return requestUri;
    }

    public void setAuthReqId(String authReqId) {
        this.authReqId = authReqId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public void setCallBackUrl(String callBackUrl) {
        this.callBackUrl = callBackUrl;
    }

    public void setResponseType(String responseType) {
        this.responseType = responseType;
    }

    public void setScopes(String[] scopes) {
        this.scopes = scopes;
    }

    public void setState(String state) {
        this.state = state;
    }

    public void setCodeExchangerType(String codeExchangerType) {
        this.codeExchangerType = codeExchangerType;
    }

    public void setCodeChallengeMethod(String codeChallengeMethod) {
        this.codeChallengeMethod = codeChallengeMethod;
    }

    public void setExpiresIn(long expiresIn) {
        this.expiresIn = expiresIn;
    }

    public void setRequestUri(String requestUri) {
        this.requestUri = requestUri;
    }
}

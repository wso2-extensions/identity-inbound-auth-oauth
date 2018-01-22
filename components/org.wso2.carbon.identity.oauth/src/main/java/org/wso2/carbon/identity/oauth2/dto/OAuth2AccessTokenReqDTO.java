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
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class OAuth2AccessTokenReqDTO {
    private String clientId;
    private String clientSecret;
    private String grantType;
    private String[] scope;
    private String authorizationCode;
    private String callbackURI;
    private String resourceOwnerUsername;
    private String resourceOwnerPassword;
    private String refreshToken;
    private String assertion;
    private String clientAssertionType;
    private String clientAssertion;
    private String tenantDomain;
    private String windows_token;
    private String pkceCodeVerifier;
    private RequestParameter[] requestParameters;
    private HttpRequestHeader[] httpRequestHeaders;
    private List<String> authenticationMethodReferences = new ArrayList<>();
    private OAuthClientAuthnContext oAuthClientAuthnContext;

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    public String getAuthorizationCode() {
        return authorizationCode;
    }

    public void setAuthorizationCode(String authorizationCode) {
        this.authorizationCode = authorizationCode;
    }

    public String getCallbackURI() {
        return callbackURI;
    }

    public void setCallbackURI(String callbackURI) {
        this.callbackURI = callbackURI;
    }

    public String getResourceOwnerUsername() {
        return resourceOwnerUsername;
    }

    public void setResourceOwnerUsername(String resourceOwnerUsername) {
        this.resourceOwnerUsername = resourceOwnerUsername;
    }

    public String getResourceOwnerPassword() {
        return resourceOwnerPassword;
    }

    public void setResourceOwnerPassword(String resourceOwnerPassword) {
        this.resourceOwnerPassword = resourceOwnerPassword;
    }

    public String[] getScope() {
        return scope;
    }

    public void setScope(String[] scope) {
        this.scope = scope;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getAssertion() {
        return assertion;
    }

    public void setAssertion(String assertion) {
        this.assertion = assertion;
    }

    public String getWindowsToken() {
        return windows_token;
    }

    public void setWindowsToken(String windowsToken) {
        this.windows_token = windowsToken;
    }

    public String getClientAssertionType() {
        return clientAssertionType;
    }

    public void setClientAssertionType(String clientAssertionType) {
        this.clientAssertionType = clientAssertionType;
    }

    public String getClientAssertion() {
        return clientAssertion;
    }

    public void setClientAssertion(String clientAssertion) {
        this.clientAssertion = clientAssertion;
    }

    public String getTenantDomain() {
        return tenantDomain;
    }

    public void setTenantDomain(String tenantDomain) {
        this.tenantDomain = tenantDomain;
    }

    public RequestParameter[] getRequestParameters() {
        return requestParameters;
    }

    public void setRequestParameters(RequestParameter[] requestParameters) {
        this.requestParameters = requestParameters;
    }

    public HttpRequestHeader[] getHttpRequestHeaders() {
        return httpRequestHeaders;
    }

    public void setHttpRequestHeaders(HttpRequestHeader[] httpRequestHeaders) {
        this.httpRequestHeaders = httpRequestHeaders;
    }

    public String getPkceCodeVerifier() {
        return pkceCodeVerifier;
    }

    public void setPkceCodeVerifier(String pkceCodeVerifier) {
        this.pkceCodeVerifier = pkceCodeVerifier;
    }

    public void addAuthenticationMethodReference(String reference) {
        authenticationMethodReferences.add(reference);
    }

    public List<String> getAuthenticationMethodReferences() {
        return Collections.unmodifiableList(authenticationMethodReferences);
    }

    public OAuthClientAuthnContext getoAuthClientAuthnContext() {
        return oAuthClientAuthnContext;
    }

    public void setoAuthClientAuthnContext(OAuthClientAuthnContext oAuthClientAuthnContext) {
        this.oAuthClientAuthnContext = oAuthClientAuthnContext;
    }
}

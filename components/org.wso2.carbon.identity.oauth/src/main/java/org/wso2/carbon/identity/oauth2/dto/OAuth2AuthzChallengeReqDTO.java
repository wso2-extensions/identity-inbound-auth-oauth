/*
 * Copyright (c) 2025, WSO2 Inc. (http://www.wso2.org).
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

import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;

import javax.servlet.http.HttpServletRequestWrapper;

public class OAuth2AuthzChallengeReqDTO {

    private String authSession;
    private String clientId;
    private String responseType;
    private String redirectUri;
    private String state;
    private String scope;
    private HttpRequestHeader[] httpRequestHeaders;
    private HttpServletRequestWrapper httpServletRequestWrapper;

    // Getters and Setters
    public String getAuthSession() {

        return authSession;
    }

    public void setAuthSession(String authSession) {

        this.authSession = authSession;
    }

    public String getClientId() {

        return clientId;
    }

    public void setClientId(String clientId) {

        this.clientId = clientId;
    }

    public String getResponseType() {

        return responseType;
    }

    public void setResponseType(String responseType) {

        this.responseType = responseType;
    }

    public String getRedirectUri() {

        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {

        this.redirectUri = redirectUri;
    }

    public String getState() {

        return state;
    }

    public void setState(String state) {

        this.state = state;
    }

    public String getScope() {

        return scope;
    }

    public void setScope(String scope) {

        this.scope = scope;
    }

    public HttpRequestHeader[] getHttpRequestHeaders() {

        return this.httpRequestHeaders;
    }

    public void setHttpRequestHeaders(HttpRequestHeader[] httpRequestHeaders) {

        this.httpRequestHeaders = httpRequestHeaders;
    }

    public HttpServletRequestWrapper getHttpServletRequestWrapper() {

        return this.httpServletRequestWrapper;
    }

    public void setHttpServletRequestWrapper(HttpServletRequestWrapper httpServletRequestWrapper) {

        this.httpServletRequestWrapper = httpServletRequestWrapper;
    }
}

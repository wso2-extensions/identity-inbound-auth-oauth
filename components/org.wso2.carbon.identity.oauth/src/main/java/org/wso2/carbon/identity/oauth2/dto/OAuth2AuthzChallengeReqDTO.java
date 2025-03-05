package org.wso2.carbon.identity.oauth2.dto;

import javax.servlet.http.HttpServletRequestWrapper;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;

public class OAuth2AuthzChallengeReqDTO {
    private String authSession;
    private String clientId;
    private String responseType;
    private String redirectUri;
    private String state;
    private String scope;
    private HttpRequestHeader[] httpRequestHeaders;
    private HttpServletRequestWrapper httpServletRequestWrapper;

    public OAuth2AuthzChallengeReqDTO(){

    }

    // Getters and Setters
    public String getAuthSession() { return authSession; }

    public void setAuthSession(String authSession) { this.authSession = authSession; }

    public String getClientId() { return clientId; }

    public void setClientId(String clientId) { this.clientId = clientId; }

    public String getResponseType() { return responseType; }

    public void setResponseType(String responseType) { this.responseType = responseType; }

    public String getRedirectUri() { return redirectUri; }

    public void setRedirectUri(String redirectUri) { this.redirectUri = redirectUri; }

    public String getState() { return state; }

    public void setState(String state) { this.state = state; }

    public String getScope() { return scope; }

    public void setScope(String scope) { this.scope = scope; }

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

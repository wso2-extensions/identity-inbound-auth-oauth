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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.endpoint.message;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.oauth.cache.SessionDataCache;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheEntry;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.endpoint.authz.OAuthAuthorizeState;
import org.wso2.carbon.identity.oauth.endpoint.authz.OAuthRequestStateValidator;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OAuthMessage {

    private HttpServletRequest request;
    private HttpServletResponse response;
    private Map<String, Object> properties = new HashMap();
    private OAuthAuthorizeState requestType;

    private SessionDataCacheKey cacheKey;
    private SessionDataCacheEntry resultFromLogin = null;
    private SessionDataCacheEntry resultFromConsent = null;
    private SessionDataCacheEntry sessionDataCacheEntry = null;

    private boolean forceAuthenticate = false;
    private boolean isPassiveAuthentication = false;
    String sessionDataKeyFromConsent;

    private OAuthMessage(HttpServletRequest request, HttpServletResponse response) {
        this.request = request;
        this.response = response;

        String sessionDataKeyFromLogin = getSessionDataKey(request);
        sessionDataKeyFromConsent = request.getParameter(OAuthConstants.SESSION_DATA_KEY_CONSENT);

        if (StringUtils.isNotEmpty(sessionDataKeyFromLogin)) {
            cacheKey = new SessionDataCacheKey(sessionDataKeyFromLogin);
            resultFromLogin = SessionDataCache.getInstance().getValueFromCache(cacheKey);
        }
        if (StringUtils.isNotEmpty(sessionDataKeyFromConsent)) {
            cacheKey = new SessionDataCacheKey(sessionDataKeyFromConsent);
            resultFromConsent = SessionDataCache.getInstance().getValueFromCache(cacheKey);
            SessionDataCache.getInstance().clearCacheEntry(cacheKey);
        }

        // if the sessionDataKeyFromConsent parameter present in the login request, skip it and allow login since
        // result from login is there
        if (sessionDataKeyFromConsent != null && resultFromConsent == null && resultFromLogin != null) {
            sessionDataKeyFromConsent = null;
        }
    }

    public Object getProperty(String key) {
        if (properties != null) {
            return properties.get(key);
        } else {
            return null;
        }
    }

    public Map<String, Object> getProperties() {
        return properties;
    }

    public void setProperty(String key, Object value) {
        properties.put(key, value);
    }

    public void removeProperty(String key) {
        properties.remove(key);
    }

    public HttpServletRequest getRequest() {
        return request;
    }

    public HttpServletResponse getResponse() {
        return response;
    }

    public OAuthAuthorizeState getRequestType() {
        return requestType;
    }

    private void setRequestType(OAuthAuthorizeState requestType) {
        this.requestType = requestType;
        if (OAuthAuthorizeState.AUTHENTICATION_RESPONSE.equals(requestType)) {
            setSessionDataCacheEntry(resultFromLogin);
        } else if (OAuthAuthorizeState.USER_CONSENT_RESPONSE.equals(requestType)) {
            setSessionDataCacheEntry(resultFromConsent);
        }
    }

    public String getClientId() {
        return request.getParameter("client_id");
    }

    public String getSessionDataKeyFromLogin() {
        return getSessionDataKey(request);
    }

    public String getSessionDataKeyFromConsent() {
        return sessionDataKeyFromConsent;
    }

    public SessionDataCacheEntry getResultFromLogin() {
        return resultFromLogin;
    }

    public void setResultFromLogin(SessionDataCacheEntry resultFromLogin) {
        this.resultFromLogin = resultFromLogin;
    }

    public SessionDataCacheEntry getResultFromConsent() {
        return resultFromConsent;
    }

    public void setResultFromConsent(SessionDataCacheEntry resultFromConsent) {
        this.resultFromConsent = resultFromConsent;
    }

    public boolean isForceAuthenticate() {
        return forceAuthenticate;
    }

    public void setForceAuthenticate(boolean forceAuthenticate) {
        this.forceAuthenticate = forceAuthenticate;
    }

    public boolean isPassiveAuthentication() {
        return isPassiveAuthentication;
    }

    public void setPassiveAuthentication(boolean passiveAuthentication) {
        this.isPassiveAuthentication = passiveAuthentication;
    }

    public SessionDataCacheEntry getSessionDataCacheEntry() {
        return sessionDataCacheEntry;
    }

    public void setSessionDataCacheEntry(SessionDataCacheEntry sessionDataCacheEntry) {
        this.sessionDataCacheEntry = sessionDataCacheEntry;
    }

    /**
     * In federated and multi steps scenario there is a redirection from commonauth to samlsso so have to get
     * session data key from query parameter
     *
     * @param req Http servlet request
     * @return Session data key
     */
    private String getSessionDataKey(HttpServletRequest req) {
        String sessionDataKey = (String) req.getAttribute(OAuthConstants.SESSION_DATA_KEY);
        if (sessionDataKey == null) {
            sessionDataKey = req.getParameter(OAuthConstants.SESSION_DATA_KEY);
        }
        return sessionDataKey;
    }

    public boolean isConsentResponseFromUser() {
        return resultFromConsent != null;
    }

    public boolean isAuthResponseFromFramework() {
        return resultFromLogin != null;
    }

    public boolean isInitialRequest() {
        return request.getParameter("client_id") != null && getSessionDataKey(request) == null
                && request.getParameter(OAuthConstants.SESSION_DATA_KEY_CONSENT) == null;
    }

    public String getFlowStatus() {
        return request.getParameter(FrameworkConstants.RequestParams.FLOW_STATUS);
    }

    public boolean isRequestToCommonauth() {
        return Boolean.parseBoolean(request.getParameter(FrameworkConstants.RequestParams.TO_COMMONAUTH));
    }

    public String getOauthPKCECodeChallenge() {
        return request.getParameter(OAuthConstants.OAUTH_PKCE_CODE_CHALLENGE);
    }

    public String getOauthPKCECodeChallengeMethod() {
        return request.getParameter(OAuthConstants.OAUTH_PKCE_CODE_CHALLENGE_METHOD);
    }

    @Override
    public String toString() {
        return "OAuthMessage{" +
                "properties=" + properties +
                ", requestType=" + requestType +
                '}';
    }


    public static class OAuthMessageBuilder {

        private HttpServletRequest request;
        private HttpServletResponse response;

        public HttpServletRequest getRequest() {

            return request;
        }

        public HttpServletResponse getResponse() {

            return response;
        }

        public OAuthMessageBuilder setRequest(HttpServletRequest request) {

            this.request = request;
            return this;
        }

        public OAuthMessageBuilder setResponse(HttpServletResponse response) {

            this.response = response;
            return this;
        }

        public OAuthMessage build() throws InvalidRequestException {

            OAuthMessage oAuthMessage = new OAuthMessage(request, response);
            OAuthRequestStateValidator validator = new OAuthRequestStateValidator();
            oAuthMessage.setRequestType(validator.validateAndGetState(oAuthMessage));
            return oAuthMessage;
        }
    }
}

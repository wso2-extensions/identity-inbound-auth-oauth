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

package org.wso2.carbon.identity.oauth.endpoint.authz;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.cache.SessionDataCache;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheEntry;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.endpoint.exception.AccessDeniedException;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidApplicationClientException;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidApplicationServerException;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestException;
import javax.servlet.http.HttpServletRequest;

public class OAuthRequestStateValidator {

    private static final Log log = LogFactory.getLog(OAuthRequestStateValidator.class);


    public OAuthAuthorizeState getAndValidateCurrentState(HttpServletRequest request) throws InvalidRequestException {

        String clientId = request.getParameter("client_id");

        String sessionDataKeyFromLogin = getSessionDataKey(request);
        String sessionDataKeyFromConsent = request.getParameter(OAuthConstants.SESSION_DATA_KEY_CONSENT);
        SessionDataCacheKey cacheKey;
        SessionDataCacheEntry resultFromLogin = null;
        SessionDataCacheEntry resultFromConsent = null;

        Object flowStatus = request.getAttribute(FrameworkConstants.RequestParams.FLOW_STATUS);
        String isToCommonOauth = request.getParameter(FrameworkConstants.RequestParams.TO_COMMONAUTH);

        if (Boolean.TRUE.toString().equalsIgnoreCase(isToCommonOauth) && flowStatus == null) {
            return OAuthAuthorizeState.TO_COMMONAUTH;
        }

        if (StringUtils.isNotEmpty(sessionDataKeyFromLogin)) {
            cacheKey = new SessionDataCacheKey(sessionDataKeyFromLogin);
            resultFromLogin = SessionDataCache.getInstance().getValueFromCache(cacheKey);
        }
        if (StringUtils.isNotEmpty(sessionDataKeyFromConsent)) {
            cacheKey = new SessionDataCacheKey(sessionDataKeyFromConsent);
            resultFromConsent = SessionDataCache.getInstance().getValueFromCache(cacheKey);
        }

        validateRequest(clientId, sessionDataKeyFromLogin, sessionDataKeyFromConsent, resultFromLogin, resultFromConsent);

        // if the sessionDataKeyFromConsent parameter present in the login request, skip it and allow login since
        // result from login is there
        if (sessionDataKeyFromConsent != null && resultFromConsent == null && resultFromLogin != null) {
            sessionDataKeyFromConsent = null;
        }

        if (StringUtils.isNotEmpty(clientId)) {
            validateOauthApplication(clientId);
        }

        if (clientId != null && sessionDataKeyFromLogin == null && sessionDataKeyFromConsent == null) {
            // Authz request from client
            return OAuthAuthorizeState.INITIAL_AUTHORIZATION_REQUEST;

        } else if (resultFromLogin != null) {
            // Authentication response
            return OAuthAuthorizeState.AUTHENTICATION_RESPONSE;

        } else if (resultFromConsent != null) {
            // Consent submission
            return OAuthAuthorizeState.USER_CONSENT_RESPONSE;

        } else {
            // Invalid request
            if (log.isDebugEnabled()) {
                log.debug("Invalid authorization request");
            }

            throw new InvalidRequestException("Invalid authorization request");
        }
    }

    private void validateRequest(String clientId, String sessionDataKeyFromLogin, String sessionDataKeyFromConsent,
                                 SessionDataCacheEntry resultFromLogin, SessionDataCacheEntry resultFromConsent)
            throws InvalidRequestException {

        if (resultFromLogin != null && resultFromConsent != null) {

            if (log.isDebugEnabled()) {
                log.debug("Invalid authorization request.\'SessionDataKey\' found in request as parameter and " +
                        "attribute, and both have non NULL objects in cache");
            }
            throw new InvalidRequestException("Invalid authorization request");

        } else if (clientId == null && resultFromLogin == null && resultFromConsent == null) {

            if (log.isDebugEnabled()) {
                log.debug("Invalid authorization request.\'SessionDataKey\' not found in request as parameter or " +
                        "attribute, and client_id parameter cannot be found in request");
            }
            throw new InvalidRequestException("Invalid authorization request");

        } else if (sessionDataKeyFromLogin != null && resultFromLogin == null) {

            if (log.isDebugEnabled()) {
                log.debug("Session data not found in SessionDataCache for " + sessionDataKeyFromLogin);
            }
            throw new AccessDeniedException("Session Timed Out");

        } else if (sessionDataKeyFromConsent != null && resultFromConsent == null) {

            if (resultFromLogin == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Session data not found in SessionDataCache for " + sessionDataKeyFromConsent);
                }
                throw new AccessDeniedException("Session Timed Out");
            }

        }
    }


    private void validateOauthApplication(String clientId) throws InvalidRequestException {

        OAuthAppDAO oAuthAppDAO = new OAuthAppDAO();

        try {
            String appState = oAuthAppDAO.getConsumerAppState(clientId);
            if (StringUtils.isEmpty(appState)) {
                if (log.isDebugEnabled()) {
                    log.debug("A valid OAuth client could not be found for client_id: " + clientId);
                }

                throw new InvalidApplicationClientException("A valid OAuth client could not be found for client_id: " + clientId);
            }

            if (!OAuthConstants.OauthAppStates.APP_STATE_ACTIVE.equalsIgnoreCase(appState)) {
                if (log.isDebugEnabled()) {
                    log.debug("Oauth App is not in active state for client ID : " + clientId);
                }

                throw new InvalidApplicationClientException("Oauth application is not in active state");
            }
        } catch (IdentityOAuthAdminException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error in getting oauth app state.", e);
            }

            throw new InvalidApplicationServerException("Error in getting oauth app state");
        }
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
}

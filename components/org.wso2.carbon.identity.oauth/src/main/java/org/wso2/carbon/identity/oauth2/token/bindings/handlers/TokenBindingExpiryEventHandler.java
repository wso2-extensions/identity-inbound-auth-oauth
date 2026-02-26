/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.token.bindings.handlers;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.COMMONAUTH_COOKIE;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.RequestParams.TYPE;

/**
 * Event handler for token revocation during access token binding expiration.
 */
public class TokenBindingExpiryEventHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(TokenBindingExpiryEventHandler.class);

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        if (log.isDebugEnabled()) {
            log.debug(event.getEventName() + " event received to TokenBindingExpiryEventHandler.");
        }

        if (!IdentityEventConstants.EventName.SESSION_TERMINATE.name().equals(event.getEventName())
                && !IdentityEventConstants.EventName.SESSION_EXPIRE.name().equals(event.getEventName())) {
            return;
        }

        HttpServletRequest request = getHttpRequestFromEvent(event);
        Map<String, Object> eventProperties = event.getEventProperties();
        AuthenticationContext context = (AuthenticationContext) eventProperties.get(IdentityEventConstants
                .EventProperty.CONTEXT);
        try {
            if (request == null) {
                if (log.isDebugEnabled()) {
                    log.debug("HttpServletRequest object is null. Hence getting the session related information from " +
                            "event and revoking the access tokens mapped to session");
                }
                revokeAccessTokensMappedForSessions(event);
                return;
            }
            if (FrameworkConstants.RequestType.CLAIM_TYPE_OIDC.equals(request.getParameter(TYPE))) {

                String consumerKey = context.getRelyingParty();
                String bindingType = null;
                if (StringUtils.isNotBlank(consumerKey)) {
                    bindingType = OAuth2Util.getAppInformationByClientId(consumerKey).getTokenBindingType();
                }

                if (bindingType != null) {
                    revokeTokensForBindingType(request, context.getLastAuthenticatedUser(), consumerKey, bindingType);
                }

                if (!OAuth2Constants.TokenBinderType.SSO_SESSION_BASED_TOKEN_BINDER.equals(bindingType)) {
                    revokeTokensForCommonAuthCookie(request, context.getLastAuthenticatedUser());
                }
            } else {
                revokeTokensForCommonAuthCookie(request, context.getLastAuthenticatedUser());
            }
        } catch (IdentityOAuth2Exception | OAuthSystemException  e) {
            log.error("Error while revoking the tokens on session termination.", e);
        } catch (InvalidOAuthClientException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while revoking the tokens on session termination.", e);
            }
        }
    }

    /**
     * This method will get the application information from session context and revoke access tokens of the
     * applications bound to that session. This method can be used when token binding information is not found in the
     * request.
     *
     * @param event Event.
     * @throws IdentityOAuth2Exception
     */
    private void revokeAccessTokensMappedForSessions(Event event) throws IdentityOAuth2Exception {

        Map<String, Object> eventProperties = event.getEventProperties();
        Map<String, Object> paramMap = (Map<String, Object>) eventProperties.get(IdentityEventConstants
                .EventProperty.PARAMS);
        String sessionContextIdentifier = getSessionIdentifier(paramMap);
        AuthenticatedUser authenticatedUser = getAuthenticatedUser(paramMap);
        if (StringUtils.isNotBlank(sessionContextIdentifier)) {
            SessionContext sessionContext = (SessionContext) eventProperties.get(IdentityEventConstants
                    .EventProperty.SESSION_CONTEXT);
            if (sessionContext != null) {
                revokeTokensMappedToSession(sessionContextIdentifier, authenticatedUser);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Session context for session context identifier: " + sessionContextIdentifier +
                            " is not found in the event");
                }
            }
        }
    }

    /**
     * Get session context identifier from the event.
     *
     * @param paramMap Event parameters.
     * @return Session context identifier.
     */
    private String getSessionIdentifier(Map<String, Object> paramMap) {

        String sessionContextIdentifier = null;
        for (Map.Entry<String, Object> entry : paramMap.entrySet()) {
            if (StringUtils.equals(entry.getKey(), FrameworkConstants.AnalyticsAttributes.SESSION_ID)) {
                sessionContextIdentifier = (String) entry.getValue();
                if (log.isDebugEnabled()) {
                    log.debug("Found session context identifier: " + sessionContextIdentifier + " from the event.");
                }
                break;
            }
        }
        return sessionContextIdentifier;
    }

    /**
     * Get authenticated user from the event.
     *
     * @param paramMap Event parameters.
     * @return AuthenticatedUser.
     */
    private AuthenticatedUser getAuthenticatedUser(Map<String, Object> paramMap) {

        AuthenticatedUser authenticatedUser = null;
        for (Map.Entry<String, Object> entry : paramMap.entrySet()) {
            if (StringUtils.equals(entry.getKey(), FrameworkConstants.AnalyticsAttributes.USER)) {
                authenticatedUser = (AuthenticatedUser) entry.getValue();
                if (log.isDebugEnabled()) {
                    log.debug("Found authenticated user : " + authenticatedUser + " from the event.");
                }
                break;
            }
        }
        return authenticatedUser;
    }

    @Override
    public String getName() {

        return "TokenBindingExpiryEventHandler";
    }

    private HttpServletRequest getHttpRequestFromEvent(Event event) {

        return (HttpServletRequest) event.getEventProperties().get(IdentityEventConstants.EventProperty.REQUEST);
    }

    private void revokeTokensForBindingType(HttpServletRequest request, AuthenticatedUser user, String consumerKey,
                                            String bindingType) throws IdentityOAuth2Exception,
            InvalidOAuthClientException, OAuthSystemException {

        revokeTokensOfBindingRef(user, getBindingRefFromType(request, consumerKey, bindingType));
    }

    private void revokeTokensForCommonAuthCookie(HttpServletRequest request, AuthenticatedUser user) throws
            IdentityOAuth2Exception, InvalidOAuthClientException {

        revokeTokensOfBindingRef(user, getBindingRefFromCommonAuthCookie(request));
    }

    /**
     * Retrieve the token binding reference from the logout request based on the token binding type that is defined
     * for the oauth application.
     *
     * @param request     logout request
     * @param consumerKey consumer key of the application that user logged out from
     * @param bindingType binding type of the application that user logged out from
     * @return token binding reference
     * @throws IdentityOAuth2Exception if an exception occurs when retrieving the binding reference
     * @throws OAuthSystemException    if an exception occurs when retrieving the binding reference
     */
    private String getBindingRefFromType(HttpServletRequest request, String consumerKey, String bindingType)
            throws IdentityOAuth2Exception, OAuthSystemException {

        if (StringUtils.isBlank(bindingType)) {
            return null;
        }

        Optional<TokenBinder> tokenBinderOptional = OAuth2ServiceComponentHolder.getInstance()
                .getTokenBinder(bindingType);
        if (!tokenBinderOptional.isPresent()) {
            throw new IdentityOAuth2Exception("Token binder for the binding type: " + bindingType + " is not " +
                    "registered.");
        }

        TokenBinder tokenBinder = tokenBinderOptional.get();
        String tokenBindingRef = OAuth2Util.getTokenBindingReference(tokenBinder.getTokenBindingValue(request));
        if (StringUtils.isBlank(tokenBindingRef)) {
            throw new IdentityOAuth2Exception("Token binding reference is null for the application " +
                    consumerKey + " with binding type " + bindingType + ".");
        }
        return tokenBindingRef;
    }

    /**
     * If the common auth cookie is available in the logout request, retrieve the token binding reference based on
     * the cookie.
     *
     * @param request logout request
     * @return token binding reference
     */
    private String getBindingRefFromCommonAuthCookie(HttpServletRequest request) {

        Cookie[] cookies = request.getCookies();

        if (ArrayUtils.isEmpty(cookies)) {
            return null;
        }

        Optional<Cookie> commonAuthCookieOptional = Arrays.stream(cookies).filter(t -> COMMONAUTH_COOKIE.equals(
                t.getName())).findAny();
        if (!commonAuthCookieOptional.isPresent() || StringUtils.isBlank(commonAuthCookieOptional.get().getValue())) {
            return null;
        }

        return OAuth2Util.getTokenBindingReference(DigestUtils.sha256Hex(commonAuthCookieOptional.get().getValue()));
    }

    /**
     * Revoke all the access tokens issued for the given user with the given token binding reference if the token
     * revocation token after logout is enabled for the application.
     *
     * @param user                  authenticated user
     * @param tokenBindingReference token binding reference
     * @throws IdentityOAuth2Exception     if an exception occurs while revoking tokens
     * @throws InvalidOAuthClientException if an exception occurs while revoking tokens
     */
    private void revokeTokensOfBindingRef(AuthenticatedUser user, String tokenBindingReference) throws
            IdentityOAuth2Exception, InvalidOAuthClientException {

        if (StringUtils.isBlank(tokenBindingReference) || user == null) {
            return;
        }
        String userId;
        try {
            userId = user.getUserId();
        } catch (UserIdNotFoundException e) {
            log.error("User id cannot be found for user: " + user.getLoggableUserId() + ". Hence skip revoking " +
                    "relevant tokens");
            throw new IdentityOAuth2Exception("Unable to revoke tokens for the token binding reference: "
                    + tokenBindingReference);
        }

        Set<AccessTokenDO> boundTokens = OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                .getAccessTokensByBindingRef(tokenBindingReference);
        if (log.isDebugEnabled() && CollectionUtils.isEmpty(boundTokens)) {
            log.debug("No bound tokens found for the the provided binding reference: " + tokenBindingReference);
        }
        for (AccessTokenDO accessTokenDO : boundTokens) {
            String consumerKey = accessTokenDO.getConsumerKey();
            String tokenBindingType = accessTokenDO.getTokenType();
            OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(consumerKey);
            if (isTokenRevocationWithIDPSessionTerminationEnabledForOAuthApp(oAuthAppDO, tokenBindingType)
                    && accessTokenDO.getAuthzUser() != null) {
                AuthenticatedUser authenticatedUser = new AuthenticatedUser(accessTokenDO.getAuthzUser());
                try {
                    boolean isFederatedRoleBasedAuthzEnabled = false;
                    if (authenticatedUser.isFederatedUser()) {
                        isFederatedRoleBasedAuthzEnabled = OAuth2Util.isFederatedRoleBasedAuthzEnabled(consumerKey);
                    }

                    if (isFederatedRoleBasedAuthzEnabled
                            && StringUtils.equalsIgnoreCase(
                                    user.getFederatedIdPName(), authenticatedUser.getFederatedIdPName())
                            && StringUtils.equalsIgnoreCase(user.getUserName(), authenticatedUser.getUserName())) {
                        revokeFederatedTokens(consumerKey, user, accessTokenDO, tokenBindingReference);
                    } else if (StringUtils.equalsIgnoreCase(userId, authenticatedUser.getUserId())) {
                        revokeTokens(consumerKey, accessTokenDO, tokenBindingReference);
                    }
                } catch (UserIdNotFoundException e) {
                    log.error("User id cannot be found for user: " + authenticatedUser.getLoggableUserId());
                    throw new IdentityOAuth2Exception("Unable to revoke tokens of the app: " + consumerKey +
                            " for the token binding reference: " + tokenBindingReference);
                }
            }
        }
    }

    /**
     * Get the access tokens mapped for the session identifier and revoke those tokens.
     *
     * @param sessionId Session context identifier.
     * @param user Authenticated user.
     * @throws IdentityOAuth2Exception
     */
    private void revokeTokensMappedToSession(String sessionId, AuthenticatedUser user) throws IdentityOAuth2Exception {

        Set<String> tokenIds =
                OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                        .getTokenIdBySessionIdentifier(sessionId);

        if (tokenIds.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Could not find tokenId mapped for the sessionId reference: %s",
                        sessionId));
            }
            return;
        }
        for (String tokenId : tokenIds) {
            String accessToken =
                    OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO().getAccessTokenByTokenId(tokenId);
            if (StringUtils.isBlank(accessToken)) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Could not find access token mapped for tokenId: %s", tokenId));
                }
                return;
            }
            AccessTokenDO accessTokenDO = null;
            try {
                accessTokenDO = OAuth2Util.getAccessTokenDOFromTokenIdentifier(accessToken, false);
            } catch (IllegalArgumentException e) {
                if (StringUtils.equals(OAuth2Util.ACCESS_TOKEN_IS_NOT_ACTIVE_ERROR_MESSAGE, e.getMessage())) {
                    if (log.isDebugEnabled()) {
                        log.debug(String.format("Invalid token id: %s was found while revoking tokens mapped to the " +
                                "session.", tokenId));
                    }
                } else {
                    throw e;
                }
            }

            if (accessTokenDO != null) {
                String tokenBindingRef = OAuthConstants.TokenBindings.NONE;
                if (accessTokenDO.getTokenBinding() != null) {
                    tokenBindingRef = accessTokenDO.getTokenBinding().getBindingReference();
                }

                boolean isFederatedRoleBasedAuthzEnabled = false;
                AuthenticatedUser authenticatedUser = new AuthenticatedUser(accessTokenDO.getAuthzUser());

                String consumerKey = accessTokenDO.getConsumerKey();
                if (authenticatedUser.isFederatedUser()) {
                    isFederatedRoleBasedAuthzEnabled = OAuth2Util.isFederatedRoleBasedAuthzEnabled(consumerKey);
                }

                if (isFederatedRoleBasedAuthzEnabled
                        && StringUtils.equalsIgnoreCase(user.getUserName(), authenticatedUser.getUserName())) {
                    revokeFederatedTokens(consumerKey, user, accessTokenDO, tokenBindingRef);
                } else {
                    revokeTokens(consumerKey, accessTokenDO, tokenBindingRef);
                }
            }
        }
    }

    private void revokeTokens(String consumerKey, AccessTokenDO accessTokenDO, String tokenBindingReference)
            throws IdentityOAuth2Exception {

        revokeFederatedTokens(consumerKey, accessTokenDO.getAuthzUser(),  accessTokenDO, tokenBindingReference);
    }

    private void revokeFederatedTokens(String consumerKey, AuthenticatedUser user, AccessTokenDO accessTokenDO,
                                       String tokenBindingReference) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Revoking tokens for the application with consumerKey:" + consumerKey + " for the user: "
                    + user.getLoggableUserId());
        }
        OAuthUtil.clearOAuthCache(consumerKey, user, OAuth2Util.buildScopeString
                (accessTokenDO.getScope()), tokenBindingReference);
        OAuthUtil.clearOAuthCache(consumerKey, user, OAuth2Util.buildScopeString
                (accessTokenDO.getScope()));
        OAuthUtil.clearOAuthCache(consumerKey, user);
        OAuthUtil.clearOAuthCache(accessTokenDO);
        OAuthUtil.invokePreRevocationBySystemListeners(accessTokenDO, Collections.emptyMap());
        OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAOImpl(consumerKey)
                .revokeAccessTokens(new String[]{accessTokenDO.getAccessToken()}, OAuth2Util.isHashEnabled());
        OAuthUtil.invokePostRevocationBySystemListeners(accessTokenDO, Collections.emptyMap());
    }
    
    /**
     * Check whether token revocation after session termination is enabled for the given OAuth application.
     *
     * @param oAuthAppDO       OAuth application.
     * @param tokenBindingType Token binding type.
     * @return true if token revocation after logout is enabled, false otherwise.
     */
    private boolean isTokenRevocationWithIDPSessionTerminationEnabledForOAuthApp(OAuthAppDO oAuthAppDO,
            String tokenBindingType) {

        if (oAuthAppDO == null) {
            return false;
        }

        // If the session binding type is SSO session based, token is revoked regardless of the application config.
        if (OAuth2Constants.TokenBinderType.SSO_SESSION_BASED_TOKEN_BINDER.equals(tokenBindingType)) {
            boolean isLegacyTokenRevocationEnabled = OAuth2Util.isLegacySessionBoundTokenBehaviourEnabled();
            // Check to preserve the legacy behaviour if the relevant config is enabled.
            return !isLegacyTokenRevocationEnabled || oAuthAppDO.isTokenRevocationWithIDPSessionTerminationEnabled();
        }

        return oAuthAppDO.isTokenRevocationWithIDPSessionTerminationEnabled();
    }
}

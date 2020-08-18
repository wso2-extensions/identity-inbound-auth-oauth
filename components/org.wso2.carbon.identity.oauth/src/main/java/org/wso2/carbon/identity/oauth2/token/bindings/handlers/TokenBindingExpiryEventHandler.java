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
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.Arrays;
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

        if (!IdentityEventConstants.EventName.SESSION_TERMINATE.name().equals(event.getEventName())) {
            return;
        }

        HttpServletRequest request = getHttpRequestFromEvent(event);
        Map<String, Object> eventProperties = event.getEventProperties();
        AuthenticationContext context = (AuthenticationContext) eventProperties.get(IdentityEventConstants
                .EventProperty.CONTEXT);
        try {
            if (request == null) {
                return;
            }
            if (FrameworkConstants.RequestType.CLAIM_TYPE_OIDC.equals(request.getParameter(TYPE))) {

                String consumerKey = context.getRelyingParty();
                String bindingType = OAuth2Util.getAppInformationByClientId(consumerKey).getTokenBindingType();

                if (bindingType != null) {
                    revokeTokensForBindingType(request, context.getLastAuthenticatedUser(), consumerKey, bindingType);
                }

                if (!OAuth2Constants.TokenBinderType.SSO_SESSION_BASED_TOKEN_BINDER.equals(bindingType)) {
                    revokeTokensForCommonAuthCookie(request, context.getLastAuthenticatedUser());
                }
            } else {
                revokeTokensForCommonAuthCookie(request, context.getLastAuthenticatedUser());
            }
        } catch (IdentityOAuth2Exception | OAuthSystemException | InvalidOAuthClientException e) {
            log.error("Error while revoking the tokens on session termination.", e);
        }
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

        Set<AccessTokenDO> boundTokens = OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                .getAccessTokensByBindingRef(user, tokenBindingReference);

        for (AccessTokenDO accessTokenDO : boundTokens) {

            String consumerKey = accessTokenDO.getConsumerKey();

            if (OAuth2Util.getAppInformationByClientId(consumerKey)
                    .isTokenRevocationWithIDPSessionTerminationEnabled()) {

                OAuthUtil.clearOAuthCache(consumerKey, accessTokenDO.getAuthzUser(), OAuth2Util.buildScopeString
                        (accessTokenDO.getScope()), tokenBindingReference);
                OAuthUtil.clearOAuthCache(consumerKey, accessTokenDO.getAuthzUser(), OAuth2Util.buildScopeString
                        (accessTokenDO.getScope()));
                OAuthUtil.clearOAuthCache(consumerKey, accessTokenDO.getAuthzUser());
                OAuthUtil.clearOAuthCache(accessTokenDO.getAccessToken());

                OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO().revokeAccessToken(accessTokenDO
                        .getAccessToken(), accessTokenDO.getAuthzUser().getUserName());
            }
        }
    }
}

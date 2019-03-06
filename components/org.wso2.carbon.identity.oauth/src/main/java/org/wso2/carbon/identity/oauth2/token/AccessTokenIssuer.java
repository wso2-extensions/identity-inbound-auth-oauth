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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.token;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.owasp.encoder.Encode;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IDTokenValidationFailureException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.ResponseHeader;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.IDTokenBuilder;
import org.wso2.carbon.utils.CarbonUtils;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OauthAppStates.APP_STATE_ACTIVE;

/**
 * This class is used to issue access tokens and refresh tokens.
 */
public class AccessTokenIssuer {

    private static AccessTokenIssuer instance;
    private static Log log = LogFactory.getLog(AccessTokenIssuer.class);
    private Map<String, AuthorizationGrantHandler> authzGrantHandlers =
            new Hashtable<String, AuthorizationGrantHandler>();
    private AppInfoCache appInfoCache;
    public static final String OAUTH_APP_DO = "OAuthAppDO";

    /**
     * Private constructor which will not allow to create objects of this class from outside
     */
    private AccessTokenIssuer() throws IdentityOAuth2Exception {

        authzGrantHandlers = OAuthServerConfiguration.getInstance().getSupportedGrantTypes();
        appInfoCache = AppInfoCache.getInstance();
        if (appInfoCache != null) {
            if (log.isDebugEnabled()) {
                log.debug("Successfully created AppInfoCache under " + OAuthConstants.OAUTH_CACHE_MANAGER);
            }
        } else {
            log.error("Error while creating AppInfoCache");
        }

    }

    /**
     * Singleton method
     *
     * @return AccessTokenIssuer
     */
    public static AccessTokenIssuer getInstance() throws IdentityOAuth2Exception {

        CarbonUtils.checkSecurity();

        if (instance == null) {
            synchronized (AccessTokenIssuer.class) {
                if (instance == null) {
                    instance = new AccessTokenIssuer();
                }
            }
        }
        return instance;
    }

    /**
     * Issue access token using the respective grant handler and client authentication handler.
     *
     * @param tokenReqDTO
     * @return access token response
     * @throws IdentityException
     * @throws InvalidOAuthClientException
     */
    public OAuth2AccessTokenRespDTO issue(OAuth2AccessTokenReqDTO tokenReqDTO)
            throws IdentityException {

        String grantType = tokenReqDTO.getGrantType();
        OAuth2AccessTokenRespDTO tokenRespDTO = null;

        AuthorizationGrantHandler authzGrantHandler = authzGrantHandlers.get(grantType);

        OAuthTokenReqMessageContext tokReqMsgCtx = new OAuthTokenReqMessageContext(tokenReqDTO);
        boolean isRefreshRequest = GrantType.REFRESH_TOKEN.toString().equals(grantType);

        triggerPreListeners(tokenReqDTO, tokReqMsgCtx, isRefreshRequest);

        OAuthClientAuthnContext oAuthClientAuthnContext = tokenReqDTO.getoAuthClientAuthnContext();

        if (oAuthClientAuthnContext == null) {
            oAuthClientAuthnContext = new OAuthClientAuthnContext();
            oAuthClientAuthnContext.setAuthenticated(false);
            oAuthClientAuthnContext.setErrorMessage("Client Authentication Failed");
            oAuthClientAuthnContext.setErrorCode(OAuthError.TokenResponse.INVALID_REQUEST);
        }

        // Will return an invalid request response if multiple authentication mechanisms are engaged irrespective of
        // whether the grant type is confidential or not.
        if (oAuthClientAuthnContext.isMultipleAuthenticatorsEngaged()) {
            tokenRespDTO = handleError(OAuth2ErrorCodes.INVALID_REQUEST, "The client MUST NOT use more than one " +
                    "authentication method in each", tokenReqDTO);
            setResponseHeaders(tokReqMsgCtx, tokenRespDTO);
            triggerPostListeners(tokenReqDTO, tokenRespDTO, tokReqMsgCtx, isRefreshRequest);
            return tokenRespDTO;
        }

        boolean isAuthenticated = oAuthClientAuthnContext.isAuthenticated();

        if (authzGrantHandler == null) {
            String errorMsg = "Unsupported grant type : " + grantType + ", is used.";
            if (log.isDebugEnabled()) {
                log.debug(errorMsg);
            }
            tokenRespDTO = handleError(OAuthError.TokenResponse.UNSUPPORTED_GRANT_TYPE,
                    errorMsg, tokenReqDTO);
            setResponseHeaders(tokReqMsgCtx, tokenRespDTO);
            triggerPostListeners(tokenReqDTO, tokenRespDTO, tokReqMsgCtx, isRefreshRequest);
            return tokenRespDTO;
        }

        // If the client is not confidential then there is no need to authenticate the client.
        if (!authzGrantHandler.isConfidentialClient() && StringUtils.isNotEmpty
                (oAuthClientAuthnContext.getClientId())) {
            isAuthenticated = true;
        }

        if (!isAuthenticated && !oAuthClientAuthnContext.isPreviousAuthenticatorEngaged() && authzGrantHandler
                .isConfidentialClient()) {
            tokenRespDTO = handleError(
                    OAuth2ErrorCodes.INVALID_CLIENT,
                    "Unsupported Client Authentication Method!", tokenReqDTO);
            setResponseHeaders(tokReqMsgCtx, tokenRespDTO);
            triggerPostListeners(tokenReqDTO, tokenRespDTO, tokReqMsgCtx, isRefreshRequest);
            return tokenRespDTO;
        }
        if (!isAuthenticated) {
            tokenRespDTO = handleError(
                    oAuthClientAuthnContext.getErrorCode(),
                    oAuthClientAuthnContext.getErrorMessage(), tokenReqDTO);
            setResponseHeaders(tokReqMsgCtx, tokenRespDTO);
            triggerPostListeners(tokenReqDTO, tokenRespDTO, tokReqMsgCtx, isRefreshRequest);
            return tokenRespDTO;
        }

        // loading the stored application data
        OAuthAppDO oAuthAppDO = getOAuthApplication(tokenReqDTO.getClientId());

        // set the tenantDomain of the SP in the tokenReqDTO
        // indirectly we can say that the tenantDomain of the SP is the tenantDomain of the user who created SP
        // this is done to avoid having to send the tenantDomain as a query param to the token endpoint
        tokenReqDTO.setTenantDomain(OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO));

        tokReqMsgCtx.addProperty(OAUTH_APP_DO, oAuthAppDO);

        if (!authzGrantHandler.isOfTypeApplicationUser()) {
            tokReqMsgCtx.setAuthorizedUser(oAuthAppDO.getUser());
        }

        boolean isAuthorizedClient = false;

        String error = "The authenticated client is not authorized to use this authorization grant type";

        try {
            isAuthorizedClient = authzGrantHandler.isAuthorizedClient(tokReqMsgCtx);
        } catch (IdentityOAuth2Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while validating client for authorization", e);
            }
            error = e.getMessage();
        }

        if (!isAuthorizedClient) {

            if (log.isDebugEnabled()) {
                log.debug("Client Id: " + tokenReqDTO.getClientId() + " is not authorized to use grant type: " +
                        grantType);
            }
            tokenRespDTO = handleError(OAuthError.TokenResponse.UNAUTHORIZED_CLIENT, error, tokenReqDTO);
            setResponseHeaders(tokReqMsgCtx, tokenRespDTO);
            triggerPostListeners(tokenReqDTO, tokenRespDTO, tokReqMsgCtx, isRefreshRequest);
            return tokenRespDTO;
        }
        boolean isValidGrant = false;
        error = "Provided Authorization Grant is invalid";
        try {
            isValidGrant = authzGrantHandler.validateGrant(tokReqMsgCtx);
        } catch (IdentityOAuth2Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while validating grant", e);
            }
            error = e.getMessage();
        }

        if (tokReqMsgCtx.getAuthorizedUser() != null && tokReqMsgCtx.getAuthorizedUser().isFederatedUser()) {
            tokReqMsgCtx.getAuthorizedUser().setTenantDomain(OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO));
        }

        if (!isValidGrant) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid Grant provided by the client Id: " + tokenReqDTO.getClientId());
            }
            tokenRespDTO = handleError(OAuthError.TokenResponse.INVALID_GRANT, error, tokenReqDTO);
            setResponseHeaders(tokReqMsgCtx, tokenRespDTO);
            triggerPostListeners(tokenReqDTO, tokenRespDTO, tokReqMsgCtx, isRefreshRequest);
            return tokenRespDTO;
        }

        boolean isAuthorized = authzGrantHandler.authorizeAccessDelegation(tokReqMsgCtx);
        if (!isAuthorized) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid authorization for client Id = " + tokenReqDTO.getClientId());
            }
            tokenRespDTO = handleError(OAuthError.TokenResponse.UNAUTHORIZED_CLIENT,
                    "Unauthorized Client!", tokenReqDTO);
            setResponseHeaders(tokReqMsgCtx, tokenRespDTO);
            triggerPostListeners(tokenReqDTO, tokenRespDTO, tokReqMsgCtx, isRefreshRequest);
            return tokenRespDTO;
        }

        boolean isValidScope = authzGrantHandler.validateScope(tokReqMsgCtx);
        if (!isValidScope) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid scope provided by client Id: " + tokenReqDTO.getClientId());
            }
            tokenRespDTO = handleError(OAuthError.TokenResponse.INVALID_SCOPE, "Invalid Scope!", tokenReqDTO);
            setResponseHeaders(tokReqMsgCtx, tokenRespDTO);
            triggerPostListeners(tokenReqDTO, tokenRespDTO, tokReqMsgCtx, isRefreshRequest);
            return tokenRespDTO;
        }

        try {
            // set the token request context to be used by downstream handlers. This is introduced as a fix for
            // IDENTITY-4111.
            OAuth2Util.setTokenRequestContext(tokReqMsgCtx);
            tokenRespDTO = authzGrantHandler.issue(tokReqMsgCtx);
            if (tokenRespDTO.isError()) {
                setResponseHeaders(tokReqMsgCtx, tokenRespDTO);
                return tokenRespDTO;
            }
        } finally {
            triggerPostListeners(tokenReqDTO, tokenRespDTO, tokReqMsgCtx, isRefreshRequest);
            // clears the token request context.
            OAuth2Util.clearTokenRequestContext();
        }

        tokenRespDTO.setCallbackURI(oAuthAppDO.getCallbackUrl());

        String[] scopes = tokReqMsgCtx.getScope();
        if (scopes != null && scopes.length > 0) {
            StringBuilder scopeString = new StringBuilder("");
            for (String scope : scopes) {
                scopeString.append(scope);
                scopeString.append(" ");
            }
            tokenRespDTO.setAuthorizedScopes(scopeString.toString().trim());
        }

        setResponseHeaders(tokReqMsgCtx, tokenRespDTO);

        //Do not change this log format as these logs use by external applications
        if (log.isDebugEnabled()) {
            log.debug("Access token issued to client Id: " + tokenReqDTO.getClientId() + " username: " +
                    tokReqMsgCtx.getAuthorizedUser() + " and scopes: " + tokenRespDTO.getAuthorizedScopes());
        }

        if (tokReqMsgCtx.getScope() != null && OAuth2Util.isOIDCAuthzRequest(tokReqMsgCtx.getScope())) {
            if (log.isDebugEnabled()) {
                log.debug("Issuing ID token for client: " + tokenReqDTO.getClientId());
            }
            IDTokenBuilder builder = OAuthServerConfiguration.getInstance().getOpenIDConnectIDTokenBuilder();
            try {
                String idToken = builder.buildIDToken(tokReqMsgCtx, tokenRespDTO);
                tokenRespDTO.setIDToken(idToken);
            } catch (IDTokenValidationFailureException e) {
                log.error(e.getMessage());
                tokenRespDTO = handleError(OAuth2ErrorCodes.SERVER_ERROR, "Server Error", tokenReqDTO);
                return tokenRespDTO;
            }
        }

        if (GrantType.AUTHORIZATION_CODE.toString().equals(grantType)) {
            addUserAttributesAgainstAccessToken(tokenReqDTO, tokenRespDTO);
            // Cache entry against the authorization code has no value beyond the token request.
            clearCacheEntryAgainstAuthorizationCode(getAuthorizationCode(tokenReqDTO));
        }

        return tokenRespDTO;
    }

    private void triggerPreListeners(OAuth2AccessTokenReqDTO tokenReqDTO,
                                     OAuthTokenReqMessageContext tokReqMsgCtx,
                                     boolean isRefresh) throws IdentityOAuth2Exception {

        OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                .getOAuthEventInterceptorProxy();
        if (oAuthEventInterceptorProxy != null && oAuthEventInterceptorProxy.isEnabled()) {
            Map<String, Object> paramMap = new HashMap<>();
            if (isRefresh) {
                if (log.isDebugEnabled()) {
                    log.debug("Triggering refresh token pre renewal listeners for client: "
                            + tokenReqDTO.getClientId());
                }
                oAuthEventInterceptorProxy.onPreTokenRenewal(tokenReqDTO, tokReqMsgCtx, paramMap);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Triggering access token pre issuer listeners for client: " + tokenReqDTO.getClientId());
                }
                oAuthEventInterceptorProxy.onPreTokenIssue(tokenReqDTO, tokReqMsgCtx, paramMap);
            }
        }
    }

    private void triggerPostListeners(OAuth2AccessTokenReqDTO tokenReqDTO,
                                      OAuth2AccessTokenRespDTO tokenRespDTO, OAuthTokenReqMessageContext tokReqMsgCtx,
                                      boolean isRefresh) {

        OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                .getOAuthEventInterceptorProxy();

        if (isRefresh) {
            if (oAuthEventInterceptorProxy != null && oAuthEventInterceptorProxy.isEnabled()) {
                try {
                    if (log.isDebugEnabled()) {
                        log.debug("Triggering refresh token post renewal listeners for client: "
                                + tokenReqDTO.getClientId());
                    }
                    Map<String, Object> paramMap = new HashMap<>();
                    oAuthEventInterceptorProxy.onPostTokenRenewal(tokenReqDTO, tokenRespDTO, tokReqMsgCtx, paramMap);
                } catch (IdentityOAuth2Exception e) {
                    log.error("Oauth post renewal listener failed", e);
                }
            }
        } else {
            if (oAuthEventInterceptorProxy != null && oAuthEventInterceptorProxy.isEnabled()) {
                try {
                    if (log.isDebugEnabled()) {
                        log.debug("Triggering access token post issuer listeners for client: "
                                + tokenReqDTO.getClientId());
                    }
                    Map<String, Object> paramMap = new HashMap<>();
                    oAuthEventInterceptorProxy.onPostTokenIssue(tokenReqDTO, tokenRespDTO, tokReqMsgCtx, paramMap);
                } catch (IdentityOAuth2Exception e) {
                    log.error("Oauth post issuer listener failed.", e);
                }
            }
        }
    }

    /**
     * Copies the cache entry against the authorization code and adds an entry against the access token. This is done to
     * reuse the calculated user claims for subsequent usages such as user info calls.
     *
     * @param tokenReqDTO
     * @param tokenRespDTO
     */
    private void addUserAttributesAgainstAccessToken(OAuth2AccessTokenReqDTO tokenReqDTO,
                                                     OAuth2AccessTokenRespDTO tokenRespDTO) {

        AuthorizationGrantCacheKey oldCacheKey = new AuthorizationGrantCacheKey(getAuthorizationCode(tokenReqDTO));
        //checking getUserAttributesId value of cacheKey before retrieve entry from cache as it causes to NPE
        if (oldCacheKey.getUserAttributesId() != null) {
            AuthorizationGrantCacheEntry authorizationGrantCacheEntry =
                    AuthorizationGrantCache.getInstance().getValueFromCacheByCode(oldCacheKey);
            AuthorizationGrantCacheKey newCacheKey = new AuthorizationGrantCacheKey(tokenRespDTO.getAccessToken());
            if (authorizationGrantCacheEntry != null) {
                authorizationGrantCacheEntry.setTokenId(tokenRespDTO.getTokenId());
                if (log.isDebugEnabled()) {
                    if(IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                        log.debug("Adding AuthorizationGrantCache entry for the access token(hashed):" +
                                DigestUtils.sha256Hex(newCacheKey.getUserAttributesId()));
                    } else {
                        log.debug("Adding AuthorizationGrantCache entry for the access token");
                    }
                }
                authorizationGrantCacheEntry.setValidityPeriod(
                        TimeUnit.MILLISECONDS.toNanos(tokenRespDTO.getExpiresInMillis()));
                AuthorizationGrantCache.getInstance().addToCacheByToken(newCacheKey, authorizationGrantCacheEntry);
            }
        }
    }

    private void clearCacheEntryAgainstAuthorizationCode(String authorizationCode) {
        AuthorizationGrantCacheKey oldCacheKey = new AuthorizationGrantCacheKey(authorizationCode);
        //checking getUserAttributesId value of cacheKey before retrieve entry from cache as it causes to NPE
        if (oldCacheKey.getUserAttributesId() != null) {
            AuthorizationGrantCache.getInstance().clearCacheEntryByCode(oldCacheKey);
        }
    }

    private String getAuthorizationCode(OAuth2AccessTokenReqDTO tokenReqDTO) {
        return tokenReqDTO.getAuthorizationCode();
    }

    /**
     * Handle error scenarios in issueing the access token.
     *
     * @param errorCode
     * @param errorMsg
     * @param tokenReqDTO
     * @return Access token response DTO
     */
    private OAuth2AccessTokenRespDTO handleError(String errorCode,
                                                 String errorMsg,
                                                 OAuth2AccessTokenReqDTO tokenReqDTO) {

        if (log.isDebugEnabled()) {
            log.debug("OAuth-Error-Code=" + errorCode + " client-id=" + tokenReqDTO.getClientId()
                    + " grant-type=" + tokenReqDTO.getGrantType()
                    + " scope=" + OAuth2Util.buildScopeString(tokenReqDTO.getScope()));
        }
        OAuth2AccessTokenRespDTO tokenRespDTO;
        tokenRespDTO = new OAuth2AccessTokenRespDTO();
        tokenRespDTO.setError(true);
        tokenRespDTO.setErrorCode(errorCode);
        tokenRespDTO.setErrorMsg(errorMsg);
        return tokenRespDTO;
    }

    /**
     * Set headers in OAuth2AccessTokenRespDTO
     *
     * @param tokReqMsgCtx
     * @param tokenRespDTO
     */
    private void setResponseHeaders(OAuthTokenReqMessageContext tokReqMsgCtx,
                                    OAuth2AccessTokenRespDTO tokenRespDTO) {

        if (tokReqMsgCtx.getProperty(OAuthConstants.RESPONSE_HEADERS_PROPERTY) != null) {
            tokenRespDTO.setResponseHeaders((ResponseHeader[]) tokReqMsgCtx.getProperty(OAuthConstants.RESPONSE_HEADERS_PROPERTY));
        }
    }

    private OAuthAppDO getOAuthApplication(String consumerKey) throws InvalidOAuthClientException,
            IdentityOAuth2Exception {

        OAuthAppDO authAppDO = OAuth2Util.getAppInformationByClientId(consumerKey);
        String appState = authAppDO.getState();
        if (StringUtils.isEmpty(appState)) {
            if (log.isDebugEnabled()) {
                log.debug("A valid OAuth client could not be found for client_id: " + consumerKey);
            }
            throw new InvalidOAuthClientException("A valid OAuth client could not be found for client_id: " +
                    Encode.forHtml(consumerKey));
        }

        if (isNotActiveState(appState)) {
            if (log.isDebugEnabled()) {
                log.debug("App is not in active state in client ID: " + consumerKey + ". App state is:" + appState);
            }
            throw new InvalidOAuthClientException("Oauth application is not in active state");
        }

        if (log.isDebugEnabled()) {
            log.debug("Oauth App validation success for consumer key: " + consumerKey);
        }
        return authAppDO;
    }

    private static boolean isNotActiveState(String appState) {

        return !APP_STATE_ACTIVE.equalsIgnoreCase(appState);
    }
}

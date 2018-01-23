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
package org.wso2.carbon.identity.oauth2.authz.handlers.util;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.oauth.cache.*;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.authz.handlers.AccessTokenResponseTypeHandler;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dao.TokenMgtDAO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.IDTokenBuilder;
import org.wso2.carbon.identity.openidconnect.OIDCConstants;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;

import java.sql.Timestamp;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * ResponseTypeHandlerUtil contains all the common methods in tokenResponseTypeHandler and IDTokenResponseTypeHandler.
 */
public class ResponseTypeHandlerUtil {
    private static Log log = LogFactory.getLog(ResponseTypeHandlerUtil.class);

    public static void triggerPreListeners(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) {
        OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                .getOAuthEventInterceptorProxy();

        if (oAuthEventInterceptorProxy != null && oAuthEventInterceptorProxy.isEnabled()) {
            Map<String, Object> paramMap = new HashMap<>();
            try {
                oAuthEventInterceptorProxy.onPreTokenIssue(oauthAuthzMsgCtx, paramMap);
                if (log.isDebugEnabled()) {
                    log.debug("Oauth pre token issue listener is triggered.");
                }
            } catch (IdentityOAuth2Exception e) {
                log.error("Oauth pre token issue listener ", e);
            }
        }

    }

    public static void triggerPostListeners(OAuthAuthzReqMessageContext
                                              oauthAuthzMsgCtx, AccessTokenDO tokenDO, OAuth2AuthorizeRespDTO respDTO) {
        OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                .getOAuthEventInterceptorProxy();

        if (oAuthEventInterceptorProxy != null && oAuthEventInterceptorProxy.isEnabled()) {
            try {
                Map<String, Object> paramMap = new HashMap<>();
                oAuthEventInterceptorProxy.onPostTokenIssue(oauthAuthzMsgCtx, tokenDO, respDTO, paramMap);
                if (log.isDebugEnabled()) {
                    log.debug("Oauth post token issue listener is triggered.");
                }
            } catch (IdentityOAuth2Exception e) {
                log.error("Oauth post token issue listener ", e);
            }
        }
    }

    public static AccessTokenDO generateAccessToken(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, boolean cacheEnabled,
                                              OauthTokenIssuer oauthIssuerImpl)
            throws IdentityOAuth2Exception {
        OAuth2AuthorizeReqDTO authorizationReqDTO = oauthAuthzMsgCtx.getAuthorizationReqDTO();

        String scope = OAuth2Util.buildScopeString(oauthAuthzMsgCtx.getApprovedScope());
        String consumerKey = authorizationReqDTO.getConsumerKey();
        String authorizedUser = authorizationReqDTO.getUser().toString();
        String oAuthCacheKeyString;

        // Loading the stored application data.
        OAuthAppDO oAuthAppDO = null;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(consumerKey);
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Error while retrieving app information for clientId: " + consumerKey, e);
        }

        String responseType = oauthAuthzMsgCtx.getAuthorizationReqDTO().getResponseType();
        String grantType;

        if (StringUtils.contains(responseType, OAuthConstants.GrantTypes.TOKEN)) {
            grantType = OAuthConstants.GrantTypes.IMPLICIT;
        } else {
            grantType = responseType;
        }

        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authorizedUser);

        if (isUsernameCaseSensitive) {
            oAuthCacheKeyString = consumerKey + ":" + authorizedUser + ":" + scope;
        } else {
            oAuthCacheKeyString = consumerKey + ":" + authorizedUser.toLowerCase() + ":" + scope;
        }

        OAuthCacheKey cacheKey = new OAuthCacheKey(oAuthCacheKeyString);
        String userStoreDomain = null;

        // Select the user store domain when multiple user stores are configured.
        if (OAuth2Util.checkAccessTokenPartitioningEnabled() &&
                OAuth2Util.checkUserNameAssertionEnabled()) {
            userStoreDomain = OAuth2Util.getUserStoreForFederatedUser(authorizationReqDTO.getUser());
        }
        if (log.isDebugEnabled()) {
            log.debug("Service Provider specific expiry time enabled for application : " + consumerKey +
                    ". Application access token expiry time : " + oAuthAppDO.getApplicationAccessTokenExpiryTime()
                    + ", User access token expiry time : " + oAuthAppDO.getUserAccessTokenExpiryTime() +
                    ", Refresh token expiry time : " + oAuthAppDO.getRefreshTokenExpiryTime());
        }

        String refreshToken = null;
        Timestamp refreshTokenIssuedTime = null;
        long refreshTokenValidityPeriodInMillis = 0;

        AccessTokenDO tokenDO = null;

        synchronized ((consumerKey + ":" + authorizedUser + ":" + scope).intern()) {

            // check if valid access token exists in cache
            if (cacheEnabled) {
                AccessTokenDO accessTokenDO = (AccessTokenDO) OAuthCache.getInstance().getValueFromCache(cacheKey);
                if (accessTokenDO != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Retrieved active Access Token" +
                                " for Client Id : " + consumerKey + ", User ID :" + authorizedUser +
                                " and Scope : " + scope + " from cache");
                    }

                    long expireTime = OAuth2Util.getTokenExpireTimeMillis(accessTokenDO);

                    if (expireTime > 0 || expireTime < 0) {
                        if (log.isDebugEnabled()) {
                            if (expireTime > 0) {
                                log.debug("Access Token" +
                                        " is valid for another " + expireTime + "ms");
                            } else {
                                log.debug("Infinite lifetime Access Token found in cache");
                            }
                        }
                        return accessTokenDO;
                    } else {

                        long refreshTokenExpiryTime = OAuth2Util.getRefreshTokenExpireTimeMillis(accessTokenDO);

                        if (refreshTokenExpiryTime < 0 || refreshTokenExpiryTime > 0) {

                            if (log.isDebugEnabled()) {
                                log.debug("Access token has expired, But refresh token is still valid. User existing " +
                                        "refresh token.");
                            }
                            refreshToken = accessTokenDO.getRefreshToken();
                            refreshTokenIssuedTime = accessTokenDO.getRefreshTokenIssuedTime();
                            refreshTokenValidityPeriodInMillis = accessTokenDO.getRefreshTokenValidityPeriodInMillis();
                        }

                        // Token is expired. Clear it from cache
                        OAuthCache.getInstance().clearCacheEntry(cacheKey);

                        if (log.isDebugEnabled()) {
                            log.debug("Access Token is expired. Therefore cleared it from cache and marked it" +
                                    " as expired in database");
                        }
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("No active access token found in cache for Client ID : " + consumerKey +
                                ", User ID : " + authorizedUser + " and Scope : " + scope);
                    }
                }
            }

            // check if the last issued access token is still active and valid in the database
            AccessTokenDO existingAccessTokenDO = OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                    .getLatestAccessToken(consumerKey, authorizationReqDTO.getUser(), userStoreDomain, scope, false);

            if (existingAccessTokenDO != null) {

                if (log.isDebugEnabled()) {
                    log.debug("Retrieved latest Access Token" +
                            " for Client ID : " + consumerKey + ", User ID :" + authorizedUser +
                            " and Scope : " + scope + " from database");
                }

                long expiryTime = OAuth2Util.getTokenExpireTimeMillis(existingAccessTokenDO);

                long refreshTokenExpiryTime = OAuth2Util.getRefreshTokenExpireTimeMillis(existingAccessTokenDO);

                if (OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE.equals(
                        existingAccessTokenDO.getTokenState()) && (expiryTime > 0 || expiryTime < 0)) {

                    // token is active and valid
                    if (log.isDebugEnabled()) {
                        if (expiryTime > 0) {
                            log.debug("Access token is valid for another " + expiryTime + "ms");
                        } else {
                            log.debug("Infinite lifetime Access Token found in cache");
                        }
                    }

                    if (cacheEnabled) {
                        OAuthCache.getInstance().addToCache(cacheKey, existingAccessTokenDO);
                        if (log.isDebugEnabled()) {
                            log.debug("Access Token was added to cache for cache key : "
                                    + cacheKey.getCacheKeyString());
                        }
                    }
                    return existingAccessTokenDO;

                } else {

                    if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable
                            (IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                        log.debug("Access Token is " + existingAccessTokenDO.getTokenState());
                    }
                    String tokenState = existingAccessTokenDO.getTokenState();

                    if (OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE.equals(tokenState)) {

                        // Token is expired. If refresh token is still valid, use it.
                        if (refreshTokenExpiryTime > 0 || refreshTokenExpiryTime < 0) {
                            if (log.isDebugEnabled()) {
                                log.debug("Access token has expired, But refresh token is still valid. User existing " +
                                        "refresh token.");
                            }
                            refreshToken = existingAccessTokenDO.getRefreshToken();
                            refreshTokenIssuedTime = existingAccessTokenDO.getRefreshTokenIssuedTime();
                            refreshTokenValidityPeriodInMillis =
                                    existingAccessTokenDO.getRefreshTokenValidityPeriodInMillis();
                        }

                        if (log.isDebugEnabled()) {
                            log.debug("Marked Access Token as expired");
                        }
                    } else {

                        //Token is revoked or inactive
                        if (log.isDebugEnabled()) {
                            log.debug("Access Token is " + existingAccessTokenDO.getTokenState());
                        }
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("No access token found in database for Client ID : " + consumerKey +
                            ", User ID : " + authorizedUser + " and Scope : " + scope +
                            ". Therefore issuing new access token");
                }
            }

            Timestamp timestamp = new Timestamp(new Date().getTime());

            // if reusing existing refresh token, use its original issued time
            if (refreshTokenIssuedTime == null) {
                refreshTokenIssuedTime = timestamp;
            }
            // Default token validity Period
            long validityPeriodInMillis = OAuthServerConfiguration.getInstance().
                    getUserAccessTokenValidityPeriodInSeconds() * 1000;
            if (oAuthAppDO.getUserAccessTokenExpiryTime() != 0) {
                validityPeriodInMillis = oAuthAppDO.getUserAccessTokenExpiryTime() * 1000;
            }

            // if a VALID validity period is set through the callback, then use it
            long callbackValidityPeriod = oauthAuthzMsgCtx.getValidityPeriod();
            if ((callbackValidityPeriod != OAuthConstants.UNASSIGNED_VALIDITY_PERIOD)
                    && callbackValidityPeriod > 0) {
                validityPeriodInMillis = callbackValidityPeriod * 1000;
            }
            // If issuing new refresh token, use default refresh token validity Period
            // otherwise use existing refresh token's validity period
            if (refreshTokenValidityPeriodInMillis == 0) {
                if (oAuthAppDO.getRefreshTokenExpiryTime() != 0) {
                    refreshTokenValidityPeriodInMillis = oAuthAppDO.getRefreshTokenExpiryTime() * 1000;
                } else {
                    refreshTokenValidityPeriodInMillis = OAuthServerConfiguration.getInstance()
                            .getRefreshTokenValidityPeriodInSeconds() * 1000;
                }
            }

            // issue a new access token
            String accessToken;

            // set the validity period. this is needed by downstream handlers.
            // if this is set before - then this will override it by the calculated new value.
            oauthAuthzMsgCtx.setValidityPeriod(validityPeriodInMillis);

            // set the refresh token validity period. this is needed by downstream handlers.
            // if this is set before - then this will override it by the calculated new value.
            oauthAuthzMsgCtx.setRefreshTokenvalidityPeriod(refreshTokenValidityPeriodInMillis);

            // set access token issued time.this is needed by downstream handlers.
            oauthAuthzMsgCtx.setAccessTokenIssuedTime(timestamp.getTime());

            // set refresh token issued time.this is needed by downstream handlers.
            oauthAuthzMsgCtx.setRefreshTokenIssuedTime(refreshTokenIssuedTime.getTime());

            try {
                accessToken = oauthIssuerImpl.accessToken(oauthAuthzMsgCtx);

                // regenerate only if refresh token is null
                if (refreshToken == null) {
                    refreshToken = oauthIssuerImpl.refreshToken(oauthAuthzMsgCtx);
                }

            } catch (OAuthSystemException e) {
                throw new IdentityOAuth2Exception("Error occurred while generating access token and refresh token", e);
            }

            if (OAuth2Util.checkUserNameAssertionEnabled()) {
                accessToken = OAuth2Util.addUsernameToToken(authorizationReqDTO.getUser(), accessToken);
                refreshToken = OAuth2Util.addUsernameToToken(authorizationReqDTO.getUser(), refreshToken);
            }

            AccessTokenDO newAccessTokenDO =
                    new AccessTokenDO(consumerKey, authorizationReqDTO.getUser(), oauthAuthzMsgCtx.getApprovedScope(),
                            timestamp,
                            refreshTokenIssuedTime, validityPeriodInMillis, refreshTokenValidityPeriodInMillis,
                            OAuthConstants.UserType.APPLICATION_USER);

            newAccessTokenDO.setAccessToken(accessToken);
            newAccessTokenDO.setRefreshToken(refreshToken);
            newAccessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
            newAccessTokenDO.setGrantType(grantType);

            String tokenId = UUID.randomUUID().toString();
            newAccessTokenDO.setTokenId(tokenId);
            oauthAuthzMsgCtx.addProperty(OAuth2Util.ACCESS_TOKEN_DO, newAccessTokenDO);

            // Persist the access token in database
            try {
                OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO().insertAccessToken(accessToken,
                        authorizationReqDTO.getConsumerKey(), newAccessTokenDO, existingAccessTokenDO, userStoreDomain);
                deactivateCurrentAuthorizationCode(newAccessTokenDO.getAuthorizationCode(),
                        newAccessTokenDO.getTokenId());
                if (!accessToken.equals(newAccessTokenDO.getAccessToken())) {
                    // Using latest active token.
                    accessToken = newAccessTokenDO.getAccessToken();
                    refreshToken = newAccessTokenDO.getRefreshToken();
                }
            } catch (IdentityException e) {
                throw new IdentityOAuth2Exception(
                        "Error occurred while storing new access token : " + accessToken, e);
            }
            tokenDO = newAccessTokenDO;
            if (log.isDebugEnabled()) {
                log.debug("Persisted Access Token for " +
                        "Client ID : " + authorizationReqDTO.getConsumerKey() +
                        ", Authorized User : " + authorizationReqDTO.getUser() +
                        ", Timestamp : " + timestamp +
                        ", Validity period (s) : " + newAccessTokenDO.getValidityPeriod() +
                        ", Scope : " + OAuth2Util.buildScopeString(oauthAuthzMsgCtx.getApprovedScope()) +
                        ", Callback URL : " + authorizationReqDTO.getCallbackUrl() +
                        ", Token State : " + OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE +
                        " and User Type : " + OAuthConstants.UserType.APPLICATION_USER);
            }

            // Add the access token to the cache.
            if (cacheEnabled) {
                OAuthCache.getInstance().addToCache(cacheKey, newAccessTokenDO);
                // Adding AccessTokenDO to improve validation performance
                OAuthCacheKey accessTokenCacheKey = new OAuthCacheKey(accessToken);
                OAuthCache.getInstance().addToCache(accessTokenCacheKey, newAccessTokenDO);
                if (log.isDebugEnabled()) {
                    log.debug("Access Token was added to OAuthCache for cache key : " + cacheKey.getCacheKeyString());
                    log.debug("Access Token was added to OAuthCache for cache key : " + accessTokenCacheKey
                            .getCacheKeyString());
                }
            }

        }
        return  tokenDO;
    }

    public static AuthzCodeDO generateAuthorizationCode(OAuthAuthzReqMessageContext oauthAuthzMsgCtx, boolean cacheEnabled,
                                                 OauthTokenIssuer oauthIssuerImpl)
            throws IdentityOAuth2Exception {

        OAuth2AuthorizeReqDTO authorizationReqDTO = oauthAuthzMsgCtx.getAuthorizationReqDTO();
        String authorizationCode;
        String codeId = UUID.randomUUID().toString();
        Timestamp timestamp = new Timestamp(new Date().getTime());

        // Loading the stored application data.
        String consumerKey = authorizationReqDTO.getConsumerKey();
        OAuthAppDO oAuthAppDO = null;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(consumerKey);
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Error while retrieving app information for clientId: " + consumerKey, e);
        }

        long validityPeriod = OAuthServerConfiguration.getInstance()
                .getAuthorizationCodeValidityPeriodInSeconds();

        // if a VALID callback is set through the callback handler, use
        // it instead of the default one
        long callbackValidityPeriod = oauthAuthzMsgCtx.getValidityPeriod();

        if ((callbackValidityPeriod != OAuthConstants.UNASSIGNED_VALIDITY_PERIOD)
                && callbackValidityPeriod > 0) {
            validityPeriod = callbackValidityPeriod;
        }
        // convert to milliseconds
        validityPeriod = validityPeriod * 1000;

        // set the validity period. this is needed by downstream handlers.
        // if this is set before - then this will override it by the calculated new value.
        oauthAuthzMsgCtx.setValidityPeriod(validityPeriod);

        // set code issued time.this is needed by downstream handlers.
        oauthAuthzMsgCtx.setCodeIssuedTime(timestamp.getTime());

        if (authorizationReqDTO.getUser() != null && authorizationReqDTO.getUser().isFederatedUser()) {
            //if a federated user, treat the tenant domain as similar to application domain.
            authorizationReqDTO.getUser().setTenantDomain(authorizationReqDTO.getTenantDomain());
        }

        try {
            authorizationCode = oauthIssuerImpl.authorizationCode(oauthAuthzMsgCtx);
        } catch (OAuthSystemException e) {
            throw new IdentityOAuth2Exception(e.getMessage(), e);
        }

        AuthzCodeDO authzCodeDO = new AuthzCodeDO(authorizationReqDTO.getUser(),
                oauthAuthzMsgCtx.getApprovedScope(), timestamp, validityPeriod, authorizationReqDTO.getCallbackUrl(),
                authorizationReqDTO.getConsumerKey(), authorizationCode, codeId,
                authorizationReqDTO.getPkceCodeChallenge(), authorizationReqDTO.getPkceCodeChallengeMethod());

        OAuthTokenPersistenceFactory.getInstance().getAuthorizationCodeDAO()
                .insertAuthorizationCode(authorizationCode, authorizationReqDTO.getConsumerKey(),
                        authorizationReqDTO.getCallbackUrl(), authzCodeDO);

        if (cacheEnabled) {
            // Cache the authz Code, here we prepend the client_key to avoid collisions with
            // AccessTokenDO instances. In database level, these are in two databases. But access
            // tokens and authorization codes are in a single cache.
            String cacheKeyString = OAuth2Util.buildCacheKeyStringForAuthzCode(
                    authorizationReqDTO.getConsumerKey(), authorizationCode);
            OAuthCache.getInstance().addToCache(new OAuthCacheKey(cacheKeyString), authzCodeDO);
            if (log.isDebugEnabled()) {
                log.debug("Authorization Code info was added to the cache for client id : " +
                        authorizationReqDTO.getConsumerKey());
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Issued Authorization Code to user : " + authorizationReqDTO.getUser() +
                    ", Using the redirect url : " + authorizationReqDTO.getCallbackUrl() +
                    ", Scope : " + OAuth2Util.buildScopeString(oauthAuthzMsgCtx.getApprovedScope()) +
                    ", validity period : " + validityPeriod);
        }
        return authzCodeDO;
    }

    public static OAuth2AuthorizeRespDTO buildAuthorizationCodeResponseDTO(OAuth2AuthorizeRespDTO respDTO, AuthzCodeDO authzCodeDO)
            throws IdentityOAuth2Exception {
        respDTO.setAuthorizationCode(authzCodeDO.getAuthorizationCode());
        respDTO.setCodeId(authzCodeDO.getAuthzCodeId());
        return  respDTO;
    }

    public  static OAuth2AuthorizeRespDTO buildAccessTokenResponseDTO(OAuth2AuthorizeRespDTO respDTO, AccessTokenDO accessTokenDO) {

        long expireTime = OAuth2Util.getTokenExpireTimeMillis(accessTokenDO);
        if (log.isDebugEnabled()) {
            if (expireTime > 0) {
                log.debug("Access Token" +
                        " is valid for another " + expireTime + "ms");
            } else {
                log.debug("Infinite lifetime Access Token found in cache");
            }
        }
        respDTO.setAccessToken(accessTokenDO.getAccessToken());
        if (expireTime > 0) {
            respDTO.setValidityPeriod(expireTime / 1000);
        } else {
            respDTO.setValidityPeriod(Long.MAX_VALUE / 1000);
        }
        respDTO.setTokenType(accessTokenDO.getTokenType());
        return  respDTO;
    }

    /**
     * This method is used to set the id_token value in respDTO.
     * When creating the id_token, an access token is issued and through that access token user attributes are called.
     * This access token details are not necessary for respDTO when issuing the id_token.
     * So a new OAuth2AuthorizeRespDTO object is created and set all the relevant details that are needed in
     * DefaultIDTokenBuilder class. After the id_token is issued, set the id_token value to respDTO object and return.
     * @param respDTO
     * @param accessTokenDO
     * @param oauthAuthzMsgCtx
     * @return OAuth2AuthorizeRespDTO object with id_token details.
     * @throws IdentityOAuth2Exception
     */
    public static OAuth2AuthorizeRespDTO buildIDTokenResponseDTO(OAuth2AuthorizeRespDTO respDTO, AccessTokenDO accessTokenDO,
                                                   OAuthAuthzReqMessageContext oauthAuthzMsgCtx)
            throws IdentityOAuth2Exception {
        if (isOIDCRequest(oauthAuthzMsgCtx)) {
            OAuth2AuthorizeRespDTO newRespDTO = new OAuth2AuthorizeRespDTO();
            newRespDTO.setAccessToken(accessTokenDO.getAccessToken());
            newRespDTO.setAuthorizationCode(respDTO.getAuthorizationCode());
            buildIdToken(oauthAuthzMsgCtx, newRespDTO);
            respDTO.setIdToken(newRespDTO.getIdToken());
        }
        return  respDTO;
    }

    private static boolean isOIDCRequest (OAuthAuthzReqMessageContext msgCtx) {

        return msgCtx.getApprovedScope() != null && OAuth2Util.isOIDCAuthzRequest(msgCtx.getApprovedScope());
    }

    /**
     * Handles caching user attributes and building the id_token for the OIDC implicit authz request.
     *
     * @param msgCtx
     * @param authzRespDTO
     * @throws IdentityOAuth2Exception
     */
    private static void buildIdToken(OAuthAuthzReqMessageContext msgCtx, OAuth2AuthorizeRespDTO authzRespDTO)
            throws IdentityOAuth2Exception {

        if (StringUtils.isNotBlank(authzRespDTO.getAccessToken())) {
            addUserAttributesToCache(authzRespDTO.getAccessToken(), msgCtx);
        }

        if (StringUtils.contains(msgCtx.getAuthorizationReqDTO().getResponseType(), "id_token")) {
            IDTokenBuilder builder = OAuthServerConfiguration.getInstance().getOpenIDConnectIDTokenBuilder();
            authzRespDTO.setIdToken(builder.buildIDToken(msgCtx, authzRespDTO));
        }
    }

    private static void addUserAttributesToCache(String accessToken, OAuthAuthzReqMessageContext msgCtx) {

        OAuth2AuthorizeReqDTO authorizeReqDTO = msgCtx.getAuthorizationReqDTO();
        Map<ClaimMapping, String> userAttributes = authorizeReqDTO.getUser().getUserAttributes();
        AuthorizationGrantCacheKey authorizationGrantCacheKey = new AuthorizationGrantCacheKey(accessToken);
        AuthorizationGrantCacheEntry authorizationGrantCacheEntry = new AuthorizationGrantCacheEntry(userAttributes);
        if (StringUtils.isNotBlank(authorizeReqDTO.getEssentialClaims())) {
            authorizationGrantCacheEntry.setEssentialClaims(authorizeReqDTO.getEssentialClaims());
        }

        ClaimMapping key = new ClaimMapping();
        Claim claimOfKey = new Claim();
        claimOfKey.setClaimUri(OAuth2Util.SUB);
        key.setRemoteClaim(claimOfKey);
        String sub = userAttributes.get(key);

        AccessTokenDO accessTokenDO = (AccessTokenDO) msgCtx.getProperty(OAuth2Util.ACCESS_TOKEN_DO);
        if (accessTokenDO != null && StringUtils.isNotBlank(accessTokenDO.getTokenId())) {
            authorizationGrantCacheEntry.setTokenId(accessTokenDO.getTokenId());
        }

        if (StringUtils.isBlank(sub)) {
            sub = authorizeReqDTO.getUser().getAuthenticatedSubjectIdentifier();
        }

        if (StringUtils.isNotBlank(sub)) {
            userAttributes.put(key, sub);
        }

        AuthorizationGrantCache.getInstance().addToCacheByToken(authorizationGrantCacheKey,
                authorizationGrantCacheEntry);
    }

    private static void deactivateCurrentAuthorizationCode(String authorizationCode, String tokenId)
            throws IdentityOAuth2Exception {

        if (authorizationCode != null) {
            AuthzCodeDO authzCodeDO = new AuthzCodeDO();
            authzCodeDO.setAuthorizationCode(authorizationCode);
            authzCodeDO.setOauthTokenId(tokenId);
            OAuthTokenPersistenceFactory.getInstance()
                    .getAuthorizationCodeDAO().deactivateAuthorizationCode(authzCodeDO);
        }
    }

}


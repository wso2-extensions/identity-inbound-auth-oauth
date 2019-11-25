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

package org.wso2.carbon.identity.oauth2.authz.handlers;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.IDTokenBuilder;

import java.sql.Timestamp;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * @deprecated use {@link AccessTokenResponseTypeHandler} instead.
 * @deprecated use {@link IDTokenResponseTypeHandler} instead.
 */
@Deprecated
public class TokenResponseTypeHandler extends AbstractResponseTypeHandler {

    private static final Log log = LogFactory.getLog(TokenResponseTypeHandler.class);
    private Boolean isHashDisabled = OAuth2Util.isHashDisabled();

    @Override
    public OAuth2AuthorizeRespDTO issue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx)
            throws IdentityOAuth2Exception {

        OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                .getOAuthEventInterceptorProxy();

        if (oAuthEventInterceptorProxy != null && oAuthEventInterceptorProxy.isEnabled()) {
            Map<String, Object> paramMap = new HashMap<>();
            oAuthEventInterceptorProxy.onPreTokenIssue(oauthAuthzMsgCtx, paramMap);
        }

        OAuth2AuthorizeRespDTO respDTO = new OAuth2AuthorizeRespDTO();
        OAuth2AuthorizeReqDTO authorizationReqDTO = oauthAuthzMsgCtx.getAuthorizationReqDTO();

        String scope = OAuth2Util.buildScopeString(oauthAuthzMsgCtx.getApprovedScope());

        respDTO.setCallbackURI(authorizationReqDTO.getCallbackUrl());

        String consumerKey = authorizationReqDTO.getConsumerKey();
        String authorizedUser = authorizationReqDTO.getUser().toString();
        String oAuthCacheKeyString;

        String responseType = oauthAuthzMsgCtx.getAuthorizationReqDTO().getResponseType();
        String grantType;

        // Loading the stored application data.
        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(consumerKey);
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Error while retrieving app information for clientId: " + consumerKey, e);
        }

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

            AccessTokenDO existingAccessTokenDO = null;
            // check if valid access token exists in cache
            if (isHashDisabled && cacheEnabled) {
                existingAccessTokenDO = (AccessTokenDO) OAuthCache.getInstance().getValueFromCache(cacheKey);
                if (existingAccessTokenDO != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Retrieved active Access Token for Client Id : " + consumerKey + ", User ID :"
                                + authorizedUser + " and Scope : " + scope + " from cache");
                    }

                    long expireTime = OAuth2Util.getTokenExpireTimeMillis(existingAccessTokenDO);

                    if ((expireTime > 0 || expireTime < 0)) {
                        // Return still valid existing access token when JWTTokenIssuer is not used.
                        if (isNotRenewAccessTokenPerRequest(oauthAuthzMsgCtx)) {
                            if (log.isDebugEnabled()) {
                                if (expireTime > 0) {
                                    log.debug("Access Token is valid for another " + expireTime + "ms");
                                } else {
                                    log.debug("Infinite lifetime Access Token found in cache");
                                }
                            }
                            respDTO.setAccessToken(existingAccessTokenDO.getAccessToken());

                            if (expireTime > 0) {
                                respDTO.setValidityPeriod(expireTime / 1000);
                            } else {
                                respDTO.setValidityPeriod(Long.MAX_VALUE / 1000);
                            }
                            respDTO.setScope(oauthAuthzMsgCtx.getApprovedScope());
                            respDTO.setTokenType(existingAccessTokenDO.getTokenType());

                            // We only need to deal with id_token and user attributes if the request is OIDC
                            if (isOIDCRequest(oauthAuthzMsgCtx)) {
                                buildIdToken(oauthAuthzMsgCtx, respDTO);
                            }

                            triggerPostListeners(oauthAuthzMsgCtx, existingAccessTokenDO, respDTO);
                            return respDTO;
                        }
                    } else {

                        long refreshTokenExpiryTime = OAuth2Util.getRefreshTokenExpireTimeMillis(existingAccessTokenDO);

                        if (refreshTokenExpiryTime < 0 || refreshTokenExpiryTime > 0) {

                            if (log.isDebugEnabled()) {
                                log.debug("Access token has expired, But refresh token is still valid. User existing " +
                                        "refresh token.");
                            }
                            refreshToken = existingAccessTokenDO.getRefreshToken();
                            refreshTokenIssuedTime = existingAccessTokenDO.getRefreshTokenIssuedTime();
                            refreshTokenValidityPeriodInMillis = existingAccessTokenDO.getRefreshTokenValidityPeriodInMillis();
                        }

                        // Token is expired. Clear it from cache
                        OAuthCache.getInstance().clearCacheEntry(cacheKey);

                        if (log.isDebugEnabled()) {
                            log.debug("Access Token is expired. Therefore cleared it from cache and marked it as" +
                                    " expired in database");
                        }
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("No active access token found in cache for Client ID : " + consumerKey + ", User "
                                + "ID" + " : " + authorizedUser + " and Scope : " + scope);
                    }
                }
            }

            // if access token is not found in cache, check if the last issued access token is still active and valid
            // in the database
            if (isHashDisabled && existingAccessTokenDO == null) {

                existingAccessTokenDO = OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                        .getLatestAccessToken(consumerKey, authorizationReqDTO.getUser(), userStoreDomain, scope,
                                false);
                if (existingAccessTokenDO != null) {

                    if (log.isDebugEnabled()) {
                        log.debug("Retrieved latest Access Token for Client ID : " + consumerKey + ", User ID :"
                                + authorizedUser + " and Scope : " + scope + " from database");
                    }

                    long expiryTime = OAuth2Util.getTokenExpireTimeMillis(existingAccessTokenDO);
                    long refreshTokenExpiryTime = OAuth2Util.getRefreshTokenExpireTimeMillis(existingAccessTokenDO);

                    if (OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE.equals(existingAccessTokenDO.getTokenState())
                            && (expiryTime > 0 || expiryTime < 0)) {
                        // Return still valid existing access token when JWTTokenIssuer is not used.
                        if (isNotRenewAccessTokenPerRequest(oauthAuthzMsgCtx)) {
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
                                    log.debug("Access Token was added to cache for cache key : " + cacheKey
                                            .getCacheKeyString());
                                }
                            }

                            respDTO.setAccessToken(existingAccessTokenDO.getAccessToken());

                            if (expiryTime > 0) {
                                respDTO.setValidityPeriod(expiryTime / 1000);
                            } else {
                                respDTO.setValidityPeriod(Long.MAX_VALUE / 1000);
                            }

                            respDTO.setScope(oauthAuthzMsgCtx.getApprovedScope());
                            respDTO.setTokenType(existingAccessTokenDO.getTokenType());

                            // we only need to deal with id_token and user attributes if the request is OIDC
                            if (isOIDCRequest(oauthAuthzMsgCtx)) {
                                buildIdToken(oauthAuthzMsgCtx, respDTO);
                            }

                            triggerPostListeners(oauthAuthzMsgCtx, existingAccessTokenDO, respDTO);
                            return respDTO;
                        }
                    } else {

                        if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                            log.debug("Access Token is " + existingAccessTokenDO.getTokenState());
                        }
                        String tokenState = existingAccessTokenDO.getTokenState();

                        if (OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE.equals(tokenState)) {

                            // Token is expired. If refresh token is still valid, use it.
                            if (refreshTokenExpiryTime > 0 || refreshTokenExpiryTime < 0) {
                                if (log.isDebugEnabled()) {
                                    log.debug("Access token has expired, But refresh token is still valid. User " +
                                            "existing refresh token.");
                                }
                                refreshToken = existingAccessTokenDO.getRefreshToken();
                                refreshTokenIssuedTime = existingAccessTokenDO.getRefreshTokenIssuedTime();
                                refreshTokenValidityPeriodInMillis = existingAccessTokenDO
                                        .getRefreshTokenValidityPeriodInMillis();
                            }

                            if (log.isDebugEnabled()) {
                                log.debug("Marked Access Token as expired");
                            }
                        } else {

                            // Token is revoked or inactive
                            if (log.isDebugEnabled()) {
                                log.debug("Access Token is " + existingAccessTokenDO.getTokenState());
                            }
                        }
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("No access token found in database for Client ID : " + consumerKey + ", User ID : "
                                + authorizedUser + " and Scope : " + scope);
                    }
                }
            }

            if (log.isDebugEnabled()) {
                log.debug("Issuing a new access token for client id: " + consumerKey + ", user : " + authorizedUser +
                        "and scope : " + scope);
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
                OauthTokenIssuer oauthIssuerImpl = OAuth2Util.getOAuthTokenIssuerForOAuthApp(oAuthAppDO);
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

            // Add the access token to the cache, if cacheEnabled and the hashing oauth key feature turn on.
            if (isHashDisabled && cacheEnabled) {
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

            if (StringUtils.contains(responseType, ResponseType.TOKEN.toString())) {
                respDTO.setAccessToken(accessToken);

                if (validityPeriodInMillis > 0) {
                    respDTO.setValidityPeriod(newAccessTokenDO.getValidityPeriod());
                } else {
                    respDTO.setValidityPeriod(Long.MAX_VALUE / 1000);
                }

                respDTO.setScope(newAccessTokenDO.getScope());
                respDTO.setTokenType(newAccessTokenDO.getTokenType());
            }
        }

        // we only need to deal with id_token and user attributes if the request is OIDC
        if (isOIDCRequest(oauthAuthzMsgCtx)) {
            buildIdToken(oauthAuthzMsgCtx, respDTO);
        }

        triggerPostListeners(oauthAuthzMsgCtx, tokenDO, respDTO);
        return respDTO;
    }

    private void deactivateCurrentAuthorizationCode(String authorizationCode, String tokenId)
            throws IdentityOAuth2Exception {

        if (authorizationCode != null) {
            AuthzCodeDO authzCodeDO = new AuthzCodeDO();
            authzCodeDO.setAuthorizationCode(authorizationCode);
            authzCodeDO.setOauthTokenId(tokenId);
            OAuthTokenPersistenceFactory.getInstance()
                    .getAuthorizationCodeDAO().deactivateAuthorizationCode(authzCodeDO);
        }
    }

    private void triggerPostListeners(OAuthAuthzReqMessageContext
                                              oauthAuthzMsgCtx, AccessTokenDO tokenDO, OAuth2AuthorizeRespDTO respDTO) {

        OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                .getOAuthEventInterceptorProxy();

        if (oAuthEventInterceptorProxy != null && oAuthEventInterceptorProxy.isEnabled()) {
            try {
                Map<String, Object> paramMap = new HashMap<>();
                oAuthEventInterceptorProxy.onPostTokenIssue(oauthAuthzMsgCtx, tokenDO, respDTO, paramMap);
            } catch (IdentityOAuth2Exception e) {
                log.error("Oauth post token issue listener ", e);
            }
        }
    }

    private boolean isOIDCRequest (OAuthAuthzReqMessageContext msgCtx) {

        return msgCtx.getApprovedScope() != null && OAuth2Util.isOIDCAuthzRequest(msgCtx.getApprovedScope());
    }

    /**
     * Handles caching user attributes and building the id_token for the OIDC implicit authz request.
     *
     * @param msgCtx
     * @param authzRespDTO
     * @throws IdentityOAuth2Exception
     */
    private void buildIdToken(OAuthAuthzReqMessageContext msgCtx, OAuth2AuthorizeRespDTO authzRespDTO)
            throws IdentityOAuth2Exception {

        if (StringUtils.isNotBlank(authzRespDTO.getAccessToken())) {
            addUserAttributesToCache(authzRespDTO.getAccessToken(), msgCtx);
        }

        if (StringUtils.contains(msgCtx.getAuthorizationReqDTO().getResponseType(), "id_token")) {
            IDTokenBuilder builder = OAuthServerConfiguration.getInstance().getOpenIDConnectIDTokenBuilder();
            authzRespDTO.setIdToken(builder.buildIDToken(msgCtx, authzRespDTO));
        }
    }

    private void addUserAttributesToCache(String accessToken,
                                          OAuthAuthzReqMessageContext msgCtx) throws IdentityOAuth2Exception {

        OAuth2AuthorizeReqDTO authorizeReqDTO = msgCtx.getAuthorizationReqDTO();
        Map<ClaimMapping, String> userAttributes = authorizeReqDTO.getUser().getUserAttributes();
        AuthorizationGrantCacheKey authorizationGrantCacheKey = new AuthorizationGrantCacheKey(accessToken);
        AuthorizationGrantCacheEntry authorizationGrantCacheEntry = new AuthorizationGrantCacheEntry(userAttributes);
        if (StringUtils.isNotBlank(authorizeReqDTO.getEssentialClaims())) {
            authorizationGrantCacheEntry.setEssentialClaims(authorizeReqDTO.getEssentialClaims());
        }

        if (authorizeReqDTO.getRequestObject() != null) {
            authorizationGrantCacheEntry.setRequestObject(authorizeReqDTO.getRequestObject());
        }

        if (authorizeReqDTO.getAuthTime() != 0) {
            authorizationGrantCacheEntry.setAuthTime(authorizeReqDTO.getAuthTime());
        }

        if (authorizeReqDTO.getMaxAge() != 0) {
            authorizationGrantCacheEntry.setMaxAge(authorizeReqDTO.getMaxAge());
        }

        ClaimMapping key = new ClaimMapping();
        Claim claimOfKey = new Claim();
        claimOfKey.setClaimUri(OAuth2Util.SUB);
        key.setRemoteClaim(claimOfKey);
        String sub = userAttributes.get(key);

        AccessTokenDO accessTokenDO = getAccessTokenDO(accessToken, msgCtx);

        if (accessTokenDO != null && StringUtils.isNotBlank(accessTokenDO.getTokenId())) {
            authorizationGrantCacheEntry.setTokenId(accessTokenDO.getTokenId());
            if (StringUtils.isBlank(sub)) {
                sub = authorizeReqDTO.getUser().getAuthenticatedSubjectIdentifier();
            }
            if (StringUtils.isNotBlank(sub)) {
                if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
                    log.debug("Setting subject: " + sub + " as the sub claim in cache against the access token.");
                }
                authorizationGrantCacheEntry.setSubjectClaim(sub);
            }
            authorizationGrantCacheEntry.setValidityPeriod(TimeUnit.MILLISECONDS.toNanos(accessTokenDO.getValidityPeriodInMillis()));
            AuthorizationGrantCache.getInstance().addToCacheByToken(authorizationGrantCacheKey,
                    authorizationGrantCacheEntry);
        }
    }

    private boolean isNotRenewAccessTokenPerRequest(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) {

        boolean isRenew = oauthIssuerImpl.renewAccessTokenPerRequest(oauthAuthzMsgCtx);
        if (log.isDebugEnabled()) {
            log.debug("Access Token renew per request: " + isRenew);
        }
        return !isRenew;
    }

    private static AccessTokenDO getAccessTokenDO(String accessToken,
                                                  OAuthAuthzReqMessageContext msgCtx) throws IdentityOAuth2Exception {

        Object accessTokenObject = msgCtx.getProperty(OAuth2Util.ACCESS_TOKEN_DO);
        if (accessTokenObject instanceof AccessTokenDO) {
            return (AccessTokenDO) accessTokenObject;
        }
        return OAuth2Util.getAccessTokenDOfromTokenIdentifier(accessToken);
    }
}

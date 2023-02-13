/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.processor;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.OIDCClaimUtil;

import java.sql.Timestamp;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.buildCacheKeyStringForTokenWithUserId;

/**
 * Default implementation of @RefreshTokenProcessor responsible for handling refresh token persistence logic.
 */
public class DefaultRefreshTokenGrantProcessor implements RefreshTokenGrantProcessor {
    private static final Log log = LogFactory.getLog(DefaultRefreshTokenGrantProcessor.class);
    public static final int LAST_ACCESS_TOKEN_RETRIEVAL_LIMIT = 10;
    public static final String PREV_ACCESS_TOKEN = "previousAccessToken";
    private boolean isHashDisabled = OAuth2Util.isHashDisabled();

    protected boolean cacheEnabled;

    public DefaultRefreshTokenGrantProcessor() {
        // Check whether OAuth caching is enabled.
        if (OAuthCache.getInstance().isEnabled()) {
            cacheEnabled = true;
        }
    }

    @Override
    public RefreshTokenValidationDataDO validateRefreshToken(OAuthTokenReqMessageContext tokenReqMessageContext)
            throws IdentityOAuth2Exception {

        OAuth2AccessTokenReqDTO tokenReq = tokenReqMessageContext.getOauth2AccessTokenReqDTO();
        RefreshTokenValidationDataDO validationBean = OAuthTokenPersistenceFactory.getInstance()
                .getTokenManagementDAO().validateRefreshToken(tokenReq.getClientId(), tokenReq.getRefreshToken());
        validatePersistedAccessToken(validationBean, tokenReq.getClientId());
        validateRefreshTokenInRequest(tokenReq, validationBean);
        return validationBean;
    }

    @Override
    public void persistNewToken(OAuthTokenReqMessageContext tokenReqMessageContext, AccessTokenDO accessTokenBean)
            throws IdentityOAuth2Exception {

        OAuth2AccessTokenReqDTO tokenReq = tokenReqMessageContext.getOauth2AccessTokenReqDTO();
        String clientId = tokenReq.getClientId();
        String userStoreDomain = getUserStoreDomain(tokenReqMessageContext.getAuthorizedUser());
        RefreshTokenValidationDataDO oldAccessToken =
                (RefreshTokenValidationDataDO) tokenReqMessageContext.getProperty(PREV_ACCESS_TOKEN);
        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Previous access token (hashed): " + DigestUtils.sha256Hex(oldAccessToken.getAccessToken()));
            }
        }
        // set the previous access token state to "INACTIVE" and store new access token in single db connection
        OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                .invalidateAndCreateNewAccessToken(oldAccessToken.getTokenId(),
                        OAuthConstants.TokenStates.TOKEN_STATE_INACTIVE, clientId,
                        UUID.randomUUID().toString(), accessTokenBean, userStoreDomain, oldAccessToken.getGrantType());
        updateCacheIfEnabled(tokenReqMessageContext, accessTokenBean, clientId, oldAccessToken);
        if (log.isDebugEnabled()) {
            log.debug("Persisted an access token for the refresh token, " +
                    "Client ID : " + tokenReq.getClientId() +
                    ", Authorized user : " + tokenReqMessageContext.getAuthorizedUser() +
                    ", Timestamp : " + accessTokenBean.getIssuedTime() +
                    ", Validity period (s) : " + accessTokenBean.getValidityPeriod() +
                    ", Scope : " + OAuth2Util.buildScopeString(tokenReqMessageContext.getScope()) +
                    ", Token State : " + OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
        }
    }

    @Override
    public void addUserAttributesToCache(AccessTokenDO accessTokenBean, OAuthTokenReqMessageContext msgCtx) {

        RefreshTokenValidationDataDO oldAccessToken =
                (RefreshTokenValidationDataDO) msgCtx.getProperty(PREV_ACCESS_TOKEN);
        AuthorizationGrantCacheKey oldAuthorizationGrantCacheKey = new AuthorizationGrantCacheKey(oldAccessToken
                .getAccessToken());
        if (log.isDebugEnabled()) {
            log.debug("Getting AuthorizationGrantCacheEntry using access token id: " + accessTokenBean.getTokenId());
        }
        AuthorizationGrantCacheEntry grantCacheEntry =
                AuthorizationGrantCache.getInstance().getValueFromCacheByTokenId(oldAuthorizationGrantCacheKey,
                        oldAccessToken.getTokenId());
        if (grantCacheEntry != null) {
            if (log.isDebugEnabled()) {
                log.debug("Getting user attributes cached against the previous access token with access token id: " +
                        oldAccessToken.getTokenId());
            }
            AuthorizationGrantCacheKey authorizationGrantCacheKey = new AuthorizationGrantCacheKey(accessTokenBean
                    .getAccessToken());

            if (StringUtils.isNotBlank(accessTokenBean.getTokenId())) {
                grantCacheEntry.setTokenId(accessTokenBean.getTokenId());
            } else {
                grantCacheEntry.setTokenId(null);
            }

            grantCacheEntry.setValidityPeriod(
                    TimeUnit.MILLISECONDS.toNanos(accessTokenBean.getValidityPeriodInMillis()));

            // This new method has introduced in order to resolve a regression occurred : wso2/product-is#4366.
            AuthorizationGrantCache.getInstance().clearCacheEntryByTokenId(oldAuthorizationGrantCacheKey,
                    oldAccessToken.getTokenId());
            AuthorizationGrantCache.getInstance().addToCacheByToken(authorizationGrantCacheKey, grantCacheEntry);
        }
    }

    @Override
    public AccessTokenDO createAccessTokenBean(OAuthTokenReqMessageContext tokReqMsgCtx,
                                               OAuth2AccessTokenReqDTO tokenReq,
                                               RefreshTokenValidationDataDO validationBean,
                                               String tokenType)
            throws IdentityOAuth2Exception {

        Timestamp timestamp = new Timestamp(new Date().getTime());
        String tokenId = UUID.randomUUID().toString();

        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setConsumerKey(tokenReq.getClientId());
        accessTokenDO.setAuthzUser(tokReqMsgCtx.getAuthorizedUser());
        accessTokenDO.setScope(tokReqMsgCtx.getScope());
        accessTokenDO.setTokenType(tokenType);
        accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
        accessTokenDO.setTokenId(tokenId);
        accessTokenDO.setGrantType(tokenReq.getGrantType());
        accessTokenDO.setIssuedTime(timestamp);
        accessTokenDO.setTokenBinding(tokReqMsgCtx.getTokenBinding());

        if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
            String previousGrantType = validationBean.getGrantType();
            // Check if the previous grant type is consent refresh token type or not.
            if (!StringUtils.equals(OAuthConstants.GrantTypes.REFRESH_TOKEN, previousGrantType)) {
                // If the previous grant type is not a refresh token, then check if it's a consent token or not.
                if (OIDCClaimUtil.isConsentBasedClaimFilteringApplicable(previousGrantType)) {
                    accessTokenDO.setIsConsentedToken(true);
                }
            } else {
                /* When previousGrantType == refresh_token, we need to check whether the original grant type
                 is consented or not. */
                AccessTokenDO accessTokenDOFromTokenIdentifier = OAuth2Util.getAccessTokenDOFromTokenIdentifier(
                        validationBean.getAccessToken(), false);
                accessTokenDO.setIsConsentedToken(accessTokenDOFromTokenIdentifier.isConsentedToken());
            }

            if (accessTokenDO.isConsentedToken()) {
                tokReqMsgCtx.setConsentedToken(true);
            }
        }
        return accessTokenDO;
    }

    private boolean validatePersistedAccessToken(RefreshTokenValidationDataDO validationBean, String clientId)
            throws IdentityOAuth2Exception {

        if (validationBean.getAccessToken() == null) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid Refresh Token provided for Client with " +
                        "Client Id : " + clientId);
            }
            throw new IdentityOAuth2Exception("Persisted access token data not found");
        }
        return true;
    }

    private boolean validateRefreshTokenInRequest(OAuth2AccessTokenReqDTO tokenReq,
                                                  RefreshTokenValidationDataDO validationBean)
            throws IdentityOAuth2Exception {

        validateRefreshTokenStatus(validationBean, tokenReq.getClientId());
        if (isLatestRefreshToken(tokenReq, validationBean)) {
            return true;
        } else {
            throw new IdentityOAuth2Exception("Invalid refresh token value in the request");
        }
    }

    private boolean validateRefreshTokenStatus(RefreshTokenValidationDataDO validationBean, String clientId)
            throws IdentityOAuth2Exception {

        String tokenState = validationBean.getRefreshTokenState();
        if (tokenState != null && !OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE.equals(tokenState) &&
                !OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED.equals(tokenState)) {
            if (log.isDebugEnabled()) {
                log.debug("Refresh Token state is " + tokenState + " for client: " + clientId + ". Expected 'Active' " +
                        "or 'EXPIRED'");
            }
            throw new IdentityOAuth2Exception("Invalid refresh token state");
        }
        return true;
    }

    private boolean isLatestRefreshToken(OAuth2AccessTokenReqDTO tokenReq,
                                         RefreshTokenValidationDataDO validationBean) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Evaluating refresh token. Token value: " + tokenReq.getRefreshToken() + ", Token state: " +
                    validationBean.getRefreshTokenState());
        }
        if (!OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE.equals(validationBean.getRefreshTokenState())) {
            // if refresh token is not in active state, check whether there is an access token
            // issued with the same refresh token
            List<AccessTokenDO> accessTokenBeans = getAccessTokenBeans(tokenReq, validationBean,
                    getUserStoreDomain(validationBean.getAuthorizedUser()));
            for (AccessTokenDO token : accessTokenBeans) {
                if (tokenReq.getRefreshToken().equals(token.getRefreshToken())
                        && (OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE.equals(token.getTokenState())
                        || OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED.equals(token.getTokenState()))) {
                    return true;
                }
            }
            if (log.isDebugEnabled()) {
                log.debug("Refresh token: " + tokenReq.getRefreshToken() + " is not the latest");
            }
            removeIfCached(tokenReq, validationBean);
            return false;
        }
        return true;
    }

    private void removeIfCached(OAuth2AccessTokenReqDTO tokenReq, RefreshTokenValidationDataDO validationBean)
            throws IdentityOAuth2Exception {

        if (cacheEnabled) {
            String userId;
            try {
                userId = validationBean.getAuthorizedUser().getUserId();
            } catch (UserIdNotFoundException e) {
                throw new IdentityOAuth2Exception("User id not found for user:"
                        + validationBean.getAuthorizedUser().getLoggableUserId(), e);
            }
            clearCache(tokenReq.getClientId(), userId,
                    validationBean.getScope(), validationBean.getAccessToken(),
                    validationBean.getAuthorizedUser().getFederatedIdPName(),
                    validationBean.getTokenBindingReference(), validationBean.getAuthorizedUser().getTenantDomain());
        }
    }

    private void clearCache(String clientId, String authorizedUserId, String[] scopes, String accessToken,
                            String authenticatedIDP, String tokenBindingReference, String tenantDomain) {

        String cacheKeyString = buildCacheKeyStringForTokenWithUserId(clientId, OAuth2Util.buildScopeString(scopes),
                authorizedUserId, authenticatedIDP, tokenBindingReference);

        // Remove the old access token from the OAuthCache
        OAuthCacheKey oauthCacheKey = new OAuthCacheKey(cacheKeyString);
        OAuthCache.getInstance().clearCacheEntry(oauthCacheKey, tenantDomain);

        // Remove the old access token from the AccessTokenCache
        OAuthCacheKey accessTokenCacheKey = new OAuthCacheKey(accessToken);
        OAuthCache.getInstance().clearCacheEntry(accessTokenCacheKey, tenantDomain);
    }

    private List<AccessTokenDO> getAccessTokenBeans(OAuth2AccessTokenReqDTO tokenReq,
                                                    RefreshTokenValidationDataDO validationBean,
                                                    String userStoreDomain) throws IdentityOAuth2Exception {

        List<AccessTokenDO> accessTokenBeans = OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                .getLatestAccessTokens(tokenReq.getClientId(), validationBean.getAuthorizedUser(), userStoreDomain,
                        OAuth2Util.buildScopeString(validationBean.getScope()),
                        validationBean.getTokenBindingReference(), true, LAST_ACCESS_TOKEN_RETRIEVAL_LIMIT);
        if (accessTokenBeans == null || accessTokenBeans.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("No previous access tokens found. User: " + validationBean.getAuthorizedUser() +
                        ", client: " + tokenReq.getClientId() + ", scope: " +
                        OAuth2Util.buildScopeString(validationBean.getScope()));
            }
            throw new IdentityOAuth2Exception("No previous access tokens found");
        }
        return accessTokenBeans;
    }


    private void updateCacheIfEnabled(OAuthTokenReqMessageContext tokReqMsgCtx, AccessTokenDO accessTokenBean,
                                      String clientId, RefreshTokenValidationDataDO oldAccessToken)
            throws IdentityOAuth2Exception {

        if (isHashDisabled && cacheEnabled) {
            // Remove old access token from the OAuthCache
            String scope = OAuth2Util.buildScopeString(tokReqMsgCtx.getScope());
            String userId;
            try {
                userId = tokReqMsgCtx.getAuthorizedUser().getUserId();
            } catch (UserIdNotFoundException e) {
                throw new IdentityOAuth2Exception("User id is not available for user: "
                        + tokReqMsgCtx.getAuthorizedUser().getLoggableUserId(), e);
            }
            String authenticatedIDP = tokReqMsgCtx.getAuthorizedUser().getFederatedIdPName();
            String cacheKeyString = buildCacheKeyStringForTokenWithUserId(clientId, scope, userId,
                    authenticatedIDP, oldAccessToken.getTokenBindingReference());
            OAuthCacheKey oauthCacheKey = new OAuthCacheKey(cacheKeyString);
            OAuthCache.getInstance().clearCacheEntry(oauthCacheKey, accessTokenBean.getAuthzUser().getTenantDomain());

            // Remove old access token from the AccessTokenCache
            OAuthCacheKey accessTokenCacheKey = new OAuthCacheKey(oldAccessToken.getAccessToken());
            OAuthCache.getInstance().clearCacheEntry(accessTokenCacheKey,
                    oldAccessToken.getAuthorizedUser().getTenantDomain());
            AccessTokenDO tokenToCache = AccessTokenDO.clone(accessTokenBean);
            OauthTokenIssuer oauthTokenIssuer;
            try {
                oauthTokenIssuer = OAuth2Util.getOAuthTokenIssuerForOAuthApp(
                        tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId());
            } catch (InvalidOAuthClientException e) {
                throw new IdentityOAuth2Exception(
                        "Error while retrieving oauth issuer for the app with clientId: " +
                                tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId(), e);
            }
            if (oauthTokenIssuer.usePersistedAccessTokenAlias()) {
                try {
                    String persistedTokenIdentifier =
                            oauthTokenIssuer.getAccessTokenHash(accessTokenBean.getAccessToken());
                    tokenToCache.setAccessToken(persistedTokenIdentifier);
                } catch (OAuthSystemException e) {
                    if (log.isDebugEnabled()) {
                        if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                            log.debug("Token issuer: " + oauthTokenIssuer.getClass() + " was tried and" +
                                    " failed to parse the received token " + tokenToCache.getAccessToken(), e);
                        } else {
                            log.debug("Token issuer: " + oauthTokenIssuer.getClass() + " was tried and" +
                                    " failed to parse the received token.", e);
                        }
                    }
                }
            }

            // Add new access token to the OAuthCache
            OAuthCache.getInstance().addToCache(oauthCacheKey, tokenToCache);

            // Add new access token to the AccessTokenCache
            OAuth2Util.addTokenDOtoCache(accessTokenBean);

            if (log.isDebugEnabled()) {
                log.debug("Access Token info for the refresh token was added to the cache for " +
                        "the client id : " + clientId + ". Old access token entry was " +
                        "also removed from the cache.");
            }
        }
    }

    private String getUserStoreDomain(AuthenticatedUser authenticatedUser) throws IdentityOAuth2Exception {
        String userStoreDomain = null;
        if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
            //select the user store domain when multiple user stores are configured.
            try {
                userStoreDomain = OAuth2Util.getUserStoreForFederatedUser(authenticatedUser);
            } catch (IdentityOAuth2Exception e) {
                String errorMsg = "Error occurred while getting user store domain for User ID : " +
                        authenticatedUser;
                if (log.isDebugEnabled()) {
                    log.debug(errorMsg, e);
                }
                throw new IdentityOAuth2Exception(errorMsg, e);
            }
        }
        return userStoreDomain;
    }
}

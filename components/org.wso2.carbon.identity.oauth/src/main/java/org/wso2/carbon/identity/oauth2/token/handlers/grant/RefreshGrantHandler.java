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

package org.wso2.carbon.identity.oauth2.token.handlers.grant;


import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.ResponseHeader;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.tokenBinding.TokenBinding;
import org.wso2.carbon.identity.oauth2.tokenBinding.TokenBindingHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Grant Type handler for Grant Type refresh_token which is used to get a new access token.
 */
public class RefreshGrantHandler extends AbstractAuthorizationGrantHandler {

    private static final String PREV_ACCESS_TOKEN = "previousAccessToken";
    public static final int LAST_ACCESS_TOKEN_RETRIEVAL_LIMIT = 10;
    public static final int ALLOWED_MINIMUM_VALIDITY_PERIOD = 1000;
    public static final String DEACTIVATED_ACCESS_TOKEN = "DeactivatedAccessToken";
    private static Log log = LogFactory.getLog(RefreshGrantHandler.class);

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {
        super.validateGrant(tokReqMsgCtx);
        OAuth2AccessTokenReqDTO tokenReq = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        RefreshTokenValidationDataDO validationBean = OAuthTokenPersistenceFactory.getInstance()
                .getTokenManagementDAO().validateRefreshToken(tokenReq.getClientId(), tokenReq.getRefreshToken());

        validatePersistedAccessToken(validationBean, tokenReq.getClientId());
        validateRefreshTokenInRequest(tokReqMsgCtx,tokenReq, validationBean);

        if (log.isDebugEnabled()) {
            log.debug("Refresh token validation successful for Client id : " + tokenReq.getClientId() +
                    ", Authorized User : " + validationBean.getAuthorizedUser() +
                    ", Token Scope : " + OAuth2Util.buildScopeString(validationBean.getScope()));
        }
        setPropertiesForTokenGeneration(tokReqMsgCtx, validationBean);
        return true;
    }

    @Override
    public OAuth2AccessTokenRespDTO issue(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        OAuth2AccessTokenReqDTO tokenReq = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        // an active or expired token will be returned. since we do the validation for active or expired token in
        // validateGrant() no need to do it here again
        RefreshTokenValidationDataDO validationBean = OAuthTokenPersistenceFactory.getInstance()
                                .getTokenManagementDAO().validateRefreshToken(tokenReq.getClientId(),
                        tokenReq.getRefreshToken());

        if (isRefreshTokenExpired(validationBean)) {
            return handleError(OAuth2ErrorCodes.INVALID_GRANT, "Refresh token is expired.", tokenReq);
        }

        AccessTokenDO accessTokenBean = createAccessTokenBean(tokReqMsgCtx, tokenReq, validationBean);
        persistNewToken(tokReqMsgCtx, accessTokenBean, tokenReq.getClientId());
        if (log.isDebugEnabled()) {
            log.debug("Persisted an access token for the refresh token, " +
                    "Client ID : " + tokenReq.getClientId() +
                    "authorized user : " + tokReqMsgCtx.getAuthorizedUser() +
                    "timestamp : " + accessTokenBean.getIssuedTime() +
                    "validity period (s) : " + accessTokenBean.getValidityPeriod() +
                    "scope : " + OAuth2Util.buildScopeString(tokReqMsgCtx.getScope()) +
                    "Token State : " + OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE +
                    "User Type : " + getTokenType());
        }

        setTokenDataToMessageContext(tokReqMsgCtx, accessTokenBean);
        return buildTokenResponse(tokReqMsgCtx, accessTokenBean);
    }

    @Override
    public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {
        if (!super.validateScope(tokReqMsgCtx)) {
            return false;
        }

        /*
          The requested scope MUST NOT include any scope
          not originally granted by the resource owner, and if omitted is
          treated as equal to the scope originally granted by the
          resource owner
         */
        String[] requestedScopes = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope();
        String[] grantedScopes = tokReqMsgCtx.getScope();
        if (ArrayUtils.isNotEmpty(requestedScopes)) {
            if (ArrayUtils.isEmpty(grantedScopes)) {
                return false;
            }
            List<String> grantedScopeList = Arrays.asList(grantedScopes);
            for (String scope : requestedScopes) {
                if (!grantedScopeList.contains(scope)) {
                    if (log.isDebugEnabled()) {
                        log.debug("scope: " + scope + "is not granted for this refresh token");
                    }
                    return false;
                }
            }
            tokReqMsgCtx.setScope(requestedScopes);
        }
        return true;
    }

    private void setPropertiesForTokenGeneration(OAuthTokenReqMessageContext tokReqMsgCtx,
                                                 RefreshTokenValidationDataDO validationBean) {
        tokReqMsgCtx.setAuthorizedUser(validationBean.getAuthorizedUser());
        tokReqMsgCtx.setScope(validationBean.getScope());
        // Store the old access token as a OAuthTokenReqMessageContext property, this is already
        // a preprocessed token.
        tokReqMsgCtx.addProperty(PREV_ACCESS_TOKEN, validationBean);
    }

    private boolean validateRefreshTokenInRequest(OAuthTokenReqMessageContext tokReqMsgCtx,OAuth2AccessTokenReqDTO
            tokenReq,RefreshTokenValidationDataDO validationBean) throws IdentityOAuth2Exception {
        validateRefreshTokenStatus(validationBean, tokenReq.getClientId());
        if (!isLatestRefreshToken(tokenReq, validationBean)) {
            throw new IdentityOAuth2Exception("Invalid refresh token value in the request");
        }
        TokenBinding tokenBinding = new TokenBindingHandler();
        if(!tokenBinding.validateRefreshToken(tokReqMsgCtx)){
            if (log.isDebugEnabled()) {
                log.debug("Token Binding validation failed for refresh token");
            }
            return false;
        }
        return true;
    }

    private boolean isLatestRefreshToken(OAuth2AccessTokenReqDTO tokenReq,
                                         RefreshTokenValidationDataDO validationBean)
            throws IdentityOAuth2Exception {
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

    private void removeIfCached(OAuth2AccessTokenReqDTO tokenReq, RefreshTokenValidationDataDO validationBean) {
        if (cacheEnabled) {
            clearCache(tokenReq.getClientId(), validationBean.getAuthorizedUser().toString(),
                    validationBean.getScope(), validationBean.getAccessToken());
        }
    }

    private List<AccessTokenDO> getAccessTokenBeans(OAuth2AccessTokenReqDTO tokenReq,
                                                    RefreshTokenValidationDataDO validationBean,
                                                    String userStoreDomain) throws IdentityOAuth2Exception {
        List<AccessTokenDO> accessTokenBeans = OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                .getLatestAccessTokens(tokenReq.getClientId(), validationBean.getAuthorizedUser(), userStoreDomain,
                        OAuth2Util.buildScopeString(validationBean.getScope()),
                        true, LAST_ACCESS_TOKEN_RETRIEVAL_LIMIT);
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

    private boolean validateRefreshTokenStatus(RefreshTokenValidationDataDO validationBean, String clientId)
            throws IdentityOAuth2Exception {
        String tokenState = validationBean.getRefreshTokenState();
        if (tokenState != null && !OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE.equals(tokenState) &&
                !OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED.equals(tokenState)) {
            if(log.isDebugEnabled()) {
                log.debug("Refresh Token state is " + tokenState + " for client: " + clientId + ". Expected 'Active' " +
                        "or 'EXPIRED'");
            }
            throw new IdentityOAuth2Exception("Invalid refresh token state");
        }
        return true;
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

    private OAuth2AccessTokenRespDTO buildTokenResponse(OAuthTokenReqMessageContext tokReqMsgCtx,
                                                        AccessTokenDO accessTokenBean) {
        String scope = OAuth2Util.buildScopeString(tokReqMsgCtx.getScope());
        OAuth2AccessTokenRespDTO tokenResp = new OAuth2AccessTokenRespDTO();
        tokenResp.setAccessToken(accessTokenBean.getAccessToken());
        tokenResp.setRefreshToken(accessTokenBean.getRefreshToken());
        if (accessTokenBean.getValidityPeriodInMillis() > 0) {
            tokenResp.setExpiresIn(accessTokenBean.getValidityPeriod());
            tokenResp.setExpiresInMillis(accessTokenBean.getValidityPeriodInMillis());
        } else {
            tokenResp.setExpiresIn(Long.MAX_VALUE);
            tokenResp.setExpiresInMillis(Long.MAX_VALUE);
        }
        tokenResp.setAuthorizedScopes(scope);
        return tokenResp;
    }

    private void persistNewToken(OAuthTokenReqMessageContext tokReqMsgCtx, AccessTokenDO accessTokenBean,
                                 String clientId) throws IdentityOAuth2Exception {
        String userStoreDomain = getUserStoreDomain(tokReqMsgCtx.getAuthorizedUser());
        RefreshTokenValidationDataDO oldAccessToken =
                (RefreshTokenValidationDataDO) tokReqMsgCtx.getProperty(PREV_ACCESS_TOKEN);
        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Previous access token (hashed): " + DigestUtils.sha256Hex(oldAccessToken.getAccessToken()));
            }
        }
        // set the previous access token state to "INACTIVE" and store new access token in single db connection
        OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                .invalidateAndCreateNewAccessToken(oldAccessToken.getTokenId(),
                        OAuthConstants.TokenStates.TOKEN_STATE_INACTIVE, clientId,
                        UUID.randomUUID().toString(), accessTokenBean, userStoreDomain);
        updateCacheIfEnabled(tokReqMsgCtx, accessTokenBean, clientId, oldAccessToken);
    }

    private void updateCacheIfEnabled(OAuthTokenReqMessageContext tokReqMsgCtx, AccessTokenDO accessTokenBean,
                                      String clientId, RefreshTokenValidationDataDO oldAccessToken) {
        if (cacheEnabled) {
            // Remove old access token from the OAuthCache
            String scope = OAuth2Util.buildScopeString(tokReqMsgCtx.getScope());
            String authorizedUser = tokReqMsgCtx.getAuthorizedUser().toString();
            String cacheKeyString  = OAuth2Util.buildCacheKeyStringForToken(clientId, scope, authorizedUser);
            OAuthCacheKey oauthCacheKey = new OAuthCacheKey(cacheKeyString);
            OAuthCache.getInstance().clearCacheEntry(oauthCacheKey);

            // Remove old access token from the AccessTokenCache
            OAuthCacheKey accessTokenCacheKey = new OAuthCacheKey(oldAccessToken.getAccessToken());
            OAuthCache.getInstance().clearCacheEntry(accessTokenCacheKey);

            // Add new access token to the OAuthCache
            OAuthCache.getInstance().addToCache(oauthCacheKey, accessTokenBean);

            // Add new access token to the AccessTokenCache
            accessTokenCacheKey = new OAuthCacheKey(accessTokenBean.getAccessToken());
            OAuthCache.getInstance().addToCache(accessTokenCacheKey, accessTokenBean);

            if (log.isDebugEnabled()) {
                log.debug("Access Token info for the refresh token was added to the cache for " +
                        "the client id : " + clientId + ". Old access token entry was " +
                        "also removed from the cache.");
            }
        }
    }

    private void setTokenDataToMessageContext(OAuthTokenReqMessageContext tokReqMsgCtx, AccessTokenDO accessTokenBean) {
        // set the validity period. this is needed by downstream handlers.
        // if this is set before - then this will override it by the calculated new value.
        tokReqMsgCtx.setValidityPeriod(accessTokenBean.getValidityPeriodInMillis());

        // set the refresh token validity period. this is needed by downstream handlers.
        // if this is set before - then this will override it by the calculated new value.
        tokReqMsgCtx.setRefreshTokenvalidityPeriod(accessTokenBean.getRefreshTokenValidityPeriodInMillis());

        // set access token issued time.this is needed by downstream handlers.
        tokReqMsgCtx.setAccessTokenIssuedTime(accessTokenBean.getIssuedTime().getTime());

        // set refresh token issued time.this is needed by downstream handlers.
        tokReqMsgCtx.setRefreshTokenIssuedTime(accessTokenBean.getRefreshTokenIssuedTime().getTime());

        tokReqMsgCtx.addProperty(OAuthConstants.RESPONSE_HEADERS_PROPERTY, getResponseHeaders(tokReqMsgCtx));
    }

    private ResponseHeader[] getResponseHeaders(OAuthTokenReqMessageContext tokReqMsgCtx) {
        ResponseHeader[] respHeaders = new ResponseHeader[1];
        ResponseHeader header = new ResponseHeader();
        header.setKey(DEACTIVATED_ACCESS_TOKEN);
        header.setValue(((RefreshTokenValidationDataDO) tokReqMsgCtx.getProperty(PREV_ACCESS_TOKEN)).getAccessToken());
        respHeaders[0] = header;
        return respHeaders;
    }

    private OAuthAppDO getOAuthApp(String clientId) throws IdentityOAuth2Exception {
        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Error while retrieving app information for clientId: "
                    + clientId, e);
        }
        if (log.isDebugEnabled()) {
            log.debug("Service Provider specific expiry time enabled for application : " +
                    clientId + ". Application access token expiry time : " +
                    oAuthAppDO.getApplicationAccessTokenExpiryTime() + ", User access token expiry time : " +
                    oAuthAppDO.getUserAccessTokenExpiryTime() + ", Refresh token expiry time : "
                    + oAuthAppDO.getRefreshTokenExpiryTime());
        }
        return oAuthAppDO;
    }

    private OAuth2AccessTokenRespDTO handleError(String errorCode, String errorMsg,
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

    private void clearCache(String clientId, String authorizedUser, String[] scopes, String accessToken) {

        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authorizedUser);
        String cacheKeyString;
        if (isUsernameCaseSensitive) {
            cacheKeyString = clientId + ":" + authorizedUser + ":" + OAuth2Util.buildScopeString(scopes);
        } else {
            cacheKeyString = clientId + ":" + authorizedUser.toLowerCase() + ":" + OAuth2Util.buildScopeString(scopes);
        }

        // Remove the old access token from the OAuthCache
        OAuthCacheKey oauthCacheKey = new OAuthCacheKey(cacheKeyString);
        OAuthCache.getInstance().clearCacheEntry(oauthCacheKey);

        // Remove the old access token from the AccessTokenCache
        OAuthCacheKey accessTokenCacheKey = new OAuthCacheKey(accessToken);
        OAuthCache.getInstance().clearCacheEntry(accessTokenCacheKey);
    }

    private boolean isRefreshTokenExpired(RefreshTokenValidationDataDO validationBean) {
        long issuedTime = validationBean.getIssuedTime().getTime();
        long refreshValidity = validationBean.getValidityPeriodInMillis();
        return OAuth2Util.getTimeToExpire(issuedTime, refreshValidity) < ALLOWED_MINIMUM_VALIDITY_PERIOD;
    }

    private void setTokenData(AccessTokenDO accessTokenDO, OAuthTokenReqMessageContext tokReqMsgCtx,
                              RefreshTokenValidationDataDO validationBean, OAuth2AccessTokenReqDTO tokenReq,
                              Timestamp timestamp) throws IdentityOAuth2Exception {
        OAuthAppDO oAuthAppDO = getOAuthApp(tokenReq.getClientId());
        createTokens(accessTokenDO, tokReqMsgCtx);
        setRefreshTokenData(accessTokenDO, tokenReq, validationBean, oAuthAppDO, accessTokenDO.getRefreshToken(),
                timestamp);
        modifyTokensIfUsernameAssertionEnabled(accessTokenDO, tokReqMsgCtx);
        setValidityPeriod(accessTokenDO, tokReqMsgCtx, oAuthAppDO);
    }

    private void setValidityPeriod(AccessTokenDO accessTokenDO, OAuthTokenReqMessageContext tokReqMsgCtx,
                                   OAuthAppDO oAuthAppDO) {
        long validityPeriodInMillis = getValidityPeriodInMillis(tokReqMsgCtx, oAuthAppDO);
        accessTokenDO.setValidityPeriod(validityPeriodInMillis / SECONDS_TO_MILISECONDS_FACTOR);
        accessTokenDO.setValidityPeriodInMillis(validityPeriodInMillis);
    }

    private void createTokens(AccessTokenDO accessTokenDO, OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {
        try {
            String accessToken = oauthIssuerImpl.accessToken(tokReqMsgCtx);
            String refreshToken = oauthIssuerImpl.refreshToken(tokReqMsgCtx);

            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug("New access token (hashed): " + DigestUtils.sha256Hex(accessToken) +
                            " & new refresh token (hashed): " + DigestUtils.sha256Hex(refreshToken));
                } else {
                    log.debug("Access token and refresh token generated.");
                }
            }
            accessTokenDO.setAccessToken(accessToken);
            accessTokenDO.setRefreshToken(refreshToken);
        } catch (OAuthSystemException e) {
            throw new IdentityOAuth2Exception("Error when generating the tokens.", e);
        }
    }

    private void modifyTokensIfUsernameAssertionEnabled(AccessTokenDO accessTokenDO,
                                                        OAuthTokenReqMessageContext tokReqMsgCtx) {
        if (OAuth2Util.checkUserNameAssertionEnabled()) {
            String accessToken = OAuth2Util.addUsernameToToken(
                    tokReqMsgCtx.getAuthorizedUser(), accessTokenDO.getAccessToken());
            String refreshToken = OAuth2Util.addUsernameToToken(
                    tokReqMsgCtx.getAuthorizedUser(), accessTokenDO.getRefreshToken());
            accessTokenDO.setAccessToken(accessToken);
            accessTokenDO.setRefreshToken(refreshToken);
            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug("Encoded access token (hashed): " + DigestUtils.sha256Hex(accessToken) +
                            " & encoded refresh token (hashed): " + DigestUtils.sha256Hex(refreshToken));
                } else {
                    log.debug("Access token and refresh token encoded using Base64 encoding.");
                }
            }
        }
    }

    private AccessTokenDO createAccessTokenBean(OAuthTokenReqMessageContext tokReqMsgCtx,
                                                OAuth2AccessTokenReqDTO tokenReq,
                                                RefreshTokenValidationDataDO validationBean)
            throws IdentityOAuth2Exception {
        Timestamp timestamp = new Timestamp(new Date().getTime());
        String tokenId = UUID.randomUUID().toString();

        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setConsumerKey(tokenReq.getClientId());
        accessTokenDO.setAuthzUser(tokReqMsgCtx.getAuthorizedUser());
        accessTokenDO.setScope(tokReqMsgCtx.getScope());
        accessTokenDO.setTokenType(getTokenType());
        accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
        accessTokenDO.setTokenId(tokenId);
        accessTokenDO.setGrantType(tokenReq.getGrantType());
        accessTokenDO.setIssuedTime(timestamp);

        // sets accessToken, refreshToken and validity data
        setTokenData(accessTokenDO, tokReqMsgCtx, validationBean, tokenReq, timestamp);
        return accessTokenDO;
    }

    private long getValidityPeriodInMillis(OAuthTokenReqMessageContext tokReqMsgCtx, OAuthAppDO oAuthAppDO) {
        long validityPeriodInMillis;
        if (oAuthAppDO.getUserAccessTokenExpiryTime() != 0) {
            validityPeriodInMillis = oAuthAppDO.getUserAccessTokenExpiryTime() * SECONDS_TO_MILISECONDS_FACTOR;
        } else {
            validityPeriodInMillis = OAuthServerConfiguration.getInstance()
                    .getUserAccessTokenValidityPeriodInSeconds() * SECONDS_TO_MILISECONDS_FACTOR;
        }
        // if a VALID validity period is set through the callback, then use it
        long callbackValidityPeriod = tokReqMsgCtx.getValidityPeriod();
        if (callbackValidityPeriod != OAuthConstants.UNASSIGNED_VALIDITY_PERIOD) {
            validityPeriodInMillis = callbackValidityPeriod * SECONDS_TO_MILISECONDS_FACTOR;
        }
        return validityPeriodInMillis;
    }

    private void setRefreshTokenData(AccessTokenDO accessTokenDO,
                                     OAuth2AccessTokenReqDTO tokenReq,
                                     RefreshTokenValidationDataDO validationBean,
                                     OAuthAppDO oAuthAppDO,
                                     String refreshToken, Timestamp timestamp) {
        Timestamp refreshTokenIssuedTime = null;
        long refreshTokenValidityPeriod = 0;
        boolean renew = OAuthServerConfiguration.getInstance().isRefreshTokenRenewalEnabled();
        if (!renew) {
            // if refresh token renewal not enabled, we use existing one else we issue a new refresh token
            refreshToken = tokenReq.getRefreshToken();
            refreshTokenIssuedTime = validationBean.getIssuedTime();
            refreshTokenValidityPeriod = validationBean.getValidityPeriodInMillis();
        }
        if (refreshTokenIssuedTime == null) {
            refreshTokenIssuedTime = timestamp;
        }
        accessTokenDO.setRefreshToken(refreshToken);
        accessTokenDO.setRefreshTokenIssuedTime(refreshTokenIssuedTime);
        accessTokenDO.setRefreshTokenValidityPeriodInMillis(
                getRefreshTokenValidityPeriod(refreshTokenValidityPeriod, oAuthAppDO));
    }

    private long getRefreshTokenValidityPeriod(long refreshTokenValidityPeriod, OAuthAppDO oAuthAppDO) {
        // If issuing new refresh token, use default refresh token validity Period
        // otherwise use existing refresh token's validity period
        if (refreshTokenValidityPeriod == 0) {
            if (oAuthAppDO.getRefreshTokenExpiryTime() != 0) {
                refreshTokenValidityPeriod = oAuthAppDO.getRefreshTokenExpiryTime() * SECONDS_TO_MILISECONDS_FACTOR;
            } else {
                refreshTokenValidityPeriod = OAuthServerConfiguration.getInstance()
                        .getRefreshTokenValidityPeriodInSeconds() * SECONDS_TO_MILISECONDS_FACTOR;
            }
        }
        return refreshTokenValidityPeriod;
    }
}

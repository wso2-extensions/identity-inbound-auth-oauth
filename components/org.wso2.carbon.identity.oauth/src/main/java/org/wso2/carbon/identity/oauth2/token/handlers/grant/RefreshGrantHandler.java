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


import org.apache.axiom.util.base64.Base64Utils;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.Charsets;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.ResponseHeader;
import org.wso2.carbon.identity.oauth2.dao.SQLQueries;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Grant Type handler for Grant Type refresh_token which is used to get a new access token.
 */
public class RefreshGrantHandler extends AbstractAuthorizationGrantHandler {

    private static final String PREV_ACCESS_TOKEN = "previousAccessToken";
    private static Log log = LogFactory.getLog(RefreshGrantHandler.class);

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        if(!super.validateGrant(tokReqMsgCtx)){
            return false;
        }

        OAuth2AccessTokenReqDTO tokenReqDTO = tokReqMsgCtx.getOauth2AccessTokenReqDTO();

        String refreshToken = tokenReqDTO.getRefreshToken();

        RefreshTokenValidationDataDO validationDataDO = tokenMgtDAO.validateRefreshToken(
                tokenReqDTO.getClientId(), refreshToken);
        String tokenBindingId =OAuth2Util.checkTB(tokReqMsgCtx,OAuthConstants.HTTP_TB_PROVIDED_HEADER_NAME); //token binding.
        if (validationDataDO.getAccessToken() == null) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid Refresh Token provided for Client with " +
                        "Client Id : " + tokenReqDTO.getClientId());
            }
            return false;
        }

        if (validationDataDO.getRefreshTokenState() != null &&
                !OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE.equals(
                        validationDataDO.getRefreshTokenState()) &&
                !OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED.equals(
                        validationDataDO.getRefreshTokenState())) {
            if(log.isDebugEnabled()) {
                log.debug("Access Token is not in 'ACTIVE' or 'EXPIRED' state for Client with " +
                        "Client Id : " + tokenReqDTO.getClientId());
            }
            return false;
        }

        String userStoreDomain = null;
        if (OAuth2Util.checkAccessTokenPartitioningEnabled() && OAuth2Util.checkUserNameAssertionEnabled()) {
            try {
                userStoreDomain = OAuth2Util.getUserStoreForFederatedUser(validationDataDO.getAuthorizedUser());
            } catch (IdentityOAuth2Exception e) {
                String errorMsg = "Error occurred while getting user store domain for User ID : " + validationDataDO.getAuthorizedUser();
                log.error(errorMsg, e);
                throw new IdentityOAuth2Exception(errorMsg, e);
            }
        }

        if (!OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE.equals(validationDataDO.getRefreshTokenState())) {
            List<AccessTokenDO> accessTokenDOs = tokenMgtDAO.retrieveLatestAccessTokens(
                    tokenReqDTO.getClientId(), validationDataDO.getAuthorizedUser(), userStoreDomain,
                    OAuth2Util.buildScopeString(validationDataDO.getScope()), true, 10);
            boolean isLatest = false;
            if (accessTokenDOs == null || accessTokenDOs.isEmpty()) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while retrieving the latest refresh token");
                }
                if (cacheEnabled) {
                    clearCache(tokenReqDTO.getClientId(), validationDataDO.getAuthorizedUser().toString(),
                               validationDataDO.getScope(), validationDataDO.getAccessToken());
                }
                return false;
            } else {
                for (AccessTokenDO token : accessTokenDOs) {
                    if (refreshToken.equals(token.getRefreshToken())
                            && (OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE.equals(token.getTokenState())
                            || OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED.equals(token.getTokenState()))) {
                        isLatest = true;
                    }
                }
            }
            if (!isLatest) {
                if (log.isDebugEnabled()) {
                    log.debug("Refresh token is not the latest.");
                }
                if (cacheEnabled) {
                    clearCache(tokenReqDTO.getClientId(), validationDataDO.getAuthorizedUser().toString(),
                            validationDataDO.getScope(), validationDataDO.getAccessToken());
                }
                return false;
            }
            if (!tokenBindingId.isEmpty()) {
                String checkTokenValue=(new String(Base64Utils.decode(refreshToken), (Charsets.UTF_8))).split(":")[0];;
                if (OAuth2Util.checkUserNameAssertionEnabled()) {
                    checkTokenValue = (new String(Base64Utils.decode(checkTokenValue), (Charsets.UTF_8))).split(":")[0];
                }
                if (!checkTokenValue.equals(OAuth2Util.hashTB(tokenBindingId))) {
                    return false;
                }
            }

            if (log.isDebugEnabled()) {
                log.debug("Refresh token validation successful for Client id : " + tokenReqDTO.getClientId() +
                          ", Authorized User : " + validationDataDO.getAuthorizedUser() +
                          ", Token Scope : " + OAuth2Util.buildScopeString(validationDataDO.getScope()));
            }
        }

        tokReqMsgCtx.setAuthorizedUser(validationDataDO.getAuthorizedUser());
        tokReqMsgCtx.setScope(validationDataDO.getScope());
        // Store the old access token as a OAuthTokenReqMessageContext property, this is already
        // a preprocessed token.
        tokReqMsgCtx.addProperty(PREV_ACCESS_TOKEN, validationDataDO);
        return true;
    }

    @Override
    public OAuth2AccessTokenRespDTO issue(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        OAuth2AccessTokenRespDTO tokenRespDTO = new OAuth2AccessTokenRespDTO();
        OAuth2AccessTokenReqDTO oauth2AccessTokenReqDTO = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        String scope = OAuth2Util.buildScopeString(tokReqMsgCtx.getScope());
//        String tokenBindingId =checkToken(oauth2AccessTokenReqDTO); //token binding.
        // loading the stored application data
        OAuthAppDO oAuthAppDO = null;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(oauth2AccessTokenReqDTO.getClientId());
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Error while retrieving app information for clientId: "
                    + oauth2AccessTokenReqDTO.getClientId(), e);
        }

        if (log.isDebugEnabled()) {
            log.debug("Service Provider specific expiry time enabled for application : " +
                    oauth2AccessTokenReqDTO.getClientId() + ". Application access token expiry time : " +
                    oAuthAppDO.getApplicationAccessTokenExpiryTime() + ", User access token expiry time : " +
                    oAuthAppDO.getUserAccessTokenExpiryTime() + ", Refresh token expiry time : "
                    + oAuthAppDO.getRefreshTokenExpiryTime());
        }

        String tokenId;
        String accessToken;
        String refreshToken;
        String userStoreDomain = null;
        String grantType;

        Timestamp refreshTokenIssuedTime = null;
        long refreshTokenValidityPeriodInMillis = 0;

        tokenId = UUID.randomUUID().toString();
        grantType = oauth2AccessTokenReqDTO.getGrantType();
        try {
            accessToken = oauthIssuerImpl.accessToken(tokReqMsgCtx);
            refreshToken = oauthIssuerImpl.refreshToken(tokReqMsgCtx);

            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug("New access token (hashed): " + DigestUtils.sha256Hex(accessToken) +
                            " & new refresh token (hashed): " + DigestUtils.sha256Hex(refreshToken));
                } else {
                    log.debug("Access token and refresh token generated.");
                }
            }
        } catch (OAuthSystemException e) {
            throw new IdentityOAuth2Exception("Error when generating the tokens.", e);
        }

        boolean renew = OAuthServerConfiguration.getInstance().isRefreshTokenRenewalEnabled();

        // an active or expired token will be returned. since we do the validation for active or expired token in
        // validateGrant() no need to do it here again
        RefreshTokenValidationDataDO refreshTokenValidationDataDO = tokenMgtDAO
                .validateRefreshToken(oauth2AccessTokenReqDTO.getClientId(), oauth2AccessTokenReqDTO.getRefreshToken());

        long issuedTime = refreshTokenValidationDataDO.getIssuedTime().getTime();
        long refreshValidityMillis = refreshTokenValidationDataDO.getValidityPeriodInMillis();

        if (OAuth2Util.calculateValidityInMillis(issuedTime, refreshValidityMillis) >= 1000) {
            if (!renew) {
                // if refresh token renewal not enabled, we use existing one else we issue a new refresh token
                refreshToken = oauth2AccessTokenReqDTO.getRefreshToken();
                refreshTokenIssuedTime = refreshTokenValidationDataDO.getIssuedTime();
                refreshTokenValidityPeriodInMillis = refreshTokenValidationDataDO.getValidityPeriodInMillis();
            }
        } else {
            // todo add proper error message/error code
            return handleError(OAuthError.TokenResponse.INVALID_REQUEST, "Refresh token is expired.", oauth2AccessTokenReqDTO);
        }

        Timestamp timestamp = new Timestamp(new Date().getTime());

        // if reusing existing refresh token, use its original issued time
        if (refreshTokenIssuedTime == null) {
            refreshTokenIssuedTime = timestamp;
        }

        // Default Validity Period (in seconds)
        long validityPeriodInMillis = 0;
        if (oAuthAppDO.getUserAccessTokenExpiryTime() != 0) {
            validityPeriodInMillis = oAuthAppDO.getUserAccessTokenExpiryTime() * 1000;
        } else {
            validityPeriodInMillis = OAuthServerConfiguration.getInstance()
                    .getUserAccessTokenValidityPeriodInSeconds() * 1000;
        }

        // if a VALID validity period is set through the callback, then use it
        long callbackValidityPeriod = tokReqMsgCtx.getValidityPeriod();
        if (callbackValidityPeriod != OAuthConstants.UNASSIGNED_VALIDITY_PERIOD) {
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

        String tokenType;
        if (isOfTypeApplicationUser()) {
            tokenType = OAuthConstants.UserType.APPLICATION_USER;
        } else {
            tokenType = OAuthConstants.UserType.APPLICATION;
        }

        String clientId = oauth2AccessTokenReqDTO.getClientId();

        // set the validity period. this is needed by downstream handlers.
        // if this is set before - then this will override it by the calculated new value.
        tokReqMsgCtx.setValidityPeriod(validityPeriodInMillis);

        // set the refresh token validity period. this is needed by downstream handlers.
        // if this is set before - then this will override it by the calculated new value.
        tokReqMsgCtx.setRefreshTokenvalidityPeriod(refreshTokenValidityPeriodInMillis);

        // set access token issued time.this is needed by downstream handlers.
        tokReqMsgCtx.setAccessTokenIssuedTime(timestamp.getTime());

        // set refresh token issued time.this is needed by downstream handlers.
        tokReqMsgCtx.setRefreshTokenIssuedTime(refreshTokenIssuedTime.getTime());

        if (OAuth2Util.checkUserNameAssertionEnabled()) {
            accessToken = OAuth2Util.addUsernameToToken(tokReqMsgCtx.getAuthorizedUser(), accessToken);
            refreshToken = OAuth2Util.addUsernameToToken(tokReqMsgCtx.getAuthorizedUser(), refreshToken);

            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug("Encoded access token (hashed): " + DigestUtils.sha256Hex(accessToken) +
                            " & encoded refresh token (hashed): " + DigestUtils.sha256Hex(refreshToken));
                } else {
                    log.debug("Access token and refresh token encoded using Base64 encoding.");
                }
            }

            // logic to store access token into different tables when multiple user stores are configured.
            if (OAuth2Util.checkAccessTokenPartitioningEnabled()) {
                userStoreDomain = OAuth2Util.getUserStoreForFederatedUser(tokReqMsgCtx.getAuthorizedUser());
            }
        }

        AccessTokenDO accessTokenDO = new AccessTokenDO(clientId, tokReqMsgCtx.getAuthorizedUser(),
                tokReqMsgCtx.getScope(), timestamp, refreshTokenIssuedTime, validityPeriodInMillis,
                refreshTokenValidityPeriodInMillis, tokenType);

        accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE);
        accessTokenDO.setRefreshToken(refreshToken);
        accessTokenDO.setTokenId(tokenId);
        accessTokenDO.setAccessToken(accessToken);
        accessTokenDO.setGrantType(grantType);
//        if(!OAuth2Util.checkTB(tokReqMsgCtx,OAuthConstants.HTTP_TB_REFERRED_HEADER_NAME).isEmpty()){
//            accessTokenDO.settBhashAccess(OAuth2Util.hashTB(OAuth2Util.checkTB(tokReqMsgCtx,OAuthConstants.HTTP_TB_REFERRED_HEADER_NAME)));
//        }

        RefreshTokenValidationDataDO oldAccessToken =
                (RefreshTokenValidationDataDO) tokReqMsgCtx.getProperty(PREV_ACCESS_TOKEN);
        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Previous access token (hashed): " + DigestUtils.sha256Hex(oldAccessToken.getAccessToken()));
            }

        }

        String authorizedUser = tokReqMsgCtx.getAuthorizedUser().toString();
	    // set the previous access token state to "INACTIVE" and store new access token in single db connection
	    tokenMgtDAO.invalidateAndCreateNewToken(oldAccessToken.getTokenId(), OAuthConstants.TokenStates.TOKEN_STATE_INACTIVE, clientId,
	                                            UUID.randomUUID().toString(), accessTokenDO,
	                                            userStoreDomain);
        if (!accessToken.equals(accessTokenDO.getAccessToken())) {
            // Using latest active token.
            accessToken = accessTokenDO.getAccessToken();
            refreshToken = accessTokenDO.getRefreshToken();
        }
        //remove the previous access token from cache and add the new access token info to the cache,
        // if it's enabled.
        if (cacheEnabled) {
            // Remove the old access token from the OAuthCache
            boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(authorizedUser);
            String cacheKeyString;
            if (isUsernameCaseSensitive) {
                cacheKeyString = clientId + ":" + authorizedUser + ":" + scope;
            } else {
                cacheKeyString = clientId + ":" + authorizedUser.toLowerCase() + ":" + scope;
            }

            OAuthCacheKey oauthCacheKey = new OAuthCacheKey(cacheKeyString);
            OAuthCache.getInstance().clearCacheEntry(oauthCacheKey);

            // Remove the old access token from the AccessTokenCache
            OAuthCacheKey accessTokenCacheKey = new OAuthCacheKey(oldAccessToken.getAccessToken());
            OAuthCache.getInstance().clearCacheEntry(accessTokenCacheKey);

            // Add new access token to the OAuthCache
            OAuthCache.getInstance().addToCache(oauthCacheKey, accessTokenDO);

            // Add new access token to the AccessTokenCache
            accessTokenCacheKey = new OAuthCacheKey(accessToken);
            OAuthCache.getInstance().addToCache(accessTokenCacheKey, accessTokenDO);

            if (log.isDebugEnabled()) {
                log.debug("Access Token info for the refresh token was added to the cache for " +
                        "the client id : " + clientId + ". Old access token entry was " +
                        "also removed from the cache.");
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Persisted an access token for the refresh token, " +
                    "Client ID : " + clientId +
                    "authorized user : " + tokReqMsgCtx.getAuthorizedUser() +
                    "timestamp : " + timestamp +
                    "validity period (s) : " + accessTokenDO.getValidityPeriod() +
                    "scope : " + OAuth2Util.buildScopeString(tokReqMsgCtx.getScope()) +
                    "Token State : " + OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE +
                    "User Type : " + tokenType);
        }

        tokenRespDTO.setAccessToken(accessToken);
        tokenRespDTO.setRefreshToken(refreshToken);
        if (validityPeriodInMillis > 0) {
            tokenRespDTO.setExpiresIn(accessTokenDO.getValidityPeriod());
            tokenRespDTO.setExpiresInMillis(accessTokenDO.getValidityPeriodInMillis());
        } else {
            tokenRespDTO.setExpiresIn(Long.MAX_VALUE);
            tokenRespDTO.setExpiresInMillis(Long.MAX_VALUE);
        }
        tokenRespDTO.setAuthorizedScopes(scope);

        ArrayList<ResponseHeader> respHeaders = new ArrayList<>();
        ResponseHeader header = new ResponseHeader();
        header.setKey("DeactivatedAccessToken");
        header.setValue(oldAccessToken.getAccessToken());
        respHeaders.add(header);

        tokReqMsgCtx.addProperty(OAuthConstants.RESPONSE_HEADERS_PROPERTY, respHeaders.toArray(
                new ResponseHeader[respHeaders.size()]));

        return tokenRespDTO;
    }

    @Override
    public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

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
                    return false;
                }
            }
            tokReqMsgCtx.setScope(requestedScopes);
        }
        return super.validateScope(tokReqMsgCtx);
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
}

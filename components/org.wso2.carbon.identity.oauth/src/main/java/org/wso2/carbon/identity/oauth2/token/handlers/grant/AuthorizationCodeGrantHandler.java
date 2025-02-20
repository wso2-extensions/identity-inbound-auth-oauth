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
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.AuthorizationCodeValidationResult;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsUtils;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenBindings.NONE;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.buildCacheKeyStringForTokenWithUserId;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.getTimeToExpire;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.validatePKCE;
import static org.wso2.carbon.identity.openidconnect.OIDCConstants.CODE_ID;

/**
 * Implements the AuthorizationGrantHandler for the Grant Type : authorization_code.
 */
public class AuthorizationCodeGrantHandler extends AbstractAuthorizationGrantHandler {

    // This is used to keep the pre processed authorization code in the OAuthTokenReqMessageContext.
    private static final String AUTHZ_CODE = "AuthorizationCode";
    private static final int ALLOWED_MINIMUM_VALIDITY_PERIOD = 1000;
    private static final Log log = LogFactory.getLog(AuthorizationCodeGrantHandler.class);

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
        super.validateGrant(tokReqMsgCtx);
        OAuth2AccessTokenReqDTO tokenReq = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        AuthzCodeDO authzCodeBean = getPersistedAuthzCode(tokenReq);

        validateAuthzCodeFromRequest(authzCodeBean, tokenReq.getClientId(), tokenReq.getAuthorizationCode());
        try {
            // If redirect_uri was given in the authorization request,
            // token request should send matching redirect_uri value.
            validateCallbackUrlFromRequest(tokenReq.getCallbackURI(), authzCodeBean.getCallbackUrl());
            validatePKCECode(authzCodeBean, tokenReq.getPkceCodeVerifier());
            setPropertiesForTokenGeneration(tokReqMsgCtx, tokenReq, authzCodeBean);
        } finally {
            // After validating grant, authorization code is revoked. This is done to stop repetitive usage of
            // same authorization code in erroneous token requests.
            tokReqMsgCtx.addProperty(CODE_ID, authzCodeBean.getAuthzCodeId());
            revokeAuthorizationCode(authzCodeBean);
        }
        if (log.isDebugEnabled()) {
            log.debug("Found Authorization Code for Client : " + tokenReq.getClientId() +
                    ", authorized user : " + authzCodeBean.getAuthorizedUser() +
                    ", scope : " + OAuth2Util.buildScopeString(authzCodeBean.getScope()));
        }
        return true;
    }

    @Override
    public OAuth2AccessTokenRespDTO issue(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {
        OAuth2AccessTokenRespDTO tokenResp = super.issue(tokReqMsgCtx);
        String authzCode = retrieveAuthzCode(tokReqMsgCtx);
        deactivateAuthzCode(tokReqMsgCtx, tokenResp.getTokenId(), authzCode);
        clearAuthzCodeCache(tokReqMsgCtx, authzCode);
        return tokenResp;
    }

    /**
     * Build and return a string to be used as a lock for synchronous token issuance for refresh token grant type.
     *
     * @param tokReqMsgCtx        OAuthTokenReqMessageContext
     * @return A string to be used as a lock for synchronous token issuance for refresh token grant type.
     */
    public String buildSyncLockString(OAuthTokenReqMessageContext tokReqMsgCtx) {

        String clientId = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId();
        String authzCode = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getAuthorizationCode();
        String tokenBindingReference = OAuth2Util.getTokenBindingReferenceString(tokReqMsgCtx);
        String scope = OAuth2Util.buildScopeString(tokReqMsgCtx.getScope());

        return AUTHZ_CODE + ":" + clientId + ":" + authzCode + ":" + tokenBindingReference + ":" + scope;
    }

    private void setPropertiesForTokenGeneration(OAuthTokenReqMessageContext tokReqMsgCtx,
                                                 OAuth2AccessTokenReqDTO tokenReq, AuthzCodeDO authzCodeBean)
            throws IdentityOAuth2Exception {

        tokReqMsgCtx.setAuthorizedUser(authzCodeBean.getAuthorizedUser());
        tokReqMsgCtx.setScope(authzCodeBean.getScope());
        // keep the pre processed authz code as a OAuthTokenReqMessageContext property to avoid
        // calculating it again when issuing the access token.
        tokReqMsgCtx.addProperty(AUTHZ_CODE, tokenReq.getAuthorizationCode());
        this.setRARPropertiesForTokenGeneration(tokReqMsgCtx);
    }

    private boolean validateCallbackUrlFromRequest(String callbackUrlFromRequest,
                                                   String callbackUrlFromPersistedAuthzCode)
            throws IdentityOAuth2Exception {
        if (StringUtils.isEmpty(callbackUrlFromPersistedAuthzCode)) {
            return true;
        }

        if (!callbackUrlFromPersistedAuthzCode.equals(callbackUrlFromRequest)) {
            if (log.isDebugEnabled()) {
                log.debug("Received callback url in the request : " + callbackUrlFromRequest +
                        " is not matching with persisted callback url " + callbackUrlFromPersistedAuthzCode);
            }
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.VALIDATE_INPUT_PARAMS)
                        .inputParam(OAuthConstants.LogConstants.InputKeys.CALLBACK_URI, callbackUrlFromRequest)
                        .configParam(OAuthConstants.LogConstants.ConfigKeys.REGISTERED_CALLBACK_URI,
                                callbackUrlFromPersistedAuthzCode)
                        .resultMessage("Received callback URL does not match with the persisted.")
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED)
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION));
            }
            throw new IdentityOAuth2Exception("Callback url mismatch");
        }
        return true;
    }

    private void clearAuthzCodeCache(OAuthTokenReqMessageContext tokReqMsgCtx, String authzCode) {
        if (cacheEnabled) {
            String clientId = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId();
            OAuthCacheKey cacheKey = new OAuthCacheKey(OAuth2Util.buildCacheKeyStringForAuthzCode(
                    clientId, authzCode));
            OAuthCache.getInstance().clearCacheEntry(cacheKey);

            if (log.isDebugEnabled()) {
                log.debug("Cache was cleared for authorization code info for client id : " + clientId);
            }
        }
    }

    private void deactivateAuthzCode(OAuthTokenReqMessageContext tokReqMsgCtx, String tokenId,
                                     String authzCode) throws IdentityOAuth2Exception {
        try {
            // Here we deactivate the authorization and in the process update the tokenId against the authorization
            // code so that we can correlate the current access token that is valid against the authorization code.
            AuthzCodeDO authzCodeDO = new AuthzCodeDO();
            authzCodeDO.setAuthorizationCode(authzCode);
            authzCodeDO.setOauthTokenId(tokenId);
            authzCodeDO.setAuthzCodeId(tokReqMsgCtx.getProperty(CODE_ID).toString());
            OAuthTokenPersistenceFactory.getInstance().getAuthorizationCodeDAO()
                    .deactivateAuthorizationCode(authzCodeDO);
            if (log.isDebugEnabled()
                    && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.AUTHORIZATION_CODE)) {
                log.debug("Deactivated authorization code : " + authzCode);
            }
        } catch (IdentityException e) {
            throw new IdentityOAuth2Exception("Error occurred while deactivating authorization code", e);
        }
    }

    /**
     * Returns whether an unexpired, pre-generated token is served for this request
     * @param tokReqMsgCtx
     * @return
     */
    private boolean isExistingTokenUsed(OAuthTokenReqMessageContext tokReqMsgCtx) {
        if (tokReqMsgCtx.getProperty(EXISTING_TOKEN_ISSUED) != null) {
            if (log.isDebugEnabled()) {
                log.debug("Token request message context has 'existingTokenUsed' value : " +
                        tokReqMsgCtx.getProperty(EXISTING_TOKEN_ISSUED).toString());
            }
            return (Boolean) tokReqMsgCtx.getProperty(EXISTING_TOKEN_ISSUED);
        }
        if (log.isDebugEnabled()) {
            log.debug("'existingTokenUsed' property not set in token request message context");
        }
        return false;
    }

    /**
     * Get the token from the OAuthTokenReqMessageContext which is stored while validating the authorization code.
     * If it's not there (which is unlikely), recalculate it.
     * @param tokReqMsgCtx
     * @return
     */
    private String retrieveAuthzCode(OAuthTokenReqMessageContext tokReqMsgCtx) {
        String authzCode = (String) tokReqMsgCtx.getProperty(AUTHZ_CODE);
        if (authzCode == null) {
            if (log.isDebugEnabled()) {
                log.debug("authorization code is not saved in the token request message context for client : " +
                tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId());
            }
            authzCode = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getAuthorizationCode();
        }
        return authzCode;
    }

    @Override
    public boolean authorizeAccessDelegation(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {
        // authorization is handled when the authorization code was issued.
        return true;
    }

    @Override
    protected void storeAccessToken(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO, String userStoreDomain,
                                    AccessTokenDO newTokenBean, String newAccessToken, AccessTokenDO
                                            existingTokenBean)
            throws IdentityOAuth2Exception {
        try {
            newTokenBean.setAuthorizationCode(oAuth2AccessTokenReqDTO.getAuthorizationCode());
            OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                    .insertAccessToken(newAccessToken, oAuth2AccessTokenReqDTO.getClientId(),
                            newTokenBean, existingTokenBean, userStoreDomain);
        } catch (IdentityException e) {
            throw new IdentityOAuth2Exception(
                    "Error occurred while storing new access token", e);
        }
    }

    @Override
    public boolean issueRefreshToken() throws IdentityOAuth2Exception {

        return OAuthServerConfiguration.getInstance()
                .getValueForIsRefreshTokenAllowed(OAuthConstants.GrantTypes.AUTHORIZATION_CODE);
    }

    /**
     * Provides authorization code request details saved in cache or DB
     * @param tokenReqDTO
     * @return
     * @throws IdentityOAuth2Exception
     */
    private AuthzCodeDO getPersistedAuthzCode(OAuth2AccessTokenReqDTO tokenReqDTO) throws IdentityOAuth2Exception {

        AuthzCodeDO authzCodeDO;
        // If cache is enabled, check in the cache first.
        if (cacheEnabled) {
            OAuthCacheKey cacheKey = new OAuthCacheKey(OAuth2Util.buildCacheKeyStringForAuthzCode(
                    tokenReqDTO.getClientId(), tokenReqDTO.getAuthorizationCode()));
            authzCodeDO = (AuthzCodeDO) OAuthCache.getInstance().getValueFromCache(cacheKey);
            if (authzCodeDO != null) {
                return authzCodeDO;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Authorization Code Info was not available in cache for client id : "
                            + tokenReqDTO.getClientId());
                }
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Retrieving authorization code information from db for client id : " + tokenReqDTO.getClientId());
        }

        AuthorizationCodeValidationResult validationResult = OAuthTokenPersistenceFactory.getInstance()
                .getAuthorizationCodeDAO().validateAuthorizationCode(tokenReqDTO.getClientId(),
                        tokenReqDTO.getAuthorizationCode());
        if (validationResult != null) {
            if (!validationResult.isActiveCode()) {
                String tokenAlias = OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                        .getAccessTokenByTokenId(validationResult.getTokenId());
                //revoking access token issued for authorization code as per RFC 6749 Section 4.1.2
                revokeExistingAccessTokens(validationResult.getTokenId(), validationResult.getAuthzCodeDO());

                clearTokenCache(tokenAlias, validationResult.getTokenId());
                String scope = OAuth2Util.buildScopeString(validationResult.getAuthzCodeDO().getScope());
                OAuthUtil.clearOAuthCache(tokenReqDTO.getClientId(), validationResult.getAuthzCodeDO().
                        getAuthorizedUser(), scope);
            }
            // The user resident organization should be resolved for the organization SSO users.
            resolveUserResidentOrgForOrganizationSSOUsers(validationResult.getAuthzCodeDO().getAuthorizedUser(),
                    tokenReqDTO.getAuthorizationCode());
            return validationResult.getAuthzCodeDO();
        } else {
            // This means an invalid authorization code was sent for validation. We return null since higher
            // layers expect a null value for an invalid authorization code.
            return null;
        }
    }

    private void revokeExistingAccessTokens(String tokenId, AuthzCodeDO authzCodeDO) throws IdentityOAuth2Exception {

        String userId = null;
        try {
            userId = authzCodeDO.getAuthorizedUser().getUserId();
        } catch (UserIdNotFoundException e) {
            throw new IdentityOAuth2Exception("User id not found for user: "
                    + authzCodeDO.getAuthorizedUser().getLoggableMaskedUserId(), e);
        }
        String accessToken = OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                .getAccessTokenByTokenId(tokenId);
        // Fetching AccessTokenDO from DB before revoking the token.
        AccessTokenDO accessTokenDO = null;
        if (StringUtils.isNotBlank(accessToken)) {
            try {
                accessTokenDO = OAuth2Util.getAccessTokenDOFromTokenIdentifier(accessToken, true);
            } catch (IllegalArgumentException e) {
                if (StringUtils.equals(OAuth2Util.ACCESS_TOKEN_IS_NOT_ACTIVE_ERROR_MESSAGE, e.getMessage())) {
                    if (log.isDebugEnabled()) {
                        log.debug(String.format("Invalid token id: %s was found while revoking the access token",
                                tokenId));
                    }
                } else {
                    throw e;
                }
            }
        }
        OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO().revokeAccessToken(tokenId, userId);
        clearAccessTokenOAuthCache(accessTokenDO);

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.AUTHORIZATION_CODE)) {
                log.debug("Validated authorization code(hashed): " + DigestUtils.sha256Hex(authzCodeDO
                        .getAuthorizationCode()) + " for client: " + authzCodeDO.getConsumerKey() + " is not active. " +
                        "So revoking the access tokens issued for the authorization code.");
            } else {
                log.debug("Validated authorization code for client: " + authzCodeDO.getConsumerKey() + " is not " +
                        "active. So revoking the access tokens issued for the authorization code.");
            }
        }
        invokePostAccessTokenRevocationListeners(accessTokenDO);
    }

    /**
     * Invokes Post Access Token Revocation Listeners
     * @param accessTokenDO nullable AccessTokenDO
     */
    private void invokePostAccessTokenRevocationListeners(AccessTokenDO accessTokenDO) {

        if (accessTokenDO == null) {
            return;
        }
        OAuthEventInterceptor oAuthEventInterceptorProxy = OAuthComponentServiceHolder.getInstance()
                .getOAuthEventInterceptorProxy();
        if (oAuthEventInterceptorProxy != null && oAuthEventInterceptorProxy.isEnabled()) {
            try {
                oAuthEventInterceptorProxy.onPostTokenRevocationBySystem(accessTokenDO, new HashMap<>());
            } catch (IdentityOAuth2Exception e) {
                log.error("Error occurred when invoking post access token revoke listener. ", e);
            }
        }
    }

    private String buildCacheKeyForToken(String clientId, AuthzCodeDO authzCodeDO) throws IdentityOAuth2Exception {

        String scope = OAuth2Util.buildScopeString(authzCodeDO.getScope());
        try {
            return buildCacheKeyStringForTokenWithUserId(clientId, scope, authzCodeDO.getAuthorizedUser().getUserId(),
                    authzCodeDO.getAuthorizedUser().getFederatedIdPName(), authzCodeDO.getTokenBindingReference());
        } catch (UserIdNotFoundException e) {
            throw new IdentityOAuth2Exception("User id not available for user: "
                    + authzCodeDO.getAuthorizedUser().getLoggableUserId(), e);
        }
    }

    /**
     * Checks whether the retrieved authorization data is invalid, inactive or expired.
     * Returns true otherwise
     *
     * @param authzCodeBean
     * @param clientId
     * @return
     * @throws IdentityOAuth2Exception
     */
    private boolean validateAuthzCodeFromRequest(AuthzCodeDO authzCodeBean, String clientId, String authzCode)
            throws IdentityOAuth2Exception {

        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                OAuthConstants.LogConstants.ActionIDs.VALIDATE_AUTHORIZATION_CODE);
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            diagnosticLogBuilder.inputParam(LogConstants.InputKeys.CLIENT_ID, clientId)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
        }
        if (authzCodeBean == null) {
            // If no auth code details available, cannot proceed with Authorization code grant
            if (log.isDebugEnabled()) {
                log.debug("Invalid token request for client id: " + clientId +
                        "and couldn't find persisted data for authorization code: " + authzCode);
            }
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                diagnosticLogBuilder.resultMessage("Invalid authorization code received. Couldn't find persisted data" +
                                " for authorization code.")
                        .inputParam(OAuthConstants.LogConstants.InputKeys.AUTHORIZATION_CODE, authzCode)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED)
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            throw new IdentityOAuth2Exception("Invalid authorization code received from token request");
        }

        if (isInactiveAuthzCode(authzCodeBean)) {
            clearTokenCache(authzCodeBean, clientId);
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                diagnosticLogBuilder.resultMessage("Inactive authorization code received.")
                        .inputParam(OAuthConstants.LogConstants.InputKeys.AUTHORIZATION_CODE, authzCode)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            throw new IdentityOAuth2Exception("Inactive authorization code received from token request");
        }

        if (isAuthzCodeExpired(authzCodeBean) || isAuthzCodeRevoked(authzCodeBean)) {
            if (isAuthzCodeExpired(authzCodeBean)) {
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    diagnosticLogBuilder.resultMessage("Expired authorization code received.")
                            .inputParam("authorization code", authzCode)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
            } else if (isAuthzCodeRevoked(authzCodeBean)) {
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    diagnosticLogBuilder.resultMessage("Revoked authorization code received.")
                            .inputParam(OAuthConstants.LogConstants.InputKeys.AUTHORIZATION_CODE, authzCode)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
            }
            throw new IdentityOAuth2Exception("Expired or Revoked authorization code received from token request");
        }
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            diagnosticLogBuilder.resultMessage("Authorization code validation is successful.")
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        return true;
    }

    private void clearTokenCache(AuthzCodeDO authzCodeBean, String clientId) throws IdentityOAuth2Exception {

        if (cacheEnabled) {
            String cacheKeyString = buildCacheKeyForToken(clientId, authzCodeBean);
            OAuthCache.getInstance().clearCacheEntry(new OAuthCacheKey(cacheKeyString));
            if (log.isDebugEnabled()) {
                log.debug("Removed token from cache for user : " + authzCodeBean.getAuthorizedUser().toString() +
                        ", for client : " + clientId);
            }
        }
    }

    private void clearTokenCache(String tokenAlias, String tokenId) {

        if (cacheEnabled) {
            if (tokenAlias == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Received token alias is null. Skipping clearing token cache with token alias for " +
                            "tokenId : " + tokenId);
                }
                return;
            }
            OAuthCache.getInstance().clearCacheEntry(new OAuthCacheKey(tokenAlias));
            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug("Removed token from cache for token alias : " + tokenAlias);
                } else {
                    log.debug("Removed token from cache for token alias associated with tokenId : "
                            + tokenId);
                }
            }
        }
    }

    private boolean isInactiveAuthzCode(AuthzCodeDO authzCodeBean) {
        if (OAuthConstants.AuthorizationCodeState.INACTIVE.equals(authzCodeBean.getState())) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid access token request with Client Id : " + authzCodeBean.getConsumerKey() +
                        ", Inactive authorization code : " + authzCodeBean.getAuthorizationCode());
            }
            return true;
        }
        return false;
    }

    private boolean isAuthzCodeRevoked(AuthzCodeDO authzCodeBean) {
        if (OAuthConstants.AuthorizationCodeState.REVOKED.equals(authzCodeBean.getState())) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid access token request with Client Id : " + authzCodeBean.getConsumerKey() +
                        ", Revoked authorization code : " + authzCodeBean.getAuthorizationCode());
            }
            return true;
        }
        return false;
    }

    private boolean isAuthzCodeExpired(AuthzCodeDO authzCodeBean)
            throws IdentityOAuth2Exception {

        if (OAuthConstants.AuthorizationCodeState.EXPIRED.equals(authzCodeBean.getState())) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid access token request with Client Id : " + authzCodeBean.getConsumerKey() +
                        ", Expired authorization code : " + authzCodeBean.getAuthorizationCode());
            }
            return true;
        }

        long issuedTime = authzCodeBean.getIssuedTime().getTime();
        long validityPeriod = authzCodeBean.getValidityPeriod();

        // If the code is not valid for more than 1 sec, it is considered to be expired
        if (getTimeToExpire(issuedTime, validityPeriod) < ALLOWED_MINIMUM_VALIDITY_PERIOD) {
            markAsExpired(authzCodeBean);
            if (log.isDebugEnabled()) {
                log.debug("Authorization Code Issued Time(ms): " + issuedTime +
                        ", Validity Period: " + validityPeriod + ", Timestamp Skew: " +
                        OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000 +
                        ", Current Time: " + System.currentTimeMillis());
            }
            return true;
        }
        return false;
    }

    private void markAsExpired(AuthzCodeDO authzCodeBean) throws IdentityOAuth2Exception {

        OAuthTokenPersistenceFactory.getInstance().getAuthorizationCodeDAO()
                .updateAuthorizationCodeState(authzCodeBean.getAuthorizationCode(), authzCodeBean.getAuthzCodeId(),
                        OAuthConstants.AuthorizationCodeState.EXPIRED);
        if (log.isDebugEnabled()) {
            log.debug("Changed state of authorization code : " + authzCodeBean.getAuthorizationCode() + " to expired");
        }

        if (cacheEnabled) {
            // remove the authorization code from the cache
            OAuthCache.getInstance().clearCacheEntry(new OAuthCacheKey(
                    OAuth2Util.buildCacheKeyStringForAuthzCode(authzCodeBean.getConsumerKey(),
                            authzCodeBean.getAuthorizationCode())));
            if (log.isDebugEnabled()) {
                log.debug("Expired Authorization code issued for client " + authzCodeBean.getConsumerKey() +
                        " was removed from the cache.");
            }
        }
    }

    /**
     * Performs PKCE Validation for "Authorization Code" Grant Type
     *
     * @param authzCodeBean
     * @param verificationCode
     * @return true if PKCE is validated
     * @throws IdentityOAuth2Exception
     */
    private boolean validatePKCECode(AuthzCodeDO authzCodeBean, String verificationCode)
            throws IdentityOAuth2Exception {

        String pkceCodeChallenge = authzCodeBean.getPkceCodeChallenge();
        String pkceCodeChallengeMethod = authzCodeBean.getPkceCodeChallengeMethod();
        OAuthAppDO oAuthApp = getOAuthAppDO(authzCodeBean.getConsumerKey());
        if (!validatePKCE(pkceCodeChallenge, verificationCode, pkceCodeChallengeMethod, oAuthApp)) {
            //possible malicious oAuthRequest
            log.warn("Failed PKCE Verification for oAuth 2.0 request");
            if (log.isDebugEnabled()) {
                log.debug("PKCE code verification failed for client : " + authzCodeBean.getConsumerKey());
            }
            throw new IdentityOAuth2Exception("PKCE validation failed");
        }
        return true;
    }

    private void revokeAuthorizationCode(AuthzCodeDO authzCodeBean) throws IdentityOAuth2Exception {

        OAuthTokenPersistenceFactory.getInstance().getAuthorizationCodeDAO().updateAuthorizationCodeState(
                authzCodeBean.getAuthorizationCode(), authzCodeBean.getAuthzCodeId(),
                OAuthConstants.AuthorizationCodeState.REVOKED);
        if (log.isDebugEnabled()) {
            log.debug("Changed state of authorization code : " + authzCodeBean.getAuthorizationCode() + " to revoked");
        }
        if (cacheEnabled) {
            // remove the authorization code from the cache
            OAuthCache.getInstance().clearCacheEntry(new OAuthCacheKey(
                    OAuth2Util.buildCacheKeyStringForAuthzCode(authzCodeBean.getConsumerKey(),
                            authzCodeBean.getAuthorizationCode())));
            if (log.isDebugEnabled()) {
                log.debug("Revoked Authorization code issued for client " + authzCodeBean.getConsumerKey() +
                        " was removed from the cache.");
            }
        }
    }

    private OAuthAppDO getOAuthAppDO(String clientId) throws IdentityOAuth2Exception {
        try {
            return OAuth2Util.getAppInformationByClientId(clientId);
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Error while retrieving app information for client: " + clientId);
        }
    }

    /**
     * Method to remove access token cache entries from the OAuthCache
     *
     * @param accessTokenDO AccessTokenDO
     */
    private void clearAccessTokenOAuthCache(AccessTokenDO accessTokenDO) {

        if (cacheEnabled && accessTokenDO != null) {
            // remove the access token from the cache.
            String tokenBindingReference = NONE;
            if (accessTokenDO.getTokenBinding() != null &&
                    StringUtils.isNotBlank(accessTokenDO.getTokenBinding().getBindingReference())) {
                tokenBindingReference = accessTokenDO.getTokenBinding().getBindingReference();
            }

            OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), accessTokenDO.getAuthzUser(),
                    OAuth2Util.buildScopeString(accessTokenDO.getScope()), tokenBindingReference);
            OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), accessTokenDO.getAuthzUser(),
                    OAuth2Util.buildScopeString(accessTokenDO.getScope()));
            OAuthUtil.clearOAuthCache(accessTokenDO.getConsumerKey(), accessTokenDO.getAuthzUser());
            OAuthUtil.clearOAuthCache(accessTokenDO.getAccessToken());

            if (log.isDebugEnabled()) {
                log.debug("The access token issued for client " + accessTokenDO.getConsumerKey() +
                        " was removed from the cache.");
            }
        }
    }

    private void resolveUserResidentOrgForOrganizationSSOUsers(AuthenticatedUser authenticatedUser, String authzCode) {

        if (authenticatedUser.isFederatedUser() && FrameworkConstants.ORGANIZATION_LOGIN_IDP_NAME
                .equals(authenticatedUser.getFederatedIdPName())) {
            String userResideOrganization = resolveUserResidentOrganization(AuthorizationGrantCache.getInstance()
                    .getValueFromCacheByCode(new AuthorizationGrantCacheKey(authzCode)).getUserAttributes());
            authenticatedUser.setAccessingOrganization(userResideOrganization);
            authenticatedUser.setUserResidentOrganization(userResideOrganization);
        }
    }

    private String resolveUserResidentOrganization(Map<ClaimMapping, String> userAttributes) {

        for (Map.Entry<ClaimMapping, String> attributes : userAttributes.entrySet()) {
            if (FrameworkConstants.USER_ORGANIZATION_CLAIM.equals(
                    attributes.getKey().getLocalClaim().getClaimUri())) {
                return attributes.getValue();
            }
        }
        return null;
    }

    /**
     * Configures RAR properties for token generation in the OAuth 2.0 flow.
     * <p>
     * It checks if authorization details were included in the authorization code request and whether the
     * user has consented to these specific authorization details. Depending on user consent, it selects
     * the appropriate authorization details to be included in the token response.
     * </p>
     *
     * @param oAuthTokenReqMessageContext Context of the OAuth token request message.
     * @throws IdentityOAuth2Exception If an error occurs while retrieving authorization details.
     */
    private void setRARPropertiesForTokenGeneration(final OAuthTokenReqMessageContext oAuthTokenReqMessageContext)
            throws IdentityOAuth2Exception {

        final int tenantId =
                OAuth2Util.getTenantId(oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getTenantDomain());

        if (log.isDebugEnabled()) {
            log.debug("Retrieving user consented authorization details for user: "
                    + oAuthTokenReqMessageContext.getAuthorizedUser().getLoggableMaskedUserId());
        }

        final AuthorizationDetails authorizationCodeAuthorizationDetails = super.authorizationDetailsService
                .getAuthorizationCodeAuthorizationDetails(
                        oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getAuthorizationCode(),
                        tenantId);

        oAuthTokenReqMessageContext.setAuthorizationDetails(AuthorizationDetailsUtils
                .getTrimmedAuthorizationDetails(authorizationCodeAuthorizationDetails));
    }
}

/*
 * Copyright (c) 2013-2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth2.token.handlers.grant;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.action.execution.api.exception.ActionExecutionException;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionStatus;
import org.wso2.carbon.identity.action.execution.api.model.ActionType;
import org.wso2.carbon.identity.action.execution.api.model.Error;
import org.wso2.carbon.identity.action.execution.api.model.Failure;
import org.wso2.carbon.identity.action.execution.api.model.FlowContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockServiceException;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth.tokenprocessor.RefreshTokenGrantProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ServerException;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.ResponseHeader;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsUtils;
import org.wso2.carbon.identity.oauth2.token.AccessTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinder;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.FederatedAssociationManager;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.exception.FederatedAssociationManagerClientException;
import org.wso2.carbon.identity.user.profile.mgt.association.federation.exception.FederatedAssociationManagerException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkErrorConstants.ErrorMessages.ERROR_WHILE_CHECKING_ACCOUNT_LOCK_STATUS;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkErrorConstants.ErrorMessages.ERROR_WHILE_GETTING_USERNAME_ASSOCIATED_WITH_IDP;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.GrantTypes.REFRESH_TOKEN;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.REQUEST_BINDING_TYPE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenBindings.NONE;
import static org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration.JWT_TOKEN_TYPE;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.buildCacheKeyStringForTokenWithUserId;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.buildCacheKeyStringForTokenWithUserIdOrgId;

/**
 * Grant Type handler for Grant Type refresh_token which is used to get a new access token.
 */
public class RefreshGrantHandler extends AbstractAuthorizationGrantHandler {

    public static final String PREV_ACCESS_TOKEN = "previousAccessToken";
    public static final String SESSION_IDENTIFIER = "sessionIdentifier";
    public static final int LAST_ACCESS_TOKEN_RETRIEVAL_LIMIT = 10;
    public static final int ALLOWED_MINIMUM_VALIDITY_PERIOD = 1000;
    public static final String DEACTIVATED_ACCESS_TOKEN = "DeactivatedAccessToken";
    private static final Log log = LogFactory.getLog(RefreshGrantHandler.class);
    private boolean isHashDisabled = OAuth2Util.isHashDisabled();
    private static final String ACCOUNT_LOCK_ERROR_MESSAGE = "Account is locked for user %s in tenant %s. Cannot" +
            " login until the account is unlocked.";

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        super.validateGrant(tokReqMsgCtx);
        OAuth2AccessTokenReqDTO tokenReq = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        RefreshTokenValidationDataDO validationBean = getRefreshTokenGrantProcessor()
                .validateRefreshToken(tokReqMsgCtx);

        validateRefreshTokenInRequest(tokenReq, validationBean);

        TokenBinding tokenBinding = null;
        if (StringUtils.isNotBlank(validationBean.getTokenBindingReference()) && !NONE
                .equals(validationBean.getTokenBindingReference())) {
            Optional<TokenBinding> tokenBindingOptional = OAuthTokenPersistenceFactory.getInstance()
                    .getTokenBindingMgtDAO()
                    .getTokenBindingByBindingRef(validationBean.getTokenId(),
                            validationBean.getTokenBindingReference());
            if (tokenBindingOptional.isPresent()) {
                tokenBinding = tokenBindingOptional.get();
                tokReqMsgCtx.setTokenBinding(tokenBinding);
            }
        }
        validateTokenBindingReference(tokenReq, validationBean, tokenBinding);
        validateAuthenticatedUser(validationBean, tokReqMsgCtx);

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
        // An active or expired token will be returned. Since we do the validation for active or expired token in
        // validateGrant() no need to do it here again also no need to read it from DB again. Simply get it from
        // context property.
        RefreshTokenValidationDataDO validationBean = (RefreshTokenValidationDataDO) tokReqMsgCtx
                .getProperty(PREV_ACCESS_TOKEN);
        if (isRefreshTokenExpired(validationBean)) {
            return handleError(OAuth2ErrorCodes.INVALID_GRANT, "Refresh token is expired.", tokenReq);
        }

        tokReqMsgCtx.setValidityPeriod(validationBean.getAccessTokenValidityInMillis());

        if (checkExecutePreIssueAccessTokensActions(validationBean, tokReqMsgCtx) ||
                checkExecutePreIssueIdTokensActions(tokReqMsgCtx)) {
            setCustomizedTokenAttributesToMessageContext(validationBean, tokReqMsgCtx);
        }

        ActionExecutionStatus<?> executionStatus = executePreIssueAccessTokenActions(validationBean, tokReqMsgCtx);

        if (executionStatus != null && (executionStatus.getStatus() == ActionExecutionStatus.Status.FAILED ||
                executionStatus.getStatus() == ActionExecutionStatus.Status.ERROR)) {
            return getFailureOrErrorResponseDTO(executionStatus);
        }

        AccessTokenDO accessTokenBean;
        try {
            accessTokenBean = getRefreshTokenGrantProcessor()
                    .createAccessTokenBean(tokReqMsgCtx, tokenReq, validationBean, getTokenType(tokReqMsgCtx));
        } catch (IllegalArgumentException e) {
            if (StringUtils.equals(OAuth2Util.ACCESS_TOKEN_IS_NOT_ACTIVE_ERROR_MESSAGE, e.getMessage())) {
                return handleError(OAuth2ErrorCodes.INVALID_GRANT, "Refresh token is expired.", tokenReq);
            }
            throw e;
        }

        String scope = OAuth2Util.buildScopeString(tokReqMsgCtx.getScope());
        String consumerKey = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId();
        String authorizedUserId;
        try {
            authorizedUserId = tokReqMsgCtx.getAuthorizedUser().getUserId();
        } catch (UserIdNotFoundException e) {
            throw new IdentityOAuth2Exception("User id is not available for user: "
                    + tokReqMsgCtx.getAuthorizedUser().getLoggableMaskedUserId(), e);
        }
        String tokenBindingReference = getTokenBindingReference(tokReqMsgCtx);
        synchronized ((consumerKey + ":" + authorizedUserId + ":" + scope + ":" + tokenBindingReference).intern()) {
            // sets accessToken, refreshToken and validity data
            setTokenData(accessTokenBean, tokReqMsgCtx, validationBean, tokenReq, accessTokenBean.getIssuedTime());
            persistNewToken(tokReqMsgCtx, accessTokenBean, tokenReq.getClientId());
            super.authorizationDetailsService
                    .replaceAccessTokenAuthorizationDetails(validationBean.getTokenId(), accessTokenBean, tokReqMsgCtx);

            if (log.isDebugEnabled()) {
                log.debug("Persisted an access token for the refresh token, " +
                        "Client ID : " + tokenReq.getClientId() +
                        ", Authorized user : " + tokReqMsgCtx.getAuthorizedUser() +
                        ", Timestamp : " + accessTokenBean.getIssuedTime() +
                        ", Validity period (s) : " + accessTokenBean.getValidityPeriod() +
                        ", Scope : " + OAuth2Util.buildScopeString(tokReqMsgCtx.getScope()) +
                        ", Token State : " + OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE +
                        " and User Type : " + getTokenType(tokReqMsgCtx));
            }

            setTokenDataToMessageContext(tokReqMsgCtx, accessTokenBean);
            addUserAttributesToCache(accessTokenBean, tokReqMsgCtx);
        }
        return buildTokenResponse(tokReqMsgCtx, accessTokenBean);
    }

    private OAuth2AccessTokenRespDTO getFailureOrErrorResponseDTO(ActionExecutionStatus<?> executionStatus) {

        OAuth2AccessTokenRespDTO accessTokenResponse = new OAuth2AccessTokenRespDTO();
        accessTokenResponse.setError(true);
        if (executionStatus.getStatus() == ActionExecutionStatus.Status.FAILED) {
            Failure failureResponse = (Failure) executionStatus.getResponse();
            accessTokenResponse.setErrorCode(failureResponse.getFailureReason());
            accessTokenResponse.setErrorMsg(failureResponse.getFailureDescription());
        } else if (executionStatus.getStatus() == ActionExecutionStatus.Status.ERROR) {
            Error errorResponse = (Error) executionStatus.getResponse();
            accessTokenResponse.setErrorCode(errorResponse.getErrorMessage());
            accessTokenResponse.setErrorMsg(errorResponse.getErrorDescription());
        }
        return accessTokenResponse;
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
        String[] grantedInternalScopes = tokReqMsgCtx.getAuthorizedInternalScopes();
        if (ArrayUtils.isNotEmpty(requestedScopes)) {
            if (ArrayUtils.isEmpty(grantedScopes) && ArrayUtils.isEmpty(grantedInternalScopes)) {
                return false;
            }
            if (ArrayUtils.isEmpty(grantedScopes)) {
                grantedScopes = new String[0];
            }
            if (ArrayUtils.isEmpty(grantedInternalScopes)) {
                grantedInternalScopes = new String[0];
            }
            List<String> grantedScopeList = Stream.concat(Arrays.stream(grantedScopes),
                    Arrays.stream(grantedInternalScopes)).collect(Collectors.toList());
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

    /**
     * Build and return a string to be used as a lock for synchronous token issuance for refresh token grant type.
     *
     * @param tokReqMsgCtx        OAuthTokenReqMessageContext
     * @return A string to be used as a lock for synchronous token issuance for refresh token grant type.
     */
    public String buildSyncLockString(OAuthTokenReqMessageContext tokReqMsgCtx) {

        String clientId = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId();
        String refreshToken = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRefreshToken();
        String tokenBindingReference = OAuth2Util.getTokenBindingReferenceString(tokReqMsgCtx);
        String scope = OAuth2Util.buildScopeString(tokReqMsgCtx.getScope());

        return REFRESH_TOKEN + ":" + clientId + ":" + refreshToken + ":" + tokenBindingReference + ":" + scope;
    }

    private void setPropertiesForTokenGeneration(OAuthTokenReqMessageContext tokReqMsgCtx,
                                                 RefreshTokenValidationDataDO validationBean)
            throws IdentityOAuth2Exception {

        tokReqMsgCtx.setAuthorizedUser(validationBean.getAuthorizedUser());
        tokReqMsgCtx.setScope(validationBean.getScope());
        tokReqMsgCtx.getOauth2AccessTokenReqDTO().setAccessTokenExtendedAttributes(
                validationBean.getAccessTokenExtendedAttributes());
        propagateImpersonationInfo(tokReqMsgCtx);
        // Store the old access token as a OAuthTokenReqMessageContext property, this is already
        // a preprocessed token.
        tokReqMsgCtx.addProperty(PREV_ACCESS_TOKEN, validationBean);
        this.setRARPropertiesForTokenGeneration(tokReqMsgCtx, validationBean);

        /*
        Add the session id from the last access token to OAuthTokenReqMessageContext. First check whether the
        session Id can be resolved from the authorization grant cache. If not resolve the session id from the token
        id session id mapping in the token binding table. Here we are assigning the session id of the refreshed
        token as same as the previously issued access token.
        */
        String sessionId = getSessionContextIdentifier(validationBean.getAccessToken());
        if (sessionId == null) {
            String oldTokenId = validationBean.getTokenId();
            sessionId = OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                    .getSessionIdentifierByTokenId(oldTokenId);
        }
        if (sessionId != null) {
            tokReqMsgCtx.addProperty(SESSION_IDENTIFIER, sessionId);
        }
    }

    private void propagateImpersonationInfo(OAuthTokenReqMessageContext tokenReqMessageContext) {

        log.debug("Checking for impersonation information in token request");
        if (tokenReqMessageContext != null && tokenReqMessageContext.getOauth2AccessTokenReqDTO() != null &&
                tokenReqMessageContext.getOauth2AccessTokenReqDTO().getAccessTokenExtendedAttributes() != null) {
            String impersonator = tokenReqMessageContext.getOauth2AccessTokenReqDTO()
                    .getAccessTokenExtendedAttributes().getParameters()
                    .get(OAuthConstants.IMPERSONATING_ACTOR);
            if (StringUtils.isNotBlank(impersonator)) {
                tokenReqMessageContext.setImpersonationRequest(true);
                tokenReqMessageContext.addProperty(OAuthConstants.IMPERSONATING_ACTOR, impersonator);
                if (log.isDebugEnabled()) {
                    log.debug("Impersonation request identified for the user: " + impersonator);
                }
            }
        }
    }

    /**
     * Return session context identifier from authorization grant cache. For authorization code flow, we mapped it
     * against auth_code. For refresh token grant, we map the cache against the access token.
     *
     * @param key Authorization code or access token.
     * @return SessionContextIdentifier.
     */
    private static String getSessionContextIdentifier(String key) {

        String sessionContextIdentifier = null;
        if (StringUtils.isNotBlank(key)) {
            AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(key);
            AuthorizationGrantCacheEntry cacheEntry =
                    AuthorizationGrantCache.getInstance().getValueFromCacheByToken(cacheKey);
            if (cacheEntry != null) {
                sessionContextIdentifier = cacheEntry.getSessionContextIdentifier();
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Found session context identifier: %s for the obtained authorization code",
                            sessionContextIdentifier));
                }
            }
        }
        return sessionContextIdentifier;
    }

    private boolean validateRefreshTokenInRequest(OAuth2AccessTokenReqDTO tokenReq,
                                                  RefreshTokenValidationDataDO validationBean)
            throws IdentityOAuth2Exception {

        validateRefreshTokenStatus(validationBean, tokenReq.getClientId());
        if (getRefreshTokenGrantProcessor().isLatestRefreshToken(tokenReq,
                validationBean, getUserStoreDomain(validationBean.getAuthorizedUser()))) {
            return true;
        } else {
            removeIfCached(tokenReq, validationBean);
            throw new IdentityOAuth2Exception("Invalid refresh token value in the request");
        }
    }

    private void removeIfCached(OAuth2AccessTokenReqDTO tokenReq, RefreshTokenValidationDataDO validationBean)
            throws IdentityOAuth2Exception {

        if (cacheEnabled) {
            String userId;
            try {
                userId = validationBean.getAuthorizedUser().getUserId();
            } catch (UserIdNotFoundException e) {
                throw new IdentityOAuth2Exception("User id not found for user:"
                        + validationBean.getAuthorizedUser().getLoggableMaskedUserId(), e);
            }
            clearCache(tokenReq.getClientId(), userId,
                    validationBean.getScope(), validationBean.getAccessToken(),
                    validationBean.getAuthorizedUser().getFederatedIdPName(),
                    validationBean.getTokenBindingReference(), validationBean.getAuthorizedUser().getTenantDomain());
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

    private boolean validateAuthenticatedUser(RefreshTokenValidationDataDO validationBean,
                                              OAuthTokenReqMessageContext oAuthTokenReqMessageContext)
            throws IdentityOAuth2Exception {

        if (!OAuthServerConfiguration.getInstance().isValidateAuthenticatedUserForRefreshGrantEnabled()) {
            return true;
        }

        AuthenticatedUser authenticatedUser = validationBean.getAuthorizedUser();
        if (authenticatedUser != null) {
            String username = null;
            String tenantDomain = null;

            if (authenticatedUser.isFederatedUser()) {
                try {
                    FederatedAssociationManager federatedAssociationManager =
                            FrameworkUtils.getFederatedAssociationManager();
                    OAuthAppDO oAuthAppDO =
                            (OAuthAppDO) oAuthTokenReqMessageContext.getProperty(AccessTokenIssuer.OAUTH_APP_DO);
                    String oAuthAppTenantDomain = OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
                    String associatedLocalUsername =
                            federatedAssociationManager.getUserForFederatedAssociation(oAuthAppTenantDomain,
                                    authenticatedUser.getFederatedIdPName(),
                                    authenticatedUser.getAuthenticatedSubjectIdentifier());
                    if (associatedLocalUsername != null) {
                        username = associatedLocalUsername;
                        tenantDomain = oAuthAppTenantDomain;
                    }
                } catch (FederatedAssociationManagerClientException | FrameworkClientException e) {
                    throw new IdentityOAuth2ClientException(ERROR_WHILE_GETTING_USERNAME_ASSOCIATED_WITH_IDP.getCode(),
                            String.format(ERROR_WHILE_GETTING_USERNAME_ASSOCIATED_WITH_IDP.getMessage(),
                                    authenticatedUser.getFederatedIdPName()), e);
                } catch (FederatedAssociationManagerException | FrameworkException e) {
                    throw new IdentityOAuth2ServerException(ERROR_WHILE_GETTING_USERNAME_ASSOCIATED_WITH_IDP.getCode(),
                            String.format(ERROR_WHILE_GETTING_USERNAME_ASSOCIATED_WITH_IDP.getMessage(),
                                    authenticatedUser.getFederatedIdPName()), e);
                }
            } else {
                username = UserCoreUtil.addDomainToName(authenticatedUser.getUserName(),
                        authenticatedUser.getUserStoreDomain());
                tenantDomain = authenticatedUser.getTenantDomain();
            }

            checkAccountLockStatusOfTheUser(username, tenantDomain);
        }

        return true;
    }

    private void checkAccountLockStatusOfTheUser(String username, String tenantDomain)
            throws IdentityOAuth2Exception {

        if (username != null && tenantDomain != null) {
            AccountLockService accountLockService = OAuth2ServiceComponentHolder.getAccountLockService();

            try {
                boolean accountLockStatus = accountLockService.isAccountLocked(username, tenantDomain);
                if (accountLockStatus) {
                    throw new IdentityOAuth2ClientException(UserCoreConstants.ErrorCode.USER_IS_LOCKED,
                            String.format(ACCOUNT_LOCK_ERROR_MESSAGE, username, tenantDomain));
                }
            } catch (AccountLockServiceException e) {
                throw new IdentityOAuth2ServerException(ERROR_WHILE_CHECKING_ACCOUNT_LOCK_STATUS.getCode(),
                        String.format(ERROR_WHILE_CHECKING_ACCOUNT_LOCK_STATUS.getMessage(), username), e);
            }
        }
    }

    private OAuth2AccessTokenRespDTO buildTokenResponse(OAuthTokenReqMessageContext tokReqMsgCtx,
                                                        AccessTokenDO accessTokenBean) {

        String scope = OAuth2Util.buildScopeString(tokReqMsgCtx.getScope());
        OAuth2AccessTokenRespDTO tokenResp = new OAuth2AccessTokenRespDTO();
        tokenResp.setAccessToken(accessTokenBean.getAccessToken());
        tokenResp.setTokenId(accessTokenBean.getTokenId());
        tokenResp.setRefreshToken(accessTokenBean.getRefreshToken());
        long expireTimeMillis = accessTokenBean.getValidityPeriodInMillis();
        if (expireTimeMillis > 0) {
            tokenResp.setExpiresIn(accessTokenBean.getValidityPeriod());
            tokenResp.setExpiresInMillis(expireTimeMillis);
            long refreshTokenExpiresInMillis = accessTokenBean.getRefreshTokenValidityPeriodInMillis();
            if (refreshTokenExpiresInMillis > 0) {
                tokenResp.setRefreshTokenExpiresInMillis(refreshTokenExpiresInMillis);
            } else {
                tokenResp.setRefreshTokenExpiresInMillis(Long.MAX_VALUE);
            }
        } else {
            tokenResp.setExpiresIn(Long.MAX_VALUE);
            tokenResp.setExpiresInMillis(Long.MAX_VALUE);
            tokenResp.setRefreshTokenExpiresInMillis(Long.MAX_VALUE);
        }
        tokenResp.setAuthorizedScopes(scope);
        tokenResp.setIsConsentedToken(accessTokenBean.isConsentedToken());
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
        getRefreshTokenGrantProcessor().persistNewToken(tokReqMsgCtx,
                accessTokenBean, userStoreDomain, clientId);
        updateCacheIfEnabled(tokReqMsgCtx, accessTokenBean, clientId, oldAccessToken);
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
                // Masking getLoggableUserId as it will return the username because the user id is not available.
                throw new IdentityOAuth2Exception("User id is not available for user: " +
                        tokReqMsgCtx.getAuthorizedUser().getLoggableMaskedUserId(), e);
            }
            String authenticatedIDP = tokReqMsgCtx.getAuthorizedUser().getFederatedIdPName();
            String accessingOrganization = OAuthConstants.AuthorizedOrganization.NONE;
            if (!StringUtils.isEmpty(oldAccessToken.getAuthorizedUser().getAccessingOrganization())) {
                accessingOrganization = oldAccessToken.getAuthorizedUser().getAccessingOrganization();
            }
            String cacheKeyString = buildCacheKeyStringForTokenWithUserIdOrgId(clientId, scope, userId,
                    authenticatedIDP, oldAccessToken.getTokenBindingReference(), accessingOrganization);
            OAuthCacheKey oauthCacheKey = new OAuthCacheKey(cacheKeyString);
            OAuthCache.getInstance().clearCacheEntry(oauthCacheKey, accessTokenBean.getAuthzUser().getTenantDomain());

            // Remove old access token from the AccessTokenCache
            if (oldAccessToken.getAccessToken() != null) {
                OAuthCacheKey accessTokenCacheKey = new OAuthCacheKey(oldAccessToken.getAccessToken());
                OAuthCache.getInstance().clearCacheEntry(accessTokenCacheKey,
                        oldAccessToken.getAuthorizedUser().getTenantDomain());
            }
            /*
             * If no token persistence, the token will be not be cached against a cache key with userId, scope, client,
             * idp and binding reference. But, token will be cached and managed as an AccessTokenDO against the
             * token identifier.
             */
            if (OAuth2Util.isTokenPersistenceEnabled()) {
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
            }
            // Add new access token to the AccessTokenCache
            OAuth2Util.addTokenDOtoCache(accessTokenBean);

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

    private OAuthAppDO getOAuthApp(String clientId, String tenantDomain) throws IdentityOAuth2Exception {

        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId, tenantDomain);
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

    private void clearCache(String clientId, String authorizedUserId, String[] scopes, String accessToken,
                            String authenticatedIDP, String tokenBindingReference, String tenantDomain) {

        String cacheKeyString = buildCacheKeyStringForTokenWithUserId(clientId, OAuth2Util.buildScopeString(scopes),
                authorizedUserId, authenticatedIDP, tokenBindingReference);

        // Remove the old access token from the OAuthCache
        OAuthCacheKey oauthCacheKey = new OAuthCacheKey(cacheKeyString);
        OAuthCache.getInstance().clearCacheEntry(oauthCacheKey, tenantDomain);

        // Remove the old access token from the AccessTokenCache
        if (accessToken != null) {
            OAuthCacheKey accessTokenCacheKey = new OAuthCacheKey(accessToken);
            OAuthCache.getInstance().clearCacheEntry(accessTokenCacheKey, tenantDomain);
        }

    }

    private boolean isRefreshTokenExpired(RefreshTokenValidationDataDO validationBean) {

        long issuedTime = validationBean.getIssuedTime().getTime();
        long refreshValidity = validationBean.getValidityPeriodInMillis();
        if (refreshValidity < 0) {
            return false;
        } else {
            return OAuth2Util.getTimeToExpire(issuedTime, refreshValidity) < ALLOWED_MINIMUM_VALIDITY_PERIOD;
        }
    }

    private void setTokenData(AccessTokenDO accessTokenDO, OAuthTokenReqMessageContext tokReqMsgCtx,
                              RefreshTokenValidationDataDO validationBean, OAuth2AccessTokenReqDTO tokenReq,
                              Timestamp timestamp) throws IdentityOAuth2Exception {

        OAuthAppDO oAuthAppDO = getOAuthApp(tokenReq.getClientId(), validationBean.getAuthorizedUser().
                getTenantDomain());
        createTokens(accessTokenDO, tokReqMsgCtx);
        setRefreshTokenData(accessTokenDO, tokenReq, validationBean, oAuthAppDO, accessTokenDO.getRefreshToken(),
                timestamp, tokReqMsgCtx);
        handleRequestBinding(accessTokenDO, tokReqMsgCtx);
        modifyTokensIfUsernameAssertionEnabled(accessTokenDO, tokReqMsgCtx);
        setValidityPeriod(accessTokenDO, tokReqMsgCtx, oAuthAppDO);
    }

    private void handleRequestBinding(AccessTokenDO accessTokenDO, OAuthTokenReqMessageContext tokReqMsgCtx) {

        if (accessTokenDO.getTokenBinding() != null) {
            // Another token binding type is already set.
            return;
        }

        if (tokReqMsgCtx.getTokenBinding() != null &&
                REQUEST_BINDING_TYPE.equals(tokReqMsgCtx.getTokenBinding().getBindingType())) {
            /* Request binding is only set to the context if renew_token_without_revoking_existing config
             * is enabled and refresh token grant is set as an allowed grant type.
             */
            accessTokenDO.setTokenBinding(tokReqMsgCtx.getTokenBinding());
        }
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
            OauthTokenIssuer oauthTokenIssuer = OAuth2Util
                    .getOAuthTokenIssuerForOAuthApp(accessTokenDO.getConsumerKey());
            String accessToken = oauthTokenIssuer.accessToken(tokReqMsgCtx);
            String refreshToken = oauthTokenIssuer.refreshToken(tokReqMsgCtx);

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
            /* Below condition check is added in order to send a client error when the root cause of the exception is
               actually a client error and not an internal server error. */
            if (e.getCause() instanceof IdentityOAuth2ClientException) {
                throw (IdentityOAuth2ClientException) e.getCause();
            }
            throw new IdentityOAuth2Exception("Error when generating the tokens.", e);
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Error while retrieving oauth issuer for the app with clientId: " +
                    accessTokenDO.getConsumerKey(), e);
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
            validityPeriodInMillis = callbackValidityPeriod;
        }
        return validityPeriodInMillis;
    }

    private void setRefreshTokenData(AccessTokenDO accessTokenDO,
                                     OAuth2AccessTokenReqDTO tokenReq,
                                     RefreshTokenValidationDataDO validationBean,
                                     OAuthAppDO oAuthAppDO,
                                     String refreshToken, Timestamp timestamp,
                                     OAuthTokenReqMessageContext tokenReqMessageContext) {

        Timestamp refreshTokenIssuedTime = null;
        long refreshTokenValidityPeriod = 0;
        if (!isRenewRefreshToken(oAuthAppDO.getRenewRefreshTokenEnabled())) {
            // if refresh token renewal not enabled, we use existing one else we issue a new refresh token
            refreshToken = tokenReq.getRefreshToken();
            refreshTokenIssuedTime = validationBean.getIssuedTime();
            refreshTokenValidityPeriod = validationBean.getValidityPeriodInMillis();
        } else if (!OAuthServerConfiguration.getInstance().isExtendRenewedTokenExpiryTimeEnabled()) {
            // If refresh token renewal enabled and extend token expiry disabled, set the old token issued and validity.
            refreshTokenIssuedTime = validationBean.getIssuedTime();
            refreshTokenValidityPeriod = validationBean.getValidityPeriodInMillis();
        } else if (tokenReq.getAccessTokenExtendedAttributes() != null &&
                tokenReq.getAccessTokenExtendedAttributes().isExtendedToken()) {
            refreshTokenValidityPeriod = validationBean.getValidityPeriodInMillis();
        }
        if (refreshTokenIssuedTime == null) {
            refreshTokenIssuedTime = timestamp;
        }
        accessTokenDO.setRefreshToken(refreshToken);
        accessTokenDO.setRefreshTokenIssuedTime(refreshTokenIssuedTime);
        accessTokenDO.setRefreshTokenValidityPeriodInMillis(
                getRefreshTokenValidityPeriod(refreshTokenValidityPeriod, oAuthAppDO, tokenReqMessageContext));
    }

    private long getRefreshTokenValidityPeriod(long refreshTokenValidityPeriod, OAuthAppDO oAuthAppDO,
                                               OAuthTokenReqMessageContext tokenReqMessageContext) {
        // If issuing new refresh token, use default refresh token validity Period
        // otherwise use existing refresh token's validity period
        long validityPeriodFromMsgContext = tokenReqMessageContext.getRefreshTokenvalidityPeriod();
        /*
        Gives priority to the refresh token validity period specified in OAuthTokenReqMessageContext,
         in the following order:
         1. Set by a custom refresh grant handler.
         2. Overridden by pre-issue access token action execution.
         */
        if (validityPeriodFromMsgContext != OAuthConstants.UNASSIGNED_VALIDITY_PERIOD
                && validityPeriodFromMsgContext > 0) {
            refreshTokenValidityPeriod = validityPeriodFromMsgContext *
                    SECONDS_TO_MILISECONDS_FACTOR;
            if (log.isDebugEnabled()) {
                log.debug("OAuth application id : " + oAuthAppDO.getOauthConsumerKey() + ", using refresh token " +
                        "validity period configured from OAuthTokenReqMessageContext: " +
                        refreshTokenValidityPeriod + " ms");
            }
        } else if (tokenReqMessageContext.getRefreshTokenValidityPeriodInMillis() > 0) {
            refreshTokenValidityPeriod = tokenReqMessageContext.getRefreshTokenValidityPeriodInMillis();
        } else if (refreshTokenValidityPeriod == 0) {
            if (oAuthAppDO.getRefreshTokenExpiryTime() != 0) {
                refreshTokenValidityPeriod = oAuthAppDO.getRefreshTokenExpiryTime() * SECONDS_TO_MILISECONDS_FACTOR;
            } else {
                refreshTokenValidityPeriod = OAuthServerConfiguration.getInstance()
                        .getRefreshTokenValidityPeriodInSeconds() * SECONDS_TO_MILISECONDS_FACTOR;
            }
        }
        return refreshTokenValidityPeriod;
    }

    private static void addUserAttributesToCache(AccessTokenDO accessTokenBean,
                                                 OAuthTokenReqMessageContext msgCtx) {

        RefreshTokenValidationDataDO oldAccessToken =
                (RefreshTokenValidationDataDO) msgCtx.getProperty(PREV_ACCESS_TOKEN);
        if (oldAccessToken.getAccessToken() == null) {
            return;
        }
        AuthorizationGrantCacheKey oldAuthorizationGrantCacheKey = new AuthorizationGrantCacheKey(oldAccessToken
                .getAccessToken());
        if (log.isDebugEnabled()) {
            log.debug("Getting AuthorizationGrantCacheEntry using access token id: " + accessTokenBean.getTokenId());
        }
        AuthorizationGrantCacheEntry grantCacheEntry =
                AuthorizationGrantCache.getInstance().getValueFromCacheByTokenId(oldAuthorizationGrantCacheKey,
                        oldAccessToken.getTokenId());

        /*
         * When multiple concurrent refresh token requests occur using the same refresh token,
         * other nodes in the cluster may revoke the cache entries associated with the previous token.
         * However, since the current node is unaware of these deletions, it may fail to retrieve the
         * cache entry for the token. This block ensures that the cache is fetched using the given token ID,
         * even if the cache entry related to the token is marked as deleted.
         * This is done for JWT tokens and federated users only.
         */
        if (grantCacheEntry == null) {
            if (msgCtx.getAuthorizedUser() != null && msgCtx.getAuthorizedUser().isFederatedUser()) {
                OAuthAppDO oAuthAppDO = (OAuthAppDO) msgCtx.getProperty(AccessTokenIssuer.OAUTH_APP_DO);
                if (oAuthAppDO != null && OAuth2Util.JWT.equals(oAuthAppDO.getTokenType())) {
                    grantCacheEntry = AuthorizationGrantCache.getInstance()
                            .getValueFromCacheByTokenId(oldAuthorizationGrantCacheKey, oldAccessToken.getTokenId(),
                                    OAuth2Constants.STORE_OPERATION);
                }
            }
        }

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

            // Setting the validity period of the cache entry to be same as the validity period of the refresh token.
            grantCacheEntry.setValidityPeriod(
                    TimeUnit.MILLISECONDS.toNanos(accessTokenBean.getRefreshTokenValidityPeriodInMillis()));

            // This new method has introduced in order to resolve a regression occurred : wso2/product-is#4366.
            AuthorizationGrantCache.getInstance().clearCacheEntryByTokenId(oldAuthorizationGrantCacheKey,
                    oldAccessToken.getTokenId());
            AuthorizationGrantCache.getInstance().addToCacheByToken(authorizationGrantCacheKey, grantCacheEntry);
        }
    }

    private ActionExecutionStatus<?> executePreIssueAccessTokenActions(
            RefreshTokenValidationDataDO refreshTokenValidationDataDO,
            OAuthTokenReqMessageContext tokenReqMessageContext) throws IdentityOAuth2Exception {

        ActionExecutionStatus<?> executionStatus = null;
        if (checkExecutePreIssueAccessTokensActions(refreshTokenValidationDataDO, tokenReqMessageContext)) {

            FlowContext flowContext = FlowContext.create().add("tokenMessageContext", tokenReqMessageContext);

            try {
                executionStatus = OAuthComponentServiceHolder.getInstance().getActionExecutorService()
                        .execute(ActionType.PRE_ISSUE_ACCESS_TOKEN, flowContext,
                                IdentityTenantUtil.getTenantDomain(IdentityTenantUtil.getLoginTenantId()));
                if (log.isDebugEnabled()) {
                    log.debug(String.format(
                            "Invoked pre issue access token action for clientID: %s grant types: %s. Status: %s",
                            tokenReqMessageContext.getOauth2AccessTokenReqDTO().getClientId(),
                            tokenReqMessageContext.getOauth2AccessTokenReqDTO().getGrantType(),
                            Optional.ofNullable(executionStatus).isPresent() ? executionStatus.getStatus() : "NA"));
                }
            } catch (ActionExecutionException e) {
                throw new IdentityOAuth2Exception("Error occurred while executing pre issue access token actions.", e);
            }
        }
        return executionStatus;
    }

    private boolean checkExecutePreIssueAccessTokensActions(RefreshTokenValidationDataDO refreshTokenValidationDataDO,
                                                            OAuthTokenReqMessageContext tokenReqMessageContext)
            throws IdentityOAuth2Exception {

        String clientId = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getClientId();
        String tenantDomain = refreshTokenValidationDataDO.getAuthorizedUser().getTenantDomain();
        OAuthAppDO oAuthAppBean = getOAuthApp(clientId, tenantDomain);
        String grantType = refreshTokenValidationDataDO.getGrantType();

        // Allow if refresh token is issued for token requests from following grant types and,
        // for JWT access tokens if pre issue access token action invocation is enabled at server level.
        return OAuthComponentServiceHolder.getInstance().getActionExecutorService()
                .isExecutionEnabled(ActionType.PRE_ISSUE_ACCESS_TOKEN) &&
                (OAuthConstants.GrantTypes.AUTHORIZATION_CODE.equals(grantType) ||
                        OAuthConstants.GrantTypes.PASSWORD.equals(grantType) ||
                        OAuthConstants.GrantTypes.REFRESH_TOKEN.equals(grantType)) &&
                JWT_TOKEN_TYPE.equals(oAuthAppBean.getTokenType());
    }

    /**
     * Check whether to execute pre issue ID token actions.
     *
     * @param tokenReqMessageContext OAuthTokenReqMessageContext
     * @return true if pre issue ID token actions execution is enabled
     * @throws IdentityOAuth2Exception Error when checking action execution is failed
     */
    private boolean checkExecutePreIssueIdTokensActions(OAuthTokenReqMessageContext tokenReqMessageContext)
            throws IdentityOAuth2Exception {

        String clientId = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getClientId();
        String tenantDomain = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getTenantDomain();
        boolean isSystemApplication = IdentityTenantUtil.isSystemApplication(tenantDomain, clientId);

        String grantType = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getGrantType();
        // Allow for following grant types and for JWT access tokens if,
        boolean isGrantTypeAllowed = (OAuthConstants.GrantTypes.AUTHORIZATION_CODE.equals(grantType) ||
                OAuthConstants.GrantTypes.PASSWORD.equals(grantType) ||
                OAuthConstants.GrantTypes.REFRESH_TOKEN.equals(grantType) ||
                OAuthConstants.GrantTypes.DEVICE_CODE_URN.equals(grantType) ||
                OAuthConstants.GrantTypes.ORGANIZATION_SWITCH.equals(grantType));
        // Pre-issue ID token action invocation is enabled at server level.
        // For the System applications, pre issue ID token actions will not be executed.
        // Fragment apps are used for internal authentication purposes(B2B scenarios) hence action execution is skipped.
        return !isSystemApplication && OAuthComponentServiceHolder.getInstance().getActionExecutorService()
                .isExecutionEnabled(ActionType.PRE_ISSUE_ID_TOKEN) && isGrantTypeAllowed
                && !OAuth2Util.isFragmentApp(clientId, tenantDomain);
    }

    private void setCustomizedTokenAttributesToMessageContext(RefreshTokenValidationDataDO refreshTokenData,
                                                              OAuthTokenReqMessageContext tokenRequestContext) {

        AuthorizationGrantCacheKey grantCacheKey = new AuthorizationGrantCacheKey(refreshTokenData.getTokenId());
        AuthorizationGrantCacheEntry grantCacheEntry = AuthorizationGrantCache.getInstance()
                .getValueFromCacheByTokenId(grantCacheKey, refreshTokenData.getTokenId());

        if (grantCacheEntry != null) {
            if (grantCacheEntry.isPreIssueAccessTokenActionsExecuted()) {
                tokenRequestContext.setPreIssueAccessTokenActionsExecuted(true);
                tokenRequestContext.setAdditionalAccessTokenClaims(grantCacheEntry.getCustomClaims());
                tokenRequestContext.setAudiences(grantCacheEntry.getAudiences());
                log.debug("Updated OAuthTokenReqMessageContext with customized audience list and access token" +
                        " attributes in the AuthorizationGrantCache for token id: " + refreshTokenData.getTokenId());
                tokenRequestContext.setRefreshTokenValidityPeriodInMillis(
                        TimeUnit.NANOSECONDS.toMillis(grantCacheEntry.getValidityPeriod()));
            }

            if (grantCacheEntry.isPreIssueIDTokenActionsExecuted()) {
                tokenRequestContext.setPreIssueIDTokenActionsExecuted(true);
                tokenRequestContext.setPreIssueIDTokenActionDTO(grantCacheEntry.getPreIssueIDTokenActionDTO());
                log.debug("Updated OAuthTokenReqMessageContext with customized ID token attributes in the" +
                        " AuthorizationGrantCache for token id: " + refreshTokenData.getTokenId());
            }

            AuthorizationGrantCache.getInstance().clearCacheEntryByToken(grantCacheKey);
        }
    }

    private boolean isRenewRefreshToken(String renewRefreshToken) {

        if (StringUtils.isNotBlank(renewRefreshToken)) {
            if (log.isDebugEnabled()) {
                log.debug("Reading the Oauth application specific renew " +
                        "refresh token value as " + renewRefreshToken + " from the IDN_OIDC_PROPERTY table");
            }
            return Boolean.parseBoolean(renewRefreshToken);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Reading the global renew refresh token value from the identity.xml");
            }
            return OAuthServerConfiguration.getInstance().isRefreshTokenRenewalEnabled();
        }
    }

    private void validateTokenBindingReference(OAuth2AccessTokenReqDTO tokenReqDTO,
                                               RefreshTokenValidationDataDO validationDataDO,
                                               TokenBinding tokenBinding)
            throws IdentityOAuth2Exception {

        if (tokenBinding == null) {
            return;
        }

        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(tokenReqDTO.getClientId());
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception(
                    "Failed load the application with client id: " + tokenReqDTO.getClientId());
        }

        if (StringUtils.isBlank(oAuthAppDO.getTokenBindingType())) {
            return;
        }

        // Validate SSO session bound token.
        if (OAuth2Constants.TokenBinderType.SSO_SESSION_BASED_TOKEN_BINDER.equals(oAuthAppDO.getTokenBindingType())) {

            if (!OAuth2Util.isLegacySessionBoundTokenBehaviourEnabled()
                    || (oAuthAppDO.isTokenRevocationWithIDPSessionTerminationEnabled()
                    && !OAuth2Util.isSessionBoundTokensAllowedAfterSessionExpiry())) {
                if (!isTokenBoundToActiveSSOSession(tokenBinding.getBindingValue(),
                        validationDataDO.getAuthorizedUser())) {
                    // Revoke the SSO session bound access token if the session is invalid/terminated.
                    revokeSSOSessionBoundToken(validationDataDO.getAccessToken());
                    throw new IdentityOAuth2Exception("Token binding validation failed. Token is not bound to an " +
                            "active SSO session.");
                }
            }
        }

        Optional<TokenBinder> tokenBinderOptional = OAuth2ServiceComponentHolder.getInstance()
                .getTokenBinder(oAuthAppDO.getTokenBindingType());
        if (!tokenBinderOptional.isPresent()) {
            throw new IdentityOAuth2Exception(
                    "Token binder for the binding type: " + oAuthAppDO.getTokenBindingType() + " is not registered.");
        }

        TokenBinder tokenBinder = tokenBinderOptional.get();

        if ((oAuthAppDO.isTokenBindingValidationEnabled()) && !tokenBinder
                .isValidTokenBinding(tokenReqDTO, validationDataDO.getTokenBindingReference())) {
            throw new IdentityOAuth2Exception("Invalid token binding value is present in the request.");
        }
    }

    /**
     * Get the RefreshTokenGrantProcessor.
     *
     * @return RefreshTokenGrantProcessor
     */
    private RefreshTokenGrantProcessor getRefreshTokenGrantProcessor() {

        return OAuth2ServiceComponentHolder.getInstance().getRefreshTokenGrantProcessor();
    }

    /**
     * Sets the RAR properties for token generation.
     * <p> It retrieves the token authorization details based on the provided OAuth token request context. </p>
     *
     * @param oAuthTokenReqMessageContext Context of the OAuth token request message.
     * @param validationBean              Refresh token validation data.
     * @throws IdentityOAuth2Exception If an error occurs while retrieving authorization details.
     */
    private void setRARPropertiesForTokenGeneration(final OAuthTokenReqMessageContext oAuthTokenReqMessageContext,
                                                      final RefreshTokenValidationDataDO validationBean)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving token authorization details for user: "
                    + oAuthTokenReqMessageContext.getAuthorizedUser().getLoggableMaskedUserId());
        }

        final int tenantId =
                OAuth2Util.getTenantId(oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getTenantDomain());

        AuthorizationDetails tokenAuthorizationDetails = super.authorizationDetailsService
                .getAccessTokenAuthorizationDetails(validationBean.getTokenId(), tenantId);

        oAuthTokenReqMessageContext.setAuthorizationDetails(AuthorizationDetailsUtils
                .getTrimmedAuthorizationDetails(tokenAuthorizationDetails));
    }

    /**
     * Check whether the SSO-session-bound access token is still tied to an active SSO session.
     *
     * @param sessionIdentifier     Session identifier.
     * @param authenticatedUser     Authenticated user.
     * @return True if the token is bound to an active SSO session, false otherwise.
     */
    private boolean isTokenBoundToActiveSSOSession(String sessionIdentifier, AuthenticatedUser authenticatedUser) {

        SessionContext sessionContext =
                FrameworkUtils.getSessionContextFromCache(sessionIdentifier, authenticatedUser.getTenantDomain());
        if (sessionContext == null) {
            if (log.isDebugEnabled()) {
                log.debug("Session context is not found corresponding to the session identifier: " +
                        sessionIdentifier);
            }
            return false;
        }

        if (log.isDebugEnabled()) {
            log.debug("SSO session validation successful for the given session identifier: " + sessionIdentifier);
        }
        return true;
    }

    /**
     * Revoke the SSO session bound access token if the associated session is terminated.
     * This is only applicable for the applications that have enabled 'revokeTokensWhenIdPSessionTerminated'.
     *
     * @param accessTokenIdentifier Access token identifier.
     */
    private void revokeSSOSessionBoundToken(String accessTokenIdentifier) {

        try {
            AccessTokenDO accessTokenDO =
                    OAuth2Util.getAccessTokenDOFromTokenIdentifier(accessTokenIdentifier, true);
            OAuthUtil.clearOAuthCache(accessTokenDO);
            OAuthRevocationRequestDTO revokeRequestDTO = new OAuthRevocationRequestDTO();
            revokeRequestDTO.setConsumerKey(accessTokenDO.getConsumerKey());
            revokeRequestDTO.setToken(accessTokenDO.getAccessToken());
            OAuth2ServiceComponentHolder.getInstance().getRevocationProcessor()
                    .revokeAccessToken(revokeRequestDTO, accessTokenDO);
        } catch (IdentityOAuth2Exception | UserIdNotFoundException e) {
            log.error("Error while revoking SSO session bound access token.", e);
        }
    }
}

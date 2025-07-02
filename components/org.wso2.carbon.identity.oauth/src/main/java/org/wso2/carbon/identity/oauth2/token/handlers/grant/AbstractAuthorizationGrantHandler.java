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
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.action.execution.api.exception.ActionExecutionException;
import org.wso2.carbon.identity.action.execution.api.model.ActionExecutionStatus;
import org.wso2.carbon.identity.action.execution.api.model.ActionType;
import org.wso2.carbon.identity.action.execution.api.model.Error;
import org.wso2.carbon.identity.action.execution.api.model.Failure;
import org.wso2.carbon.identity.action.execution.api.model.FlowContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.callback.OAuthCallback;
import org.wso2.carbon.identity.oauth.callback.OAuthCallbackManager;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenExtendedAttributes;
import org.wso2.carbon.identity.oauth2.rar.AuthorizationDetailsService;
import org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsUtils;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.util.Oauth2ScopeUtils;
import org.wso2.carbon.identity.oauth2.validators.OAuth2ScopeHandler;
import org.wso2.carbon.identity.oauth2.validators.scope.ScopeValidator;
import org.wso2.carbon.identity.openidconnect.OIDCClaimUtil;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.utils.DiagnosticLog;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.IMPERSONATING_ACTOR;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAUTH_APP;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.RENEW_TOKEN_WITHOUT_REVOKING_EXISTING_ENABLE_CONFIG;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenBindings.NONE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE;
import static org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration.JWT_TOKEN_TYPE;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.EXTENDED_REFRESH_TOKEN_DEFAULT_TIME;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.JWT;

/**
 * Abstract authorization grant handler.
 */
public abstract class AbstractAuthorizationGrantHandler implements AuthorizationGrantHandler {

    private static final Log log = LogFactory.getLog(AbstractAuthorizationGrantHandler.class);
    protected OauthTokenIssuer oauthIssuerImpl = OAuthServerConfiguration.getInstance().getIdentityOauthTokenIssuer();
    protected OAuthCallbackManager callbackManager;
    protected boolean cacheEnabled;
    protected OAuthCache oauthCache;
    protected static final String EXISTING_TOKEN_ISSUED = "existingTokenUsed";
    protected static final int SECONDS_TO_MILISECONDS_FACTOR = 1000;
    private boolean isHashDisabled = OAuth2Util.isHashDisabled();
    protected AuthorizationDetailsService authorizationDetailsService;

    @Override
    public void init() throws IdentityOAuth2Exception {
        callbackManager = new OAuthCallbackManager();
        // Check whether OAuth caching is enabled.
        if (OAuthCache.getInstance().isEnabled()) {
            cacheEnabled = true;
            oauthCache = OAuthCache.getInstance();
        }
        this.authorizationDetailsService = OAuth2ServiceComponentHolder.getInstance().getAuthorizationDetailsService();
    }

    @Override
    public boolean isConfidentialClient() throws IdentityOAuth2Exception {
        return true;
    }

    @Override
    public boolean issueRefreshToken() throws IdentityOAuth2Exception {
        return true;
    }

    @Override
    public boolean isOfTypeApplicationUser() throws IdentityOAuth2Exception {
        return true;
    }

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {
        if (tokReqMsgCtx.getOauth2AccessTokenReqDTO() != null) {
            return true;
        } else {
            throw new IdentityOAuth2Exception("Token request data not found in the request message context");
        }

    }

    @Override
    public OAuth2AccessTokenRespDTO issue(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        String scope = OAuth2Util.buildScopeString(tokReqMsgCtx.getScope());
        String consumerKey = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId();
        String authorizedUserId;
        try {
            authorizedUserId = tokReqMsgCtx.getAuthorizedUser().getUserId();
        } catch (UserIdNotFoundException e) {
            throw new IdentityOAuth2Exception(
                    "User id is not available for user: " +
                            tokReqMsgCtx.getAuthorizedUser().getLoggableMaskedUserId(), e);
        }
        String authenticatedIDP = OAuth2Util.getAuthenticatedIDP(tokReqMsgCtx.getAuthorizedUser());
        String tokenBindingReference = getTokenBindingReference(tokReqMsgCtx);
        String authorizedOrganization = getAuthorizedOrganization(tokReqMsgCtx);

        // If the authorizedOrganization is deactivated or not available, return an error.
        if (!(OAuthConstants.AuthorizedOrganization.NONE.equals(authorizedOrganization) ||
                StringUtils.isBlank(authorizedOrganization)) &&
                !OAuth2Util.isOrganizationValidAndActive(authorizedOrganization)) {
            throw new IdentityOAuth2ClientException(OAuth2ErrorCodes.INVALID_REQUEST,
                    "Organization : " + authorizedOrganization + " is invalid or inactive.");
        }

        OauthTokenIssuer oauthTokenIssuer;
        try {
            oauthTokenIssuer = OAuth2Util.getOAuthTokenIssuerForOAuthApp(consumerKey);
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception(
                    "Error while retrieving oauth issuer for the app with clientId: " + consumerKey, e);
        }

        synchronized ((consumerKey + ":" + authorizedUserId + ":" + scope + ":" + tokenBindingReference).intern()) {
            AccessTokenDO existingTokenBean = null;

            OAuthAppDO oAuthAppDO = (OAuthAppDO) tokReqMsgCtx.getProperty(OAUTH_APP);
            String tokenType = oauthTokenIssuer.getAccessTokenType();

            /*
            Check if the token type is JWT and renew without revoking existing tokens is enabled.
            Additionally, ensure that the grant type used for the token request is allowed to renew without revoke,
            based on the config.
            */
            if (JWT.equalsIgnoreCase(tokenType) && getRenewWithoutRevokingExistingStatus() &&
                    OAuth2ServiceComponentHolder.getJwtRenewWithoutRevokeAllowedGrantTypes()
                            .contains(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType())) {
                /*
                If the application does not have a token binding type (i.e., no specific binding type is set),
                binding reference will be randomly generated UUID, in that case we can generate a new access token
                without looking up the existing tokens in the token table.
                */
                if (oAuthAppDO.getTokenBindingType() == null) {
                    return generateNewAccessToken(tokReqMsgCtx, scope, consumerKey, existingTokenBean,
                            false, oauthTokenIssuer);
                }
            }

            if (isHashDisabled) {
                existingTokenBean = getExistingToken(tokReqMsgCtx,
                        getOAuthCacheKey(scope, consumerKey, authorizedUserId, authenticatedIDP,
                                tokenBindingReference, authorizedOrganization));
            }

            if (existingTokenBean != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Latest access token is found in the OAuthCache for the app: " + consumerKey);
                }
                if (accessTokenRenewedPerRequest(oauthTokenIssuer, tokReqMsgCtx)) {
                    if (log.isDebugEnabled()) {
                        log.debug("TokenRenewalPerRequest is enabled. " +
                                "Proceeding to revoke any existing active tokens and issue new token for client Id: " +
                                consumerKey + ", user: " + authorizedUserId + " and scope: " + scope + ".");
                    }
                    return renewAccessToken(tokReqMsgCtx, scope, consumerKey, existingTokenBean, oauthTokenIssuer);
                }

                long expireTime = getAccessTokenExpiryTimeMillis(existingTokenBean);
                if (isExistingTokenValid(existingTokenBean, expireTime)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Existing token is active for client Id: " + consumerKey + ", user: " +
                                authorizedUserId + " and scope: " + scope + ". Therefore issuing the same token.");
                    }
                    return issueExistingAccessToken(tokReqMsgCtx, scope, expireTime, existingTokenBean);
                }
            }

            if (log.isDebugEnabled()) {
                log.debug("No active access token found for client Id: " + consumerKey + ", user: " +
                        authorizedUserId + " and scope: " + scope + ". Therefore issuing new token.");
            }
            return generateNewAccessToken(tokReqMsgCtx, scope, consumerKey, existingTokenBean, true,
                    oauthTokenIssuer);
        }
    }

    private void setDetailsToMessageContext(OAuthTokenReqMessageContext tokReqMsgCtx, AccessTokenDO existingToken) {

        if (existingToken.getIssuedTime() != null) {
            tokReqMsgCtx.setAccessTokenIssuedTime(existingToken.getIssuedTime().getTime());
        }
        if (existingToken.getRefreshTokenIssuedTime() != null) {
            tokReqMsgCtx.setRefreshTokenIssuedTime(existingToken.getRefreshTokenIssuedTime().getTime());
        }

        tokReqMsgCtx.setRefreshTokenvalidityPeriod(existingToken.getRefreshTokenValidityPeriodInMillis());
    }

    @Override
    public boolean isAuthorizedClient(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
        OAuth2AccessTokenReqDTO tokenReqDTO = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        String grantType = tokenReqDTO.getGrantType();

        OAuthAppDO oAuthAppBean = (OAuthAppDO) tokReqMsgCtx.getProperty("OAuthAppDO");

        if (oAuthAppBean == null) {
            if (log.isDebugEnabled()) {
                log.debug("OAuthAppDO is not available in OAuthTokenReqMessageContext for client id: " + tokenReqDTO
                        .getClientId());
            }
            return false;
        }
        if (StringUtils.isBlank(oAuthAppBean.getGrantTypes())) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find authorized grant types for client id: " + tokenReqDTO.getClientId());
            }
            return false;
        }

        // If the application has defined a limited set of grant types, then check the grant
        if (!oAuthAppBean.getGrantTypes().contains(grantType)) {
            if (log.isDebugEnabled()) {
                //Do not change this log format as these logs use by external applications
                log.debug("Unsupported Grant Type : " + grantType + " for client id : " + tokenReqDTO.getClientId());
            }
            return false;
        }
        return true;
    }

    @Override
    public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        if (hasValidationByApplicationScopeValidatorsFailed(tokReqMsgCtx)) {
            return false;
        }
        OAuthCallback scopeValidationCallback = new OAuthCallback(tokReqMsgCtx.getAuthorizedUser(),
                tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId(), OAuthCallback.OAuthCallbackType
                .SCOPE_VALIDATION_TOKEN);
        scopeValidationCallback.setRequestedScope(tokReqMsgCtx.getScope());
        if (tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType().equals(
                org.wso2.carbon.identity.oauth.common.GrantType.SAML20_BEARER.toString())) {
            scopeValidationCallback.setCarbonGrantType(org.wso2.carbon.identity.oauth.common.GrantType.valueOf(
                    OAuthConstants.OAUTH_SAML2_BEARER_GRANT_ENUM.toString()));
        } else if (tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType().equals(
                org.wso2.carbon.identity.oauth.common.GrantType.IWA_NTLM.toString())) {
            scopeValidationCallback.setCarbonGrantType(org.wso2.carbon.identity.oauth.common.GrantType.valueOf(
                    OAuthConstants.OAUTH_IWA_NTLM_GRANT_ENUM.toString()));
        } else {
            scopeValidationCallback.setGrantType(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType());
        }

        callbackManager.handleCallback(scopeValidationCallback);
        tokReqMsgCtx.setValidityPeriod(scopeValidationCallback.getValidityPeriod());
        tokReqMsgCtx.setScope(scopeValidationCallback.getApprovedScope());

        Set<OAuth2ScopeHandler> scopeHandlers = OAuthServerConfiguration.getInstance().getOAuth2ScopeHandlers();
        boolean isValid = true;

        for (OAuth2ScopeHandler scopeHandler : scopeHandlers) {
            if (scopeHandler != null && scopeHandler.canHandle(tokReqMsgCtx)) {
                isValid = scopeHandler.validateScope(tokReqMsgCtx);
                if (log.isDebugEnabled()) {
                    log.debug(String.format("ScopeHandler: %s validated to: %s", scopeHandler.getClass()
                            .getCanonicalName(), isValid));
                }
                if (!isValid) {
                    if (LoggerUtils.isDiagnosticLogsEnabled()) {
                        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                                DiagnosticLog.DiagnosticLogBuilder(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                                OAuthConstants.LogConstants.ActionIDs.SCOPE_VALIDATION);
                        diagnosticLogBuilder.configParam("scope validator", scopeHandler.getClass().getCanonicalName())
                                .inputParam(LogConstants.InputKeys.CLIENT_ID,
                                        tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId())
                                .resultMessage("Scope validation failed against the configured scope validator.")
                                .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                                .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                        if (ArrayUtils.isNotEmpty(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope())) {
                            List<String> scopes = Arrays.asList(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope());
                            diagnosticLogBuilder.inputParam("scopes", scopes);
                        }
                        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                    }
                    break;
                }
            }
        }
        // Deriving the list of global level scope validation implementations.
        // These are global/server level scope validators which are engaged after the app level scope validation.
        List<ScopeValidator> globalScopeValidators = OAuthComponentServiceHolder.getInstance().getScopeValidators();
        for (ScopeValidator validator : globalScopeValidators) {
            if (log.isDebugEnabled()) {
                log.debug("Engaging global scope validator in token issuer flow : " + validator.getName());
            }
            boolean isGlobalValidScope = validator.validateScope(tokReqMsgCtx);
            if (log.isDebugEnabled()) {
                log.debug("Scope Validation was" + isGlobalValidScope + "at the global level by : "
                        + validator.getName());
            }
        }

        return isValid && scopeValidationCallback.isValidScope();
    }

    @Override
    public boolean authorizeAccessDelegation(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        OAuthCallback authzCallback = new OAuthCallback(tokReqMsgCtx.getAuthorizedUser(),
                tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId(),
                OAuthCallback.OAuthCallbackType.ACCESS_DELEGATION_TOKEN);
        authzCallback.setRequestedScope(tokReqMsgCtx.getScope());
        if (tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType().equals(
                org.wso2.carbon.identity.oauth.common.GrantType.SAML20_BEARER.toString())) {
            authzCallback.setCarbonGrantType(org.wso2.carbon.identity.oauth.common.GrantType.valueOf(
                    OAuthConstants.OAUTH_SAML2_BEARER_GRANT_ENUM));
        } else if (tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType().equals(
                org.wso2.carbon.identity.oauth.common.GrantType.IWA_NTLM.toString())) {
            authzCallback.setCarbonGrantType(org.wso2.carbon.identity.oauth.common.GrantType.valueOf(
                    OAuthConstants.OAUTH_IWA_NTLM_GRANT_ENUM));
        } else {
            authzCallback.setGrantType(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType());
        }
        callbackManager.handleCallback(authzCallback);
        tokReqMsgCtx.setValidityPeriod(authzCallback.getValidityPeriod());
        return authzCallback.isAuthorized();
    }

    protected String getTokenType() throws IdentityOAuth2Exception {
        return isOfTypeApplicationUser() ?
                OAuthConstants.UserType.APPLICATION_USER : OAuthConstants.UserType.APPLICATION;
    }

    protected String getTokenType(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        return isOfTypeApplicationUser(tokReqMsgCtx) ?
                OAuthConstants.UserType.APPLICATION_USER : OAuthConstants.UserType.APPLICATION;
    }

    protected void storeAccessToken(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO, String userStoreDomain,
                                    AccessTokenDO newTokenBean, String newAccessToken, AccessTokenDO
                                            existingTokenBean) throws IdentityOAuth2Exception {
        try {
            OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                    .insertAccessToken(newAccessToken, oAuth2AccessTokenReqDTO.getClientId(),
                            newTokenBean, existingTokenBean, userStoreDomain);
        } catch (IdentityException e) {
            String maskedToken = LoggerUtils.isLogMaskingEnable ? LoggerUtils.getMaskedContent(newAccessToken) :
                    newAccessToken;
            throw new IdentityOAuth2Exception(
                    "Error occurred while storing new access token : " + maskedToken, e);
        }
    }

    protected String getUserStoreDomain(AuthenticatedUser authenticatedUser) throws IdentityOAuth2Exception {
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

    private OAuth2AccessTokenRespDTO renewAccessToken(OAuthTokenReqMessageContext tokReqMsgCtx, String scope,
                                                      String consumerKey, AccessTokenDO existingTokenBean,
                                                      OauthTokenIssuer oauthTokenIssuer)
            throws IdentityOAuth2Exception {

        // Revoke the existing token and generate new access and refresh tokens.
        OAuthUtil.invokePreRevocationBySystemListeners(existingTokenBean, Collections.emptyMap());
        OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                .updateAccessTokenState(existingTokenBean.getTokenId(), OAuthConstants.TokenStates
                        .TOKEN_STATE_REVOKED, existingTokenBean.getGrantType());
        clearExistingTokenFromCache(tokReqMsgCtx, existingTokenBean);
        OAuthUtil.invokePostRevocationBySystemListeners(existingTokenBean, Collections.emptyMap());

        return generateNewAccessToken(tokReqMsgCtx, scope, consumerKey, existingTokenBean, false,
                oauthTokenIssuer);
    }

    private OAuth2AccessTokenRespDTO issueExistingAccessToken(OAuthTokenReqMessageContext tokReqMsgCtx, String scope,
                                                              long expireTime, AccessTokenDO existingTokenBean)
            throws IdentityOAuth2Exception {

        tokReqMsgCtx.addProperty(EXISTING_TOKEN_ISSUED, true);
        String requestGrantType = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType();
        /* When issuing the existing access token, that access token may be originated from a different grant
        type. The origin grant type can be a consent required one. If the existing token is issued previously
        for a consent not required grant and the current grant requires consent, we update the existing token as
        a consented token. */
        boolean isConsentRequiredGrant = OIDCClaimUtil.
                isConsentBasedClaimFilteringApplicable(requestGrantType);
        if (isConsentRequiredGrant && !existingTokenBean.isConsentedToken()) {
            existingTokenBean.setIsConsentedToken(true);
            OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO().updateTokenIsConsented(
                    existingTokenBean.getTokenId(), true);
        }

        if (AuthorizationDetailsUtils.isRichAuthorizationRequest(tokReqMsgCtx.getAuthorizationDetails())) {
            this.authorizationDetailsService.replaceAccessTokenAuthorizationDetails(existingTokenBean.getTokenId(),
                    existingTokenBean, tokReqMsgCtx);
        }

        setDetailsToMessageContext(tokReqMsgCtx, existingTokenBean);
        return createResponseWithTokenBean(existingTokenBean, expireTime, scope);
    }

    private OAuth2AccessTokenRespDTO generateNewAccessToken(OAuthTokenReqMessageContext tokReqMsgCtx, String scope,
                                                            String consumerKey, AccessTokenDO existingTokenBean,
                                                            boolean expireExistingToken,
                                                            OauthTokenIssuer oauthTokenIssuer)
            throws IdentityOAuth2Exception {

        Timestamp timestamp = new Timestamp(new Date().getTime());
        updateMessageContextToCreateNewToken(tokReqMsgCtx, consumerKey, existingTokenBean, timestamp);
        ActionExecutionStatus<?> executionStatus = executePreIssueAccessTokenActions(tokReqMsgCtx);
        if (executionStatus != null && (executionStatus.getStatus() == ActionExecutionStatus.Status.FAILED ||
                executionStatus.getStatus() == ActionExecutionStatus.Status.ERROR)) {
            return getFailureOrErrorResponseDTO(executionStatus);
        }
        AccessTokenDO newTokenBean = createNewTokenBean(tokReqMsgCtx, existingTokenBean, oauthTokenIssuer);

        /* Check whether the existing token needs to be expired and send the corresponding parameters to the
        persistAccessTokenInDB method. */
        if (expireExistingToken) {
            // Persist the access token in database and mark the existing token as expired.
            persistAccessTokenInDB(tokReqMsgCtx, existingTokenBean, newTokenBean, timestamp,
                    newTokenBean.getAccessToken());
        } else {
            // Persist the access token in database without updating the existing token.
            // The existing token should already be updated by this point.
            persistAccessTokenInDB(tokReqMsgCtx, null, newTokenBean, timestamp,
                    newTokenBean.getAccessToken());
        }

        // Update cache with newly added token.
        updateCacheIfEnabled(newTokenBean, OAuth2Util.buildScopeString(tokReqMsgCtx.getScope()), oauthTokenIssuer);
        return createResponseWithTokenBean(newTokenBean, newTokenBean.getValidityPeriodInMillis(), scope);
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

    private ActionExecutionStatus<?> executePreIssueAccessTokenActions(
            OAuthTokenReqMessageContext tokenReqMessageContext) throws IdentityOAuth2Exception {

        ActionExecutionStatus<?> executionStatus = null;
        if (checkExecutePreIssueAccessTokensActions(tokenReqMessageContext)) {

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

    private boolean checkExecutePreIssueAccessTokensActions(OAuthTokenReqMessageContext tokenReqMessageContext)
            throws IdentityOAuth2Exception {

        OAuthAppDO oAuthAppBean = getoAuthApp(tokenReqMessageContext.getOauth2AccessTokenReqDTO().getClientId());
        String grantType = tokenReqMessageContext.getOauth2AccessTokenReqDTO().getGrantType();

        // Allow for following grant types and for JWT access tokens if,
        // pre issue access token action invocation is enabled at server level.
        return OAuthComponentServiceHolder.getInstance().getActionExecutorService()
                .isExecutionEnabled(ActionType.PRE_ISSUE_ACCESS_TOKEN) &&
                (OAuthConstants.GrantTypes.AUTHORIZATION_CODE.equals(grantType) ||
                        OAuthConstants.GrantTypes.CLIENT_CREDENTIALS.equals(grantType) ||
                        OAuthConstants.GrantTypes.PASSWORD.equals(grantType) ||
                        OAuthConstants.GrantTypes.REFRESH_TOKEN.equals(grantType)) &&
                JWT_TOKEN_TYPE.equals(oAuthAppBean.getTokenType());
    }

    private boolean isExistingTokenValid(AccessTokenDO existingTokenBean, long expireTime) {

        if (TOKEN_STATE_ACTIVE.equals(existingTokenBean.getTokenState()) && expireTime != 0) {
            return true;
        } else {
            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug("Access token(hashed) " + DigestUtils.sha256Hex(existingTokenBean
                            .getAccessToken()) + " is not valid anymore");
                } else {
                    log.debug("Latest access token in the database for client: " +
                            existingTokenBean.getConsumerKey() + " is not valid anymore");
                }
            }
        }
        return false;
    }

    private AccessTokenDO createNewTokenBean(OAuthTokenReqMessageContext tokReqMsgCtx, AccessTokenDO existingTokenBean,
                                             OauthTokenIssuer oauthTokenIssuer) throws IdentityOAuth2Exception {

        String tenantDomain = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();

        OAuth2AccessTokenReqDTO tokenReq = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        validateGrantTypeParam(tokenReq);

        AccessTokenDO newTokenBean = new AccessTokenDO();
        newTokenBean.setTokenState(TOKEN_STATE_ACTIVE);
        newTokenBean.setConsumerKey(tokenReq.getClientId());
        newTokenBean.setAuthzUser(tokReqMsgCtx.getAuthorizedUser());
        newTokenBean.setScope(tokReqMsgCtx.getScope());
        newTokenBean.setTenantID(OAuth2Util.getTenantId(tenantDomain));
        newTokenBean.setTokenId(UUID.randomUUID().toString());
        newTokenBean.setGrantType(tokenReq.getGrantType());
        newTokenBean.setAppResidentTenantId(IdentityTenantUtil.getLoginTenantId());
        newTokenBean.setIsConsentedToken(tokReqMsgCtx.isConsentedToken());
        newTokenBean.setTokenType(getTokenType(tokReqMsgCtx));
        newTokenBean.setIssuedTime(new Timestamp(tokReqMsgCtx.getAccessTokenIssuedTime()));
        newTokenBean.setAccessToken(getNewAccessToken(tokReqMsgCtx, oauthTokenIssuer));
        newTokenBean.setValidityPeriodInMillis(tokReqMsgCtx.getValidityPeriod());
        newTokenBean.setValidityPeriod(tokReqMsgCtx.getValidityPeriod() / SECONDS_TO_MILISECONDS_FACTOR);
        newTokenBean.setTokenBinding(tokReqMsgCtx.getTokenBinding());
        newTokenBean.setAccessTokenExtendedAttributes(
                getAccessTokenExtendedAttributes(tokenReq.getAccessTokenExtendedAttributes(), tokReqMsgCtx));
        newTokenBean.setAcr(tokReqMsgCtx.getSelectedAcr());
        newTokenBean.setAuthTime(tokReqMsgCtx.getAuthTime());
        setRefreshTokenDetails(tokReqMsgCtx, existingTokenBean, newTokenBean, oauthTokenIssuer);

        return newTokenBean;
    }

    private AccessTokenExtendedAttributes getAccessTokenExtendedAttributes(
            AccessTokenExtendedAttributes accessTokenExtendedAttributes,
            OAuthTokenReqMessageContext tokReqMsgCtx) {

        if (tokReqMsgCtx.isImpersonationRequest()) {
            accessTokenExtendedAttributes =
                    addExtendedAttribute(IMPERSONATING_ACTOR, tokReqMsgCtx.getProperty(IMPERSONATING_ACTOR).toString(),
                            accessTokenExtendedAttributes);
        }
        // Add any new extended attributes here using @addExtendedAttribute.
        return accessTokenExtendedAttributes;
    }

    private AccessTokenExtendedAttributes addExtendedAttribute(String key, String value, AccessTokenExtendedAttributes
            accessTokenExtendedAttributes) {

        if (accessTokenExtendedAttributes == null) {
            accessTokenExtendedAttributes = new AccessTokenExtendedAttributes(new HashMap<>());
        }
        if (key != null && value != null) {
            accessTokenExtendedAttributes.getParameters().put(key, value);
        }
        return accessTokenExtendedAttributes;
    }

    private void updateMessageContextToCreateNewToken(OAuthTokenReqMessageContext tokReqMsgCtx, String consumerKey,
                                                      AccessTokenDO existingTokenBean, Timestamp timestamp)
            throws IdentityOAuth2Exception {

        /* If the existing token is available, the consented token flag will be extracted from that. Otherwise,
        from the current grant. */
        if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
            if (existingTokenBean != null) {
                tokReqMsgCtx.setConsentedToken(existingTokenBean.isConsentedToken());
            } else {
                if (OIDCClaimUtil.isConsentBasedClaimFilteringApplicable(
                        tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType())) {
                    tokReqMsgCtx.setConsentedToken(true);
                }
            }
        }
        OAuthAppDO oAuthAppBean = getoAuthApp(consumerKey);
        long validityPeriodInMillis = getConfiguredExpiryTimeForApplication(tokReqMsgCtx, consumerKey, oAuthAppBean);
        tokReqMsgCtx.setValidityPeriod(validityPeriodInMillis);
        tokReqMsgCtx.setAccessTokenIssuedTime(timestamp.getTime());
        tokReqMsgCtx.setAudiences(OAuth2Util.getOIDCAudience(consumerKey, oAuthAppBean));

        updateRefreshTokenValidityPeriodInMessageContext(oAuthAppBean, existingTokenBean, tokReqMsgCtx);
    }

    private void setRefreshTokenDetails(OAuthTokenReqMessageContext tokReqMsgCtx, AccessTokenDO existingTokenBean,
                                        AccessTokenDO newTokenBean, OauthTokenIssuer oauthTokenIssuer)
            throws IdentityOAuth2Exception {

        OAuth2AccessTokenReqDTO tokenReq = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        boolean isExtendedToken = tokenReq.getAccessTokenExtendedAttributes() != null &&
                tokenReq.getAccessTokenExtendedAttributes().getRefreshTokenValidityPeriod() >
                        EXTENDED_REFRESH_TOKEN_DEFAULT_TIME;
        /* Check whether the token renewal per request configuration is configured and the validation of the refresh
        token. If the token renewal per request configuration is enabled, renew the refresh token as well. */
        if (!isTokenRenewalPerRequestConfigured() &&
                isRefreshTokenValid(existingTokenBean, tokReqMsgCtx.getValidityPeriod(),
                        tokenReq.getClientId()) && !isExtendedToken) {
            setRefreshTokenDetailsFromExistingToken(existingTokenBean, newTokenBean, tokReqMsgCtx);
        } else {
            // no valid refresh token found in existing Token
            newTokenBean.setRefreshTokenIssuedTime(new Timestamp(tokReqMsgCtx.getAccessTokenIssuedTime()));
            // Set refresh token validity period.
            if (tokReqMsgCtx.getRefreshTokenValidityPeriodInMillis() > 0) {
                newTokenBean.setRefreshTokenValidityPeriodInMillis(
                        tokReqMsgCtx.getRefreshTokenValidityPeriodInMillis());
            } else {
                newTokenBean.setRefreshTokenValidityPeriodInMillis(tokReqMsgCtx.getRefreshTokenvalidityPeriod());
            }
            newTokenBean.setRefreshToken(getRefreshToken(tokReqMsgCtx, oauthTokenIssuer));
        }
    }

    private void persistAccessTokenInDB(OAuthTokenReqMessageContext tokReqMsgCtx, AccessTokenDO existingTokenBean,
                                        AccessTokenDO newTokenBean, Timestamp timestamp, String newAccessToken)
            throws IdentityOAuth2Exception {
        OAuth2AccessTokenReqDTO tokenReq = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        if (log.isDebugEnabled()) {
            log.debug("Persisting Access Token for " +
                    "Client ID: " + tokenReq.getClientId() +
                    ", Authorized User: " + tokReqMsgCtx.getAuthorizedUser() +
                    ", Is Federated User: " + isFederatedUser(tokReqMsgCtx) +
                    ", Timestamp: " + timestamp +
                    ", Validity period: " + newTokenBean.getValidityPeriod() + "s" +
                    ", Scope: " + OAuth2Util.buildScopeString(tokReqMsgCtx.getScope()) +
                    ", Token State: " + TOKEN_STATE_ACTIVE +
                    ", accessTokenId for token binding: " + getTokenIdForTokenBinding(tokReqMsgCtx) +
                    ", bindingType: " + getTokenBindingType(tokReqMsgCtx) +
                    " and bindingRef: " + getTokenBindingReference(tokReqMsgCtx) +
                    " and authorized organization: " + getAuthorizedOrganization(tokReqMsgCtx));
        }
        storeAccessToken(tokenReq, getUserStoreDomain(tokReqMsgCtx.getAuthorizedUser()), newTokenBean, newAccessToken,
                existingTokenBean);
        this.authorizationDetailsService
                .storeOrReplaceAccessTokenAuthorizationDetails(newTokenBean, existingTokenBean, tokReqMsgCtx);
    }

    private void updateCacheIfEnabled(AccessTokenDO newTokenBean, String scope, OauthTokenIssuer oauthTokenIssuer)
            throws IdentityOAuth2Exception {

        if (isHashDisabled && cacheEnabled) {
            /*
             * If no token persistence, the token will be not be cached against a cache key with userId, scope, client,
             * idp and binding reference. But, token will be cached and managed as an AccessTokenDO against the
             * token identifier.
             */
            if (OAuth2Util.isTokenPersistenceEnabled()) {
                AccessTokenDO tokenToCache = AccessTokenDO.clone(newTokenBean);
                // If usePersistedAccessTokenAlias is enabled then in the DB the
                // access token alias taken from the OauthTokenIssuer's getAccessTokenHash
                // method is set as the token.
                if (oauthTokenIssuer.usePersistedAccessTokenAlias()) {
                    try {
                        String persistedTokenIdentifier =
                                oauthTokenIssuer.getAccessTokenHash(newTokenBean.getAccessToken());
                        tokenToCache.setAccessToken(persistedTokenIdentifier);
                    } catch (OAuthSystemException e) {
                        if (log.isDebugEnabled()) {
                            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                                log.debug("Token issuer: " + oauthTokenIssuer.getClass() + " was tried and" +
                                        " failed to parse the received token: " + tokenToCache.getAccessToken(), e);
                            } else {
                                log.debug("Token issuer: " + oauthTokenIssuer.getClass() + " was tried and" +
                                        " failed to parse the received token.", e);
                            }
                        }
                    }
                }

                String userId;
                String authorizedOrganization;
                try {
                    userId = tokenToCache.getAuthzUser().getUserId();
                    authorizedOrganization = tokenToCache.getAuthzUser().getAccessingOrganization();
                    if (StringUtils.isBlank(authorizedOrganization)) {
                        authorizedOrganization = OAuthConstants.AuthorizedOrganization.NONE;
                    }
                } catch (UserIdNotFoundException e) {
                    throw new IdentityOAuth2Exception(
                            "User id is not available for user: " +
                                    tokenToCache.getAuthzUser().getLoggableMaskedUserId(), e);
                }

                String authenticatedIDP = OAuth2Util.getAuthenticatedIDP(tokenToCache.getAuthzUser());
                OAuthCacheKey cacheKey = getOAuthCacheKey(scope, tokenToCache.getConsumerKey(), userId,
                        authenticatedIDP, getTokenBindingReference(tokenToCache), authorizedOrganization);
                oauthCache.addToCache(cacheKey, tokenToCache);
                if (log.isDebugEnabled()) {
                    log.debug("Access token was added to OAuthCache with cache key : " + cacheKey.getCacheKeyString());
                }
            }
            // Adding AccessTokenDO to improve validation performance
            OAuth2Util.addTokenDOtoCache(newTokenBean);
        }
    }

    private boolean getRenewWithoutRevokingExistingStatus() {

        return Boolean.parseBoolean(IdentityUtil.
                getProperty(RENEW_TOKEN_WITHOUT_REVOKING_EXISTING_ENABLE_CONFIG));
    }

    private String getNewAccessToken(OAuthTokenReqMessageContext tokReqMsgCtx, OauthTokenIssuer oauthTokenIssuer)
            throws IdentityOAuth2Exception {
        try {
            String newAccessToken = oauthTokenIssuer.accessToken(tokReqMsgCtx);
            if (OAuth2Util.checkUserNameAssertionEnabled()) {
                newAccessToken = OAuth2Util.addUsernameToToken(tokReqMsgCtx.getAuthorizedUser(), newAccessToken);
            }
            return newAccessToken;
        } catch (OAuthSystemException e) {
            /* Below condition check is added in order to send a client error when the root cause of the exception is
               actually a client error and not an internal server error. */
            if (e.getCause() instanceof IdentityOAuth2ClientException) {
                throw (IdentityOAuth2ClientException) e.getCause();
            }
            throw new IdentityOAuth2Exception("Error while generating access token", e);
        }
    }

    private String getRefreshToken(OAuthTokenReqMessageContext tokReqMsgCtx, OauthTokenIssuer oauthTokenIssuer)
            throws IdentityOAuth2Exception {
        try {
            String refreshToken = oauthTokenIssuer.refreshToken(tokReqMsgCtx);
            if (OAuth2Util.checkUserNameAssertionEnabled()) {
                refreshToken = OAuth2Util.addUsernameToToken(tokReqMsgCtx.getAuthorizedUser(), refreshToken);
            }
            return refreshToken;
        } catch (OAuthSystemException e) {
            throw new IdentityOAuth2Exception("Error while issueing refresh token", e);
        }
    }

    private void setRefreshTokenDetailsFromExistingToken(AccessTokenDO existingAccessTokenDO,
                                                         AccessTokenDO newTokenBean,
                                                         OAuthTokenReqMessageContext tokReqMsgCtx) {

        newTokenBean.setRefreshToken(existingAccessTokenDO.getRefreshToken());
        newTokenBean.setRefreshTokenIssuedTime(existingAccessTokenDO.getRefreshTokenIssuedTime());

        /*
        Giving precedence to OAuthTokenReqMessageContext which is updated during
        pre-issue access token action execution.
         */
        if (tokReqMsgCtx.getRefreshTokenValidityPeriodInMillis() > 0) {
            newTokenBean.setRefreshTokenValidityPeriodInMillis(tokReqMsgCtx.getRefreshTokenValidityPeriodInMillis());
        } else {
            newTokenBean.setRefreshTokenValidityPeriodInMillis(existingAccessTokenDO
                    .getRefreshTokenValidityPeriodInMillis());
        }
    }

    private void validateGrantTypeParam(OAuth2AccessTokenReqDTO tokenReq) throws IdentityOAuth2Exception {
        if (tokenReq.getGrantType() == null) {
            throw new IdentityOAuth2Exception("Grant type not found in the token request");
        }
    }

    private void updateRefreshTokenValidityPeriodInMessageContext(OAuthAppDO oAuthAppBean,
                                                                  AccessTokenDO existingTokenBean,
                                                                  OAuthTokenReqMessageContext tokReqMsgCtx) {

        OAuth2AccessTokenReqDTO tokenReq = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        boolean isExtendedToken = tokenReq.getAccessTokenExtendedAttributes() != null &&
                tokenReq.getAccessTokenExtendedAttributes().getRefreshTokenValidityPeriod() >
                        EXTENDED_REFRESH_TOKEN_DEFAULT_TIME;

        long refreshTokenValidityPeriodInMillis;
        long validityPeriodFromMsgContext = tokReqMsgCtx.getRefreshTokenvalidityPeriod();

        if (validityPeriodFromMsgContext > 0) {
            refreshTokenValidityPeriodInMillis = validityPeriodFromMsgContext * SECONDS_TO_MILISECONDS_FACTOR;
            if (log.isDebugEnabled()) {
                log.debug("OAuth application id : " + oAuthAppBean.getOauthConsumerKey() + ", using refresh token " +
                        "validity period configured from OAuthTokenReqMessageContext: " +
                        refreshTokenValidityPeriodInMillis + " ms");
            }
        } else if (existingTokenBean != null && !isTokenRenewalPerRequestConfigured() &&
                isRefreshTokenValid(existingTokenBean, tokReqMsgCtx.getValidityPeriod(), tokenReq.getClientId()) &&
                !isExtendedToken) {
            /*
            Checks if the existing refresh token will be reused. If so, its original expiry time should be
            retained instead of recalculating it from the application-level configuration.
             */
            refreshTokenValidityPeriodInMillis = existingTokenBean.getRefreshTokenValidityPeriodInMillis();
        } else if (oAuthAppBean.getRefreshTokenExpiryTime() != 0) {
            refreshTokenValidityPeriodInMillis =
                    oAuthAppBean.getRefreshTokenExpiryTime() * SECONDS_TO_MILISECONDS_FACTOR;
            if (log.isDebugEnabled()) {
                log.debug("OAuth application id : " + oAuthAppBean.getOauthConsumerKey() +
                        ", refresh token validity time " + refreshTokenValidityPeriodInMillis + "ms");
            }
        } else {
            refreshTokenValidityPeriodInMillis = OAuthServerConfiguration.getInstance()
                    .getRefreshTokenValidityPeriodInSeconds() * SECONDS_TO_MILISECONDS_FACTOR;
        }

        tokReqMsgCtx.setRefreshTokenvalidityPeriod(refreshTokenValidityPeriodInMillis);
        tokReqMsgCtx.setRefreshTokenValidityPeriodInMillis(refreshTokenValidityPeriodInMillis);
    }

    private void addTokenToCache(OAuthCacheKey cacheKey, AccessTokenDO existingAccessTokenDO) {
        if (isHashDisabled && cacheEnabled) {
            oauthCache.addToCache(cacheKey, existingAccessTokenDO);
            // Adding AccessTokenDO to improve validation performance
            OAuthCacheKey accessTokenCacheKey = new OAuthCacheKey(existingAccessTokenDO.getAccessToken());
            oauthCache.addToCache(accessTokenCacheKey, existingAccessTokenDO);
            if (log.isDebugEnabled()) {
                log.debug("Access Token info was added to the cache for the cache key : " +
                        cacheKey.getCacheKeyString());
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug("Access token was added to OAuthCache for cache key : " + accessTokenCacheKey
                            .getCacheKeyString());
                }
            }
        }
    }

    private OAuth2AccessTokenRespDTO createResponseWithTokenBean(AccessTokenDO existingAccessTokenDO,
                                                                 long expireTimeMillis, String scope)
            throws IdentityOAuth2Exception {
        OAuth2AccessTokenRespDTO tokenRespDTO = new OAuth2AccessTokenRespDTO();
        tokenRespDTO.setAccessToken(existingAccessTokenDO.getAccessToken());
        tokenRespDTO.setTokenId(existingAccessTokenDO.getTokenId());
        OAuthAppDO oAuthAppDO;
        String consumerKey = existingAccessTokenDO.getConsumerKey();
        try {
            String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            String applicationResidentOrgId = PrivilegedCarbonContext.getThreadLocalCarbonContext()
                    .getApplicationResidentOrganizationId();
            /*
             If applicationResidentOrgId is not empty, then the request comes for an application which is registered
             directly in the organization of the applicationResidentOrgId. Therefore, the tenant domain should be
             extracted from the organization id to get the information of the application.
            */
            if (StringUtils.isNotEmpty(applicationResidentOrgId)) {
                tenantDomain = OAuth2ServiceComponentHolder.getInstance().getOrganizationManager()
                        .resolveTenantDomain(applicationResidentOrgId);
            }
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(consumerKey, tenantDomain);
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Error while retrieving app information for client_id : " + consumerKey,
                    e);
        } catch (OrganizationManagementException e) {
            throw new IdentityOAuth2Exception("Error while resolving tenant domain from the organization id: ", e);
        }

        if (issueRefreshToken(existingAccessTokenDO.getTokenType()) &&
                OAuthServerConfiguration.getInstance().getSupportedGrantTypes().containsKey(
                        GrantType.REFRESH_TOKEN.toString())) {
            String grantTypes = oAuthAppDO.getGrantTypes();
            List<String> supportedGrantTypes = new ArrayList<>();
            if (StringUtils.isNotEmpty(grantTypes)) {
                supportedGrantTypes = Arrays.asList(grantTypes.split(" "));
            }
            if (supportedGrantTypes.contains(OAuthConstants.GrantTypes.REFRESH_TOKEN)) {
                tokenRespDTO.setRefreshToken(existingAccessTokenDO.getRefreshToken());
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Refresh grant is not allowed for client_id : " + consumerKey + ", therefore not " +
                            "issuing a refresh token.");
                }
            }
        }
        if (expireTimeMillis > 0) {
            tokenRespDTO.setExpiresIn(expireTimeMillis / SECONDS_TO_MILISECONDS_FACTOR);
            tokenRespDTO.setExpiresInMillis(expireTimeMillis);
        } else {
            tokenRespDTO.setExpiresIn(Long.MAX_VALUE / SECONDS_TO_MILISECONDS_FACTOR);
            tokenRespDTO.setExpiresInMillis(Long.MAX_VALUE);
        }
        tokenRespDTO.setAuthorizedScopes(scope);
        tokenRespDTO.setIsConsentedToken(existingAccessTokenDO.isConsentedToken());
        return tokenRespDTO;
    }

    private OAuthCacheKey getOAuthCacheKey(String scope, String consumerKey, String authorizedUserId,
                                           String authenticatedIDP, String tokenBindingType,
                                           String authorizedOrganization) {

        String cacheKeyString = OAuth2Util.buildCacheKeyStringForTokenWithUserIdOrgId(consumerKey, scope,
                authorizedUserId, authenticatedIDP, tokenBindingType, authorizedOrganization);
        return new OAuthCacheKey(cacheKeyString);
    }

    private OAuthAppDO getoAuthApp(String consumerKey) throws IdentityOAuth2Exception {
        OAuthAppDO oAuthAppBean;
        try {
            String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            String applicationResidentOrgId = PrivilegedCarbonContext.getThreadLocalCarbonContext()
                    .getApplicationResidentOrganizationId();
            /*
             If applicationResidentOrgId is not empty, then the request comes for an application which is registered
             directly in the organization of the applicationResidentOrgId. Therefore, the tenant domain should be
             extracted from the organization id to get the information of the application.
            */
            if (StringUtils.isNotEmpty(applicationResidentOrgId)) {
                tenantDomain = OAuth2ServiceComponentHolder.getInstance().getOrganizationManager()
                        .resolveTenantDomain(applicationResidentOrgId);
            }
            oAuthAppBean = OAuth2Util.getAppInformationByClientId(consumerKey, tenantDomain);
            if (log.isDebugEnabled()) {
                log.debug("Service Provider specific expiry time enabled for application : " + consumerKey +
                        ". Application access token expiry time : " + oAuthAppBean.getApplicationAccessTokenExpiryTime()
                        + ", User access token expiry time : " + oAuthAppBean.getUserAccessTokenExpiryTime() +
                        ", Refresh token expiry time : " + oAuthAppBean.getRefreshTokenExpiryTime());
            }
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Error while retrieving app information for clientId: " + consumerKey, e);
        } catch (OrganizationManagementException e) {
            throw new IdentityOAuth2Exception("Error while resolving tenant domain from the organization id: ", e);
        }
        return oAuthAppBean;
    }

    /**
     * Returns access token expiry time in milliseconds for given access token.
     *
     * @param existingAccessTokenDO
     * @return
     * @throws IdentityOAuth2Exception
     */
    private long getAccessTokenExpiryTimeMillis(AccessTokenDO existingAccessTokenDO) throws IdentityOAuth2Exception {
        long expireTimeMillis;
        if (issueRefreshToken(existingAccessTokenDO.getTokenType())) {
            // Consider both access and refresh expiry time
            expireTimeMillis = OAuth2Util.getTokenExpireTimeMillis(existingAccessTokenDO, false);
        } else {
            // Consider only access token expiry time
            expireTimeMillis = OAuth2Util.getAccessTokenExpireMillis(existingAccessTokenDO, false);
        }
        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                if (expireTimeMillis > 0) {
                    log.debug("Access Token(hashed): " + DigestUtils.sha256Hex(existingAccessTokenDO
                            .getAccessToken()) + " is still valid. Remaining time: " +
                            expireTimeMillis + "ms");
                } else {
                    log.debug("Infinite lifetime Access Token(hashed) "
                            + DigestUtils.sha256Hex(existingAccessTokenDO
                            .getAccessToken()) + " found");
                }
            } else {
                if (expireTimeMillis > 0) {
                    log.debug("Valid access token is found in cache for client: " +
                            existingAccessTokenDO.getConsumerKey() + ". Remaining time: " + expireTimeMillis + "ms");
                } else {
                    log.debug("Infinite lifetime Access Token found in cache for client: " +
                            existingAccessTokenDO.getConsumerKey());
                }
            }
        }
        return expireTimeMillis;
    }

    /**
     * Returns configured expiry time (in milliseconds) for the app indicated by consumer key.
     *
     * @param tokReqMsgCtx
     * @param consumerKey
     * @param oAuthAppBean
     * @return
     * @throws IdentityOAuth2Exception
     */
    private long getConfiguredExpiryTimeForApplication(OAuthTokenReqMessageContext tokReqMsgCtx, String consumerKey,
                                                       OAuthAppDO oAuthAppBean) throws IdentityOAuth2Exception {
        long validityPeriodInMillis;

        if (isOfTypeApplicationUser(tokReqMsgCtx)) {
            validityPeriodInMillis = getValidityPeriodForApplicationUser(consumerKey, oAuthAppBean);
        } else {
            validityPeriodInMillis = getValidityPeriodForApplication(consumerKey, oAuthAppBean);

        }
        // if a VALID validity period is set through the callback, then use it
        validityPeriodInMillis = getValidityPeriodFromCallback(tokReqMsgCtx, consumerKey, validityPeriodInMillis);
        if (log.isDebugEnabled()) {
            log.debug("OAuth application id : " + consumerKey + ", access token validity time in milliseconds : " +
                    validityPeriodInMillis);
        }
        return validityPeriodInMillis;
    }

    private long getValidityPeriodFromCallback(OAuthTokenReqMessageContext tokReqMsgCtx, String consumerKey,
                                               long validityPeriodInMillis) {
        long callbackValidityPeriod = tokReqMsgCtx.getValidityPeriod();
        if (callbackValidityPeriod != OAuthConstants.UNASSIGNED_VALIDITY_PERIOD) {
            validityPeriodInMillis = callbackValidityPeriod * SECONDS_TO_MILISECONDS_FACTOR;
            if (log.isDebugEnabled()) {
                log.debug("OAuth application id : " + consumerKey +
                        ", callback access token validity time in milliseconds : " + validityPeriodInMillis);
            }
        }
        return validityPeriodInMillis;
    }

    private long getValidityPeriodForApplication(String consumerKey, OAuthAppDO oAuthAppBean) {

        long validityPeriodInMillis; // If the user is an application
        // Default Validity Period (in seconds)
        if (oAuthAppBean.getApplicationAccessTokenExpiryTime() != 0) {
            validityPeriodInMillis = oAuthAppBean.getApplicationAccessTokenExpiryTime() * SECONDS_TO_MILISECONDS_FACTOR;
            if (log.isDebugEnabled()) {
                log.debug("OAuth application id : " + consumerKey + ", application access token validity time in " +
                        "milliseconds : " + validityPeriodInMillis);
            }
        } else {
            validityPeriodInMillis = OAuthServerConfiguration.getInstance()
                    .getApplicationAccessTokenValidityPeriodInSeconds() * SECONDS_TO_MILISECONDS_FACTOR;
        }
        return validityPeriodInMillis;
    }

    private long getValidityPeriodForApplicationUser(String consumerKey, OAuthAppDO oAuthAppBean) {

        long validityPeriodInMillis; // If the user is an application user
        if (oAuthAppBean.getUserAccessTokenExpiryTime() != 0) {
            validityPeriodInMillis = oAuthAppBean.getUserAccessTokenExpiryTime() * SECONDS_TO_MILISECONDS_FACTOR;
            if (log.isDebugEnabled()) {
                log.debug("OAuth application id: " + consumerKey + ", user access token validity time " +
                        validityPeriodInMillis + "ms");
            }
        } else {
            validityPeriodInMillis = OAuthServerConfiguration.getInstance().
                    getUserAccessTokenValidityPeriodInSeconds() * SECONDS_TO_MILISECONDS_FACTOR;
        }
        return validityPeriodInMillis;
    }

    private AccessTokenDO getExistingToken(OAuthTokenReqMessageContext tokenMsgCtx, OAuthCacheKey cacheKey)
            throws IdentityOAuth2Exception {
        AccessTokenDO existingToken = null;
        OAuth2AccessTokenReqDTO tokenReq = tokenMsgCtx.getOauth2AccessTokenReqDTO();
        String scope = OAuth2Util.buildScopeString(tokenMsgCtx.getScope());
        String tokenBindingReference = getTokenBindingReference(tokenMsgCtx);
        String authorizedOrganization = getAuthorizedOrganization(tokenMsgCtx);

        if (cacheEnabled && OAuth2Util.isTokenPersistenceEnabled()) {
            /*
             * If no token persistence, the token is not cached against a cache key with userId, scope, client,
             * idp and binding reference as, multiple active tokens can exist for the same key.
             */
            existingToken = getExistingTokenFromCache(cacheKey, tokenReq.getClientId(),
                    tokenMsgCtx.getAuthorizedUser().getLoggableUserId(), scope, tokenBindingReference,
                    authorizedOrganization, tokenMsgCtx.getAuthorizedUser().getTenantDomain());
        }

        if (existingToken == null) {
            existingToken = getExistingTokenFromDB(tokenMsgCtx, tokenReq, scope, cacheKey);
        }
        return existingToken;
    }

    private AccessTokenDO getExistingTokenFromDB(OAuthTokenReqMessageContext tokenMsgCtx,
                                                 OAuth2AccessTokenReqDTO tokenReq, String scope, OAuthCacheKey cacheKey)
            throws IdentityOAuth2Exception {

        AccessTokenDO existingToken = OAuthTokenPersistenceFactory.getInstance().getAccessTokenDAO()
                .getLatestAccessToken(tokenReq.getClientId(), tokenMsgCtx.getAuthorizedUser(),
                        getUserStoreDomain(tokenMsgCtx.getAuthorizedUser()), scope,
                        getTokenBindingReference(tokenMsgCtx), false);
        if (existingToken != null) {
            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug("Retrieved latest access token(hashed): " + DigestUtils.sha256Hex
                            (existingToken.getAccessToken()) + " in the state: " + existingToken.getTokenState() +
                            " for client Id: " + tokenReq.getClientId() + " user: " + tokenMsgCtx.getAuthorizedUser() +
                            " and scope: " + scope + " from db");
                } else {
                    log.debug("Retrieved latest access token for client Id: " + tokenReq.getClientId() + " user: " +
                            tokenMsgCtx.getAuthorizedUser() + " and scope: " + scope + " from db");
                }
            }
            if (tokenMsgCtx.getSelectedAcr() != null) {
                existingToken.setAcr(tokenMsgCtx.getSelectedAcr());
            }
            if (tokenMsgCtx.getAuthTime() != 0) {
                existingToken.setAuthTime(tokenMsgCtx.getAuthTime());
            }
            long expireTime = getAccessTokenExpiryTimeMillis(existingToken);
            if (TOKEN_STATE_ACTIVE.equals(existingToken.getTokenState()) &&
                    expireTime != 0) {
                // Active token retrieved from db, adding to cache if cacheEnabled
                addTokenToCache(cacheKey, existingToken);
            }
        }
        return existingToken;
    }

    private AccessTokenDO getExistingTokenFromCache(OAuthCacheKey cacheKey, String consumerKey, String loggableUserId,
                                                    String scope, String tokenBindingReference,
                                                    String authorizedOrganization, String tenantDomain)
            throws IdentityOAuth2Exception {

        AccessTokenDO existingToken = null;
        CacheEntry cacheEntry = oauthCache.getValueFromCache(cacheKey, tenantDomain);
        if (cacheEntry instanceof AccessTokenDO) {
            existingToken = (AccessTokenDO) cacheEntry;
            if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Retrieved active access token(hashed): " + DigestUtils
                        .sha256Hex(existingToken.getAccessToken()) + " in the state: " + existingToken.getTokenState()
                        + " for client Id: " + consumerKey + ", user: " + loggableUserId + " ,scope: " + scope
                        + " and token binding reference: " + tokenBindingReference + " and authorized organization: "
                        + authorizedOrganization + " from cache");
            }
            if (getAccessTokenExpiryTimeMillis(existingToken) == 0) {
                // Token is expired. Clear it from cache.
                removeFromCache(cacheKey, consumerKey, existingToken);
                return null;
            }
            return existingToken;
        }
        if (existingToken != null) {
            if (log.isDebugEnabled()) {
                log.debug("Retrieved active access token from OAuthCache for the cachekey: " + cacheKey);
            }
        }

        return existingToken;
    }

    private void removeFromCache(OAuthCacheKey cacheKey, String consumerKey, AccessTokenDO existingAccessTokenDO) {
        oauthCache.clearCacheEntry(cacheKey , existingAccessTokenDO.getAuthzUser().getTenantDomain());
        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Access token(hashed) " + DigestUtils.sha256Hex(existingAccessTokenDO
                        .getAccessToken()) + " is expired. Therefore cleared it from cache and marked" +
                        " it as expired in database");
            } else {
                log.debug("Existing access token for client: " + consumerKey + " is expired. " +
                        "Therefore cleared it from cache and marked it as expired in database");
            }
        }
    }

    private boolean isRefreshTokenValid(AccessTokenDO existingAccessTokenDO, long validityPeriod, String consumerKey) {
        if (isHashDisabled && existingAccessTokenDO != null) {
            long refreshTokenExpireTime = OAuth2Util.getRefreshTokenExpireTimeMillis(existingAccessTokenDO);
            if (TOKEN_STATE_ACTIVE.equals(existingAccessTokenDO.getTokenState())) {
                if (!isRefreshTokenExpired(validityPeriod, refreshTokenExpireTime)) {
                    if (log.isDebugEnabled()) {
                        if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                            log.debug("Existing access token: " + existingAccessTokenDO.getAccessToken() +
                                    " has expired, but refresh token:" +
                                    existingAccessTokenDO.getRefreshToken() + " is still valid for client: " +
                                    consumerKey + ". Remaining time: " + refreshTokenExpireTime +
                                    "ms. Using existing refresh token.");

                        } else {
                            log.debug("Existing access token has expired, but refresh token is still valid " +
                                    "for client: " + consumerKey + ". Remaining time: " +
                                    refreshTokenExpireTime + "ms. Using existing refresh token.");
                        }
                    }
                    return true;
                }
            }
        }
        return false;
    }

    private boolean isRefreshTokenExpired(long validityPeriod, long refreshTokenExpireTime) {
        if (refreshTokenExpireTime < 0) {
            // refresh token has infinite validity
            return false;
        }
        return !(refreshTokenExpireTime > 0 && refreshTokenExpireTime > validityPeriod);
    }

    private boolean accessTokenRenewedPerRequest(OauthTokenIssuer oauthTokenIssuer,
                                                 OAuthTokenReqMessageContext tokReqMsgCtx) {

        boolean isRenewTokenPerRequestEnabledInIssuer = oauthTokenIssuer.renewAccessTokenPerRequest();
        boolean isRenewTokenPerRequestEnabledInTokReqMsgCtx = oauthIssuerImpl.renewAccessTokenPerRequest(tokReqMsgCtx);
        boolean isRenewTokenPerRequestEnabledInConfig = isTokenRenewalPerRequestConfigured();
        if (log.isDebugEnabled()) {
            log.debug("Access token renew per request: OauthTokenIssuer: " + isRenewTokenPerRequestEnabledInIssuer +
                    ", OAuthTokenReqMessageContext: " + isRenewTokenPerRequestEnabledInTokReqMsgCtx +
                    ", Configuration: " + isRenewTokenPerRequestEnabledInConfig);
        }
        return isRenewTokenPerRequestEnabledInIssuer || isRenewTokenPerRequestEnabledInTokReqMsgCtx ||
                isRenewTokenPerRequestEnabledInConfig;
    }

    /**
     * Checks whether the TokenRenewalPerRequest is enabled in the configuration file.
     *
     * @return The boolean from the configuration.
     */
    private boolean isTokenRenewalPerRequestConfigured() {
        return OAuthServerConfiguration.getInstance().isTokenRenewalPerRequestEnabled();
    }

    private void clearExistingTokenFromCache(OAuthTokenReqMessageContext tokenMsgCtx, AccessTokenDO existingTokenBean)
            throws IdentityOAuth2Exception {

        if (cacheEnabled) {
            String tokenBindingReference = getTokenBindingReference(tokenMsgCtx);
            String authorizedOrganization = getAuthorizedOrganization(tokenMsgCtx);

            OAuthUtil.clearOAuthCache(existingTokenBean.getConsumerKey(), existingTokenBean.getAuthzUser(),
                    OAuth2Util.buildScopeString(existingTokenBean.getScope()), tokenBindingReference,
                    authorizedOrganization);
            OAuthUtil.clearOAuthCache(existingTokenBean.getConsumerKey(), existingTokenBean.getAuthzUser(),
                    OAuth2Util.buildScopeString(existingTokenBean.getScope()));
            OAuthUtil.clearOAuthCache(existingTokenBean.getConsumerKey(), existingTokenBean.getAuthzUser());
            OAuthUtil.clearOAuthCache(existingTokenBean);
        }
    }

    private OAuth2Service getOauth2Service() {

        return (OAuth2Service) PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiService(OAuth2Service.class, null);
    }

    /**
     * Inverting validateByApplicationScopeValidator method for better readability.
     */
    private boolean hasValidationByApplicationScopeValidatorsFailed(OAuthTokenReqMessageContext tokenReqMsgContext)
            throws IdentityOAuth2Exception {

        return !Oauth2ScopeUtils.validateByApplicationScopeValidator(tokenReqMsgContext, null);
    }

    /**
     * Get token binding reference.
     *
     * @param tokReqMsgCtx OAuthTokenReqMessageContext.
     * @return token binding reference.
     */
    protected String getTokenBindingReference(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        /**
         * If OAuth.JWT.RenewTokenWithoutRevokingExisting is enabled from configurations, and current token
         * binding is null,then we will add a new token binding (request binding) to the token binding with
         * a value of a random UUID.
         * The purpose of this new token binding type is to add a random value to the token binding so that
         * "User, Application, Scope, Binding" combination will be unique for each token.
         * Previously, if a token issue request come for the same combination of "User, Application, Scope, Binding",
         * the existing JWT token will be revoked and issue a new token. but with this way, we can issue new tokens
         * without revoking the old ones.
         *
         * Add following configuration to deployment.toml file to enable this feature.
         *     [oauth.jwt.renew_token_without_revoking_existing]
         *     enable = true
         *
         * By default, the allowed grant type for this feature is "client_credentials". If you need to enable for
         * other grant types, add the following configuration to deployment.toml file.
         *     [oauth.jwt.renew_token_without_revoking_existing]
         *     enable = true
         *     allowed_grant_types = ["client_credentials","password", ...]
         */
        String consumerKey = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId();
        OauthTokenIssuer oauthTokenIssuer;

        try {
            oauthTokenIssuer = OAuth2Util.getOAuthTokenIssuerForOAuthApp(consumerKey);
        } catch (InvalidOAuthClientException | IdentityOAuth2Exception e) {
            throw new IdentityOAuth2Exception(
                    "Error while retrieving oauth issuer for the app with clientId: " + consumerKey, e);
        }

        String tokenType = oauthTokenIssuer.getAccessTokenType();

        if (JWT.equalsIgnoreCase(tokenType)) {
            if (getRenewWithoutRevokingExistingStatus()
                    && tokReqMsgCtx != null && (tokReqMsgCtx.getTokenBinding() == null
                    || StringUtils.isBlank(tokReqMsgCtx.getTokenBinding().getBindingReference()))) {
                if (OAuth2ServiceComponentHolder.getJwtRenewWithoutRevokeAllowedGrantTypes()
                        .contains(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getGrantType())) {
                    return UUID.randomUUID().toString();
                }
                return NONE;
            }
        }
        return getExistingTokenBindingReference(tokReqMsgCtx);
    }

    /**
     * Retrieves the existing token binding reference if available, otherwise returns NONE.
     *
     * @param tokReqMsgCtx OAuthTokenReqMessageContext.
     * @return token binding reference.
     */
    private String getExistingTokenBindingReference(OAuthTokenReqMessageContext tokReqMsgCtx) {

        if (tokReqMsgCtx == null || tokReqMsgCtx.getTokenBinding() == null) {
            return NONE;
        }
        String bindingReference = tokReqMsgCtx.getTokenBinding().getBindingReference();
        return StringUtils.isBlank(bindingReference) ? NONE : bindingReference;
    }

    /**
     * Get the user authorized organization to access.
     *
     * @param tokReqMsgCtx OAuthTokenReqMessageContext.
     * @return User authorized organization.
     */
    private String getAuthorizedOrganization(OAuthTokenReqMessageContext tokReqMsgCtx) {

        if (StringUtils.isEmpty(tokReqMsgCtx.getAuthorizedUser().getAccessingOrganization())) {
            return OAuthConstants.AuthorizedOrganization.NONE;
        }
        return tokReqMsgCtx.getAuthorizedUser().getAccessingOrganization();
    }

    /**
     * Get token binding reference.
     *
     * @param accessTokenDO accessTokenDO.
     * @return token binding reference.
     */
    private String getTokenBindingReference(AccessTokenDO accessTokenDO) {

        if (accessTokenDO.getTokenBinding() == null || StringUtils
                .isBlank(accessTokenDO.getTokenBinding().getBindingReference())) {
            return NONE;
        }
        return accessTokenDO.getTokenBinding().getBindingReference();
    }

    private String getTokenBindingType(OAuthTokenReqMessageContext tokReqMsgCtx) {

        if (tokReqMsgCtx.getTokenBinding() == null) {
            if (log.isDebugEnabled()) {
                log.debug("Token binding data is null.");
            }
            return null;
        }
        return tokReqMsgCtx.getTokenBinding().getBindingType();
    }

    private String getTokenIdForTokenBinding(OAuthTokenReqMessageContext tokReqMsgCtx) {

        if (tokReqMsgCtx.getTokenBinding() == null) {
            if (log.isDebugEnabled()) {
                log.debug("Token binding data is null.");
            }
            return null;
        }
        return tokReqMsgCtx.getTokenBinding().getTokenId();
    }

    private boolean isFederatedUser(OAuthTokenReqMessageContext tokReqMsgCtx) {

        if (tokReqMsgCtx.getAuthorizedUser() == null) {
            if (log.isDebugEnabled()) {
                log.debug("Authorized user is null hence returning false.");
            }
            return false;
        }
        return tokReqMsgCtx.getAuthorizedUser().isFederatedUser();
    }
}

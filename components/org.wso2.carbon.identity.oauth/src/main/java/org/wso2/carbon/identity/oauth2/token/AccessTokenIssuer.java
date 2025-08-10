/*
 * Copyright (c) 2017-2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.token;

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.owasp.encoder.Encode;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
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
import org.wso2.carbon.identity.oauth.rar.exception.AuthorizationDetailsProcessingException;
import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth.rar.util.AuthorizationDetailsConstants;
import org.wso2.carbon.identity.oauth2.IDTokenValidationFailureException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.ResponseHeader;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.device.cache.DeviceAuthorizationGrantCache;
import org.wso2.carbon.identity.oauth2.device.cache.DeviceAuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth2.device.cache.DeviceAuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationNotificationRequestDTO;
import org.wso2.carbon.identity.oauth2.impersonation.services.ImpersonationNotificationMgtService;
import org.wso2.carbon.identity.oauth2.impersonation.services.ImpersonationNotificationMgtServiceImpl;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsUtils;
import org.wso2.carbon.identity.oauth2.rar.validator.AuthorizationDetailsValidator;
import org.wso2.carbon.identity.oauth2.rar.validator.DefaultAuthorizationDetailsValidator;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinder;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.token.handlers.response.AccessTokenResponseHandler;
import org.wso2.carbon.identity.oauth2.util.AuthzUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2TokenUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.util.OAuthEventPublishingUtil;
import org.wso2.carbon.identity.oauth2.validators.DefaultOAuth2ScopeValidator;
import org.wso2.carbon.identity.oauth2.validators.JDBCPermissionBasedInternalScopeValidator;
import org.wso2.carbon.identity.oauth2.validators.RoleBasedInternalScopeValidator;
import org.wso2.carbon.identity.openidconnect.IDTokenBuilder;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.apache.commons.lang.StringUtils.isNotBlank;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.ACTOR_TOKEN;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.GrantTypes.REFRESH_TOKEN;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.GrantTypes.TOKEN_EXCHANGE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.IMPERSONATING_ACTOR;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.LogConstants.InputKeys.IMPERSONATOR;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.MAY_ACT;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OauthAppStates.APP_STATE_ACTIVE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.SUBJECT_TOKEN;
import static org.wso2.carbon.identity.oauth2.OAuth2Constants.MAX_ALLOWED_LENGTH;
import static org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants.CONSOLE_SCOPE_PREFIX;
import static org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants.INTERNAL_SCOPE_PREFIX;
import static org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants.SYSTEM_SCOPE;
import static org.wso2.carbon.identity.oauth2.device.constants.Constants.DEVICE_FLOW_GRANT_TYPE;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.EXTENDED_REFRESH_TOKEN_DEFAULT_TIME;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.INTERNAL_LOGIN_SCOPE;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.validateRequestTenantDomain;
import static org.wso2.carbon.identity.openidconnect.OIDCConstants.ID_TOKEN_USER_CLAIMS_PROP_KEY;

/**
 * This class is used to issue access tokens and refresh tokens.
 */
public class AccessTokenIssuer {

    private static AccessTokenIssuer instance;
    private static final Log log = LogFactory.getLog(AccessTokenIssuer.class);
    private Map<String, AuthorizationGrantHandler> authzGrantHandlers;
    public static final String OAUTH_APP_DO = "OAuthAppDO";
    private static final String SERVICE_PROVIDERS_SUB_CLAIM = "ServiceProviders.UseUsernameAsSubClaim";
    private final AuthorizationDetailsValidator authorizationDetailsValidator;

    /**
     * Private constructor which will not allow to create objects of this class from outside
     */
    private AccessTokenIssuer() throws IdentityOAuth2Exception {

        authzGrantHandlers = OAuthServerConfiguration.getInstance().getSupportedGrantTypes();
        this.authorizationDetailsValidator = new DefaultAuthorizationDetailsValidator();
        AppInfoCache appInfoCache = AppInfoCache.getInstance();
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
        boolean isCodeRequest = GrantType.AUTHORIZATION_CODE.toString().equals(grantType);
        boolean isDeviceCodeRequest = DEVICE_FLOW_GRANT_TYPE.equals(grantType);

        if (isCodeRequest) {

            AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(getAuthorizationCode(tokenReqDTO));
            AuthorizationGrantCacheEntry authorizationGrantCacheEntry =
                    AuthorizationGrantCache.getInstance().getValueFromCacheByCode(cacheKey);
            if (authorizationGrantCacheEntry != null &&
                    authorizationGrantCacheEntry.getAccessTokenExtensionDO() != null) {
                if (authorizationGrantCacheEntry.getAccessTokenExtensionDO().getRefreshTokenValidityPeriod() >
                        EXTENDED_REFRESH_TOKEN_DEFAULT_TIME) {
                    tokReqMsgCtx.setRefreshTokenvalidityPeriod(
                            authorizationGrantCacheEntry.getAccessTokenExtensionDO().getRefreshTokenValidityPeriod());
                }
                tokReqMsgCtx.getOauth2AccessTokenReqDTO().setAccessTokenExtendedAttributes(
                        authorizationGrantCacheEntry.getAccessTokenExtensionDO());
            }
            persistImpersonationInfoToTokenReqCtx(authorizationGrantCacheEntry, tokReqMsgCtx);
        }

        if (isDeviceCodeRequest) {
            AuthorizationGrantCacheEntry authorizationGrantCacheEntry =
                    getAuthzGrantCacheEntryFromDeviceCode(tokenReqDTO);
            persistImpersonationInfoToTokenReqCtx(authorizationGrantCacheEntry, tokReqMsgCtx);
        }

        triggerPreListeners(tokenReqDTO, tokReqMsgCtx, isRefreshRequest);

        OAuthClientAuthnContext oAuthClientAuthnContext = tokenReqDTO.getoAuthClientAuthnContext();

        DiagnosticLog.DiagnosticLogBuilder errorDiagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            errorDiagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.ISSUE_ACCESS_TOKEN)
                    .inputParam(LogConstants.InputKeys.CLIENT_ID, tokenReqDTO.getClientId())
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.FAILED);
        }
        if (oAuthClientAuthnContext == null) {
            // errorDiagnosticLogBuilder will be null if diagnostic logs are disabled.
            if (errorDiagnosticLogBuilder != null) {
                errorDiagnosticLogBuilder.resultMessage("OAuth client authentication failed.");
                LoggerUtils.triggerDiagnosticLogEvent(errorDiagnosticLogBuilder);
            }
            oAuthClientAuthnContext = new OAuthClientAuthnContext();
            oAuthClientAuthnContext.setAuthenticated(false);
            oAuthClientAuthnContext.setErrorMessage("Client Authentication Failed");
            oAuthClientAuthnContext.setErrorCode(OAuthError.TokenResponse.INVALID_REQUEST);
        }

        // Will return an invalid request response if multiple authentication mechanisms are engaged irrespective of
        // whether the grant type is confidential or not.
        if (oAuthClientAuthnContext.isMultipleAuthenticatorsEngaged()) {
            // errorDiagnosticLogBuilder will be null if diagnostic logs are disabled.
            if (errorDiagnosticLogBuilder != null) {
                errorDiagnosticLogBuilder.inputParam("client authenticators",
                                oAuthClientAuthnContext.getExecutedAuthenticators())
                        .resultMessage("The client MUST NOT use more than one authentication method per request.");
                LoggerUtils.triggerDiagnosticLogEvent(errorDiagnosticLogBuilder);
            }
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
            // errorDiagnosticLogBuilder will be null if diagnostic logs are disabled.
            if (errorDiagnosticLogBuilder != null) {
                errorDiagnosticLogBuilder.resultMessage("Unsupported grant type.")
                        .inputParam(OAuthConstants.LogConstants.InputKeys.GRANT_TYPE, grantType);
                LoggerUtils.triggerDiagnosticLogEvent(errorDiagnosticLogBuilder);
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
            // errorDiagnosticLogBuilder will be null if diagnostic logs are disabled.
            if (errorDiagnosticLogBuilder != null) {
                errorDiagnosticLogBuilder.resultMessage("Unsupported client authentication method.");
                LoggerUtils.triggerDiagnosticLogEvent(errorDiagnosticLogBuilder);
            }
            tokenRespDTO = handleError(
                    OAuth2ErrorCodes.INVALID_CLIENT,
                    "Unsupported Client Authentication Method!", tokenReqDTO);
            setResponseHeaders(tokReqMsgCtx, tokenRespDTO);
            triggerPostListeners(tokenReqDTO, tokenRespDTO, tokReqMsgCtx, isRefreshRequest);
            return tokenRespDTO;
        }
        if (!isAuthenticated) {
            // errorDiagnosticLogBuilder will be null if diagnostic logs are disabled.
            if (errorDiagnosticLogBuilder != null) {
                errorDiagnosticLogBuilder.resultMessage("Client authentication failed.")
                        .inputParam(LogConstants.InputKeys.ERROR_MESSAGE, oAuthClientAuthnContext.getErrorMessage());
                LoggerUtils.triggerDiagnosticLogEvent(errorDiagnosticLogBuilder);
            }
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
        // Indirectly we can say that the tenantDomain of the SP is the tenantDomain of the user who created SP.
        // This is done to avoid having to send the tenantDomain as a query param to the token endpoint
        String tenantDomainOfApp = OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
        validateRequestTenantDomain(tenantDomainOfApp, tokenReqDTO);

        tokenReqDTO.setTenantDomain(tenantDomainOfApp);

        tokReqMsgCtx.addProperty(OAUTH_APP_DO, oAuthAppDO);

        boolean isOfTypeApplicationUser = authzGrantHandler.isOfTypeApplicationUser(tokReqMsgCtx);

        if (!isOfTypeApplicationUser) {
            tokReqMsgCtx.setAuthorizedUser(oAuthAppDO.getAppOwner());
            tokReqMsgCtx.addProperty(OAuthConstants.UserType.USER_TYPE, OAuthConstants.UserType.APPLICATION);
            String applicationResidentOrgId = PrivilegedCarbonContext.getThreadLocalCarbonContext()
                    .getApplicationResidentOrganizationId();
            /*
             If applicationResidentOrgId is not empty, then the request comes for an application which is registered
             directly in the organization of the applicationResidentOrgId. Therefore, we are setting the authorized
             user's accessing organization as the applicationResidentOrgId.
            */
            if (StringUtils.isNotEmpty(applicationResidentOrgId)) {
                tokReqMsgCtx.getAuthorizedUser().setAccessingOrganization(applicationResidentOrgId);
            }
        } else {
            tokReqMsgCtx.addProperty(OAuthConstants.UserType.USER_TYPE, OAuthConstants.UserType.APPLICATION_USER);
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
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.ISSUE_ACCESS_TOKEN)
                        .inputParam(LogConstants.InputKeys.ERROR_MESSAGE, error)
                        .resultMessage("System error occurred.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED));
            }
        }

        if (!isAuthorizedClient) {

            if (log.isDebugEnabled()) {
                log.debug("Client Id: " + tokenReqDTO.getClientId() + " is not authorized to use grant type: " +
                        grantType);
            }
            // errorDiagnosticLogBuilder will be null if diagnostic logs are disabled.
            if (errorDiagnosticLogBuilder != null) {
                errorDiagnosticLogBuilder.inputParam(OAuthConstants.LogConstants.InputKeys.GRANT_TYPE, grantType)
                        .resultMessage("Client is not authorized to use the requested grant type.");
                LoggerUtils.triggerDiagnosticLogEvent(errorDiagnosticLogBuilder);
            }
            tokenRespDTO = handleError(OAuthError.TokenResponse.UNAUTHORIZED_CLIENT, error, tokenReqDTO);
            setResponseHeaders(tokReqMsgCtx, tokenRespDTO);
            triggerPostListeners(tokenReqDTO, tokenRespDTO, tokReqMsgCtx, isRefreshRequest);
            return tokenRespDTO;
        }

        String syncLockString = authzGrantHandler.buildSyncLockString(tokReqMsgCtx);
        if (StringUtils.isBlank(syncLockString)) {
            tokenRespDTO = validateGrantAndIssueToken(tokenReqDTO, tokReqMsgCtx, tokenRespDTO, authzGrantHandler,
                    tenantDomainOfApp, oAuthAppDO);
        } else {
            synchronized (syncLockString.intern()) {
                tokenRespDTO = validateGrantAndIssueToken(tokenReqDTO, tokReqMsgCtx, tokenRespDTO, authzGrantHandler,
                        tenantDomainOfApp, oAuthAppDO);
            }
        }

        if (tokenRespDTO != null && !tokenRespDTO.isError() && tokenRespDTO.getAccessToken() != null) {
            OAuthEventPublishingUtil.publishTokenIssueEvent(tokReqMsgCtx, tokenReqDTO);
        }

        return tokenRespDTO;
    }

    private AuthorizationGrantCacheEntry getAuthzGrantCacheEntryFromDeviceCode(OAuth2AccessTokenReqDTO tokenReqDTO) {

        Optional<String> deviceCodeOptional = getDeviceCode(tokenReqDTO);
        if (deviceCodeOptional.isPresent()) {
            String deviceCode = deviceCodeOptional.get();
            Optional<AuthorizationGrantCacheEntry> authorizationGrantCacheEntryOptional
                    = getAuthzGrantCacheEntryFromDeviceCode(deviceCode);
            return authorizationGrantCacheEntryOptional.orElse(null);
        }
        return null;
    }

    private void persistImpersonationInfoToTokenReqCtx(AuthorizationGrantCacheEntry authorizationGrantCacheEntry,
                                                     OAuthTokenReqMessageContext tokReqMsgCtx) {

        // Set impersonation details into the token context before triggeringPreListeners.
        if (authorizationGrantCacheEntry != null && authorizationGrantCacheEntry.getImpersonator() != null) {
            tokReqMsgCtx.setImpersonationRequest(true);
            // Mandatory when getting additional claims (may_act & sub).
            tokReqMsgCtx.addProperty(IMPERSONATING_ACTOR, authorizationGrantCacheEntry.getImpersonator());
        }
    }

    private OAuth2AccessTokenRespDTO validateGrantAndIssueToken(OAuth2AccessTokenReqDTO tokenReqDTO,
                                                                OAuthTokenReqMessageContext tokReqMsgCtx,
                                                                OAuth2AccessTokenRespDTO tokenRespDTO,
                                                                AuthorizationGrantHandler authzGrantHandler,
                                                                String tenantDomainOfApp,
                                                                OAuthAppDO oAuthAppDO) throws IdentityException {

        String grantType = tokenReqDTO.getGrantType();
        boolean isRefreshRequest = GrantType.REFRESH_TOKEN.toString().equals(grantType);
        boolean isOfTypeApplicationUser = authzGrantHandler.isOfTypeApplicationUser(tokReqMsgCtx);

        boolean isValidGrant = false;
        String error = "Provided Authorization Grant is invalid";
        String errorCode = OAuthError.TokenResponse.INVALID_GRANT;
        try {
            isValidGrant = authzGrantHandler.validateGrant(tokReqMsgCtx);
        } catch (IdentityOAuth2Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while validating grant", e);
            }
            if (e.getErrorCode() != null) {
                errorCode = e.getErrorCode();
            }
            error = e.getMessage();
            if (e.getErrorCode() != null) {
                errorCode = e.getErrorCode();
            }
        }

        AuthenticatedUser authenticatedUser = tokReqMsgCtx.getAuthorizedUser();
        if (authenticatedUser != null && authenticatedUser.isFederatedUser()) {
            boolean skipTenantDomainOverWriting = false;
            if (authenticatedUser.getTenantDomain() != null) {
                skipTenantDomainOverWriting = OAuth2Util.isFederatedRoleBasedAuthzEnabled(tokReqMsgCtx);
            }
            // If federated role-based authorization is engaged skip overwriting the user tenant domain.
            if (!skipTenantDomainOverWriting) {
                authenticatedUser.setTenantDomain(tenantDomainOfApp);
            }
        }

        if (!isValidGrant) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid Grant provided by the client Id: " + tokenReqDTO.getClientId());
            }
            tokenRespDTO = handleError(errorCode, error, tokenReqDTO);
            setResponseHeaders(tokReqMsgCtx, tokenRespDTO);
            triggerPostListeners(tokenReqDTO, tokenRespDTO, tokReqMsgCtx, isRefreshRequest);
            return tokenRespDTO;
        }

        boolean isAuthorized = authzGrantHandler.authorizeAccessDelegation(tokReqMsgCtx);
        if (!isAuthorized) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid authorization for client Id : " + tokenReqDTO.getClientId());
            }
            tokenRespDTO = handleError(OAuthError.TokenResponse.UNAUTHORIZED_CLIENT,
                    "Unauthorized Client!", tokenReqDTO);
            setResponseHeaders(tokReqMsgCtx, tokenRespDTO);
            triggerPostListeners(tokenReqDTO, tokenRespDTO, tokReqMsgCtx, isRefreshRequest);
            return tokenRespDTO;
        }

        boolean isValidScope = validateScope(tokReqMsgCtx);
        if (!isValidScope) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid scope provided by client Id: " + tokenReqDTO.getClientId());
            }

            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.SCOPE_VALIDATION)
                        .inputParam(LogConstants.InputKeys.CLIENT_ID, tokenReqDTO.getClientId())
                        .inputParam(OAuthConstants.LogConstants.InputKeys.REQUESTED_SCOPES,
                                getScopeList(tokenReqDTO.getScope()))
                        .resultMessage("Invalid scope provided in the request.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED));
            }
            tokenRespDTO = handleError(OAuthError.TokenResponse.INVALID_SCOPE, "Invalid Scope!", tokenReqDTO);
            setResponseHeaders(tokReqMsgCtx, tokenRespDTO);
            triggerPostListeners(tokenReqDTO, tokenRespDTO, tokReqMsgCtx, isRefreshRequest);
            return tokenRespDTO;
        }

        if (AuthorizationDetailsUtils.isRichAuthorizationRequest(tokReqMsgCtx)) {
            try {
                final AuthorizationDetails validatedAuthorizationDetails = this.authorizationDetailsValidator
                        .getValidatedAuthorizationDetails(tokReqMsgCtx);
                tokReqMsgCtx.setAuthorizationDetails(validatedAuthorizationDetails);
            } catch (AuthorizationDetailsProcessingException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Invalid authorization details requested by client Id: " + tokenReqDTO.getClientId());
                }

                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                            OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                            OAuthConstants.LogConstants.ActionIDs.VALIDATE_AUTHORIZATION_DETAILS)
                            .inputParam(LogConstants.InputKeys.CLIENT_ID, tokenReqDTO.getClientId())
                            .inputParam(OAuthConstants.LogConstants.InputKeys.REQUESTED_AUTHORIZATION_DETAILS,
                                    tokenReqDTO.getAuthorizationDetails().toSet())
                            .resultMessage(AuthorizationDetailsConstants.VALIDATION_FAILED_ERR_MSG)
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED));
                }
                tokenRespDTO = handleError(AuthorizationDetailsConstants.VALIDATION_FAILED_ERR_CODE,
                        AuthorizationDetailsConstants.VALIDATION_FAILED_ERR_MSG, tokenReqDTO);
                setResponseHeaders(tokReqMsgCtx, tokenRespDTO);
                triggerPostListeners(tokenReqDTO, tokenRespDTO, tokReqMsgCtx, isRefreshRequest);
                return tokenRespDTO;
            }
        }

        handleTokenBinding(tokenReqDTO, grantType, tokReqMsgCtx, oAuthAppDO);

        try {
            // set the token request context to be used by downstream handlers. This is introduced as a fix for
            // IDENTITY-4111.
            OAuth2Util.setTokenRequestContext(tokReqMsgCtx);

            AuthenticatedUser authorizedUser = tokReqMsgCtx.getAuthorizedUser();
            ServiceProvider serviceProvider = getServiceProvider(tokReqMsgCtx.getOauth2AccessTokenReqDTO());
            boolean useClientIdAsSubClaimForAppTokensEnabledServerConfig = OAuthServerConfiguration.getInstance()
                    .isUseClientIdAsSubClaimForAppTokensEnabled();
            boolean useClientIdAsSubClaimForAppTokensEnabled =
                    OAuth2Util.isAppVersionAllowed(serviceProvider.getApplicationVersion(),
                            ApplicationConstants.ApplicationVersion.APP_VERSION_V1);
            if (authorizedUser.getAuthenticatedSubjectIdentifier() == null) {
                if ((!isOfTypeApplicationUser && (useClientIdAsSubClaimForAppTokensEnabled
                        || useClientIdAsSubClaimForAppTokensEnabledServerConfig))) {
                    authorizedUser.setAuthenticatedSubjectIdentifier(oAuthAppDO.getOauthConsumerKey());
                } else {
                    authorizedUser.setAuthenticatedSubjectIdentifier(getSubjectClaim(serviceProvider, authorizedUser));
                }
            }

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
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                    OAuthConstants.LogConstants.ActionIDs.ISSUE_ACCESS_TOKEN);
            diagnosticLogBuilder.inputParam(LogConstants.InputKeys.CLIENT_ID, tokenReqDTO.getClientId())
                    .inputParam(OAuthConstants.LogConstants.InputKeys.AUTHORIZED_SCOPES,
                            tokenRespDTO.getAuthorizedScopes())
                    .inputParam(OAuthConstants.LogConstants.InputKeys.GRANT_TYPE, grantType)
                    .inputParam("token expiry time (s)", tokenRespDTO.getExpiresIn())
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
            if (tokReqMsgCtx.isImpersonationRequest()) {
                if (tokReqMsgCtx.getProperty(IMPERSONATING_ACTOR) != null) {
                    String impersonatorId = tokReqMsgCtx.getProperty(IMPERSONATING_ACTOR).toString();
                    diagnosticLogBuilder.inputParam(IMPERSONATOR, impersonatorId);
                }
                diagnosticLogBuilder.resultMessage("Impersonated Access token issued for the application.");
            } else {
                diagnosticLogBuilder.resultMessage("Access token issued for the application.");
            }
            if (tokReqMsgCtx.getAuthorizedUser() != null) {
                diagnosticLogBuilder.inputParam(LogConstants.InputKeys.USER_ID,
                        tokReqMsgCtx.getAuthorizedUser().getUserId());
                String username = tokReqMsgCtx.getAuthorizedUser().getUserName();
                diagnosticLogBuilder.inputParam(LogConstants.InputKeys.USER, LoggerUtils.isLogMaskingEnable ?
                        LoggerUtils.getMaskedContent(username) : username);
            }
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        Optional<AuthorizationGrantCacheEntry> authorizationGrantCacheEntry = Optional.empty();
        if (GrantType.AUTHORIZATION_CODE.toString().equals(grantType)) {

            authorizationGrantCacheEntry = getAuthzGrantCacheEntryFromAuthzCode(tokenReqDTO);
        }
        if (tokReqMsgCtx.getScope() != null && OAuth2Util.isOIDCAuthzRequest(tokReqMsgCtx.getScope())) {
            if (log.isDebugEnabled()) {
                log.debug("Issuing ID token for client: " + tokenReqDTO.getClientId());
            }
            IDTokenBuilder builder = OAuthServerConfiguration.getInstance().getOpenIDConnectIDTokenBuilder();
            try {
                String idToken = builder.buildIDToken(tokReqMsgCtx, tokenRespDTO);
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                            OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                            OAuthConstants.LogConstants.ActionIDs.ISSUE_ID_TOKEN);
                    diagnosticLogBuilder.inputParam(LogConstants.InputKeys.CLIENT_ID, tokenReqDTO.getClientId())
                            .inputParam("issued claims for id token", tokReqMsgCtx.getProperty(
                                    ID_TOKEN_USER_CLAIMS_PROP_KEY))
                            .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                            .resultMessage("ID token issued for the application.")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
                tokenRespDTO.setIDToken(idToken);
            } catch (IDTokenValidationFailureException e) {
                log.error(e.getMessage());
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                            OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                            OAuthConstants.LogConstants.ActionIDs.ISSUE_ID_TOKEN)
                            .inputParam(LogConstants.InputKeys.CLIENT_ID, tokenReqDTO.getClientId())
                            .inputParam(LogConstants.InputKeys.ERROR_MESSAGE, e.getMessage())
                            .resultMessage("System error occurred.")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED));
                }
                tokenRespDTO = handleError(OAuth2ErrorCodes.SERVER_ERROR, "Server Error", tokenReqDTO);
                return tokenRespDTO;
            }
        }

        List<AccessTokenResponseHandler> tokenResponseHandlers = OAuthComponentServiceHolder.getInstance().
                getAccessTokenResponseHandlers();
        // Engaging token response handlers.
        for (AccessTokenResponseHandler tokenResponseHandler : tokenResponseHandlers) {
            Map<String, Object> additionalTokenResponseAttributes =
                    tokenResponseHandler.getAdditionalTokenResponseAttributes(tokReqMsgCtx);
            if (additionalTokenResponseAttributes != null) {
                for (Map.Entry<String, Object> attribute : additionalTokenResponseAttributes.entrySet()) {
                    tokenRespDTO.addParameterObject(attribute.getKey(), attribute.getValue());
                }
            }
        }

        if (Constants.DEVICE_FLOW_GRANT_TYPE.equals(grantType)) {
            Optional<String> deviceCodeOptional = getDeviceCode(tokenReqDTO);
            if (deviceCodeOptional.isPresent()) {
                String deviceCode = deviceCodeOptional.get();
                authorizationGrantCacheEntry = getAuthzGrantCacheEntryFromDeviceCode(deviceCode);
                // Cache entry against the device code has no value beyond the token request.
                clearCacheEntryAgainstDeviceCode(deviceCode);
            }
        }
        if (authorizationGrantCacheEntry.isPresent()) {
            cacheUserAttributesAgainstAccessToken(authorizationGrantCacheEntry.get(), tokenRespDTO);
        }

        if (GrantType.PASSWORD.toString().equals(grantType)) {
            addUserAttributesAgainstAccessTokenForPasswordGrant(tokenRespDTO, tokReqMsgCtx);
        }

        persistCustomizedAccessTokenAttributesForRefreshToken(tokenRespDTO, tokReqMsgCtx);

        if (GrantType.AUTHORIZATION_CODE.toString().equals(grantType)) {
            // Cache entry against the authorization code has no value beyond the token request.
            clearCacheEntryAgainstAuthorizationCode(getAuthorizationCode(tokenReqDTO));
        }

        // Write impersonation details to into the session context.
        if (!tokenRespDTO.isError() && tokReqMsgCtx.isImpersonationRequest() && TOKEN_EXCHANGE.equals(grantType)) {
            persistImpersonationInfoToSessionContext(tokenReqDTO, tokReqMsgCtx.getAuthorizedUser().getTenantDomain(),
                    tokReqMsgCtx);
        }

        return tokenRespDTO;
    }

    private void persistImpersonationInfoToSessionContext(OAuth2AccessTokenReqDTO tokenReqDTO, String tenantDomain,
                                                          OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        RequestParameter[] params = tokenReqDTO.getRequestParameters();
        Map<String, String> requestParams = Arrays.stream(params).collect(Collectors.toMap(RequestParameter::getKey,
                requestParam -> requestParam.getValue()[0]));
        JWTClaimsSet claimsSetSubjectToken = OAuth2TokenUtil.getJWTClaimSet(requestParams.get(SUBJECT_TOKEN));
        JWTClaimsSet claimsSetActorToken = OAuth2TokenUtil.getJWTClaimSet(requestParams.get(ACTOR_TOKEN));

        if (claimsSetSubjectToken != null && claimsSetActorToken != null) {
            if (claimsSetSubjectToken.getClaim(MAY_ACT) == null) {
                throw new IdentityOAuth2Exception("may_act claim is not found in the subject token.");
            }

            String subClaim = claimsSetSubjectToken.getSubject();
            String iskClaim = (String) claimsSetActorToken.getClaim(OAuthConstants.OIDCClaims.IDP_SESSION_KEY);

            // Set session context data.
            if (subClaim != null && iskClaim != null) {
                SessionContext sessionContext = FrameworkUtils.getSessionContextFromCache(iskClaim, tenantDomain);
                // Send notification only on session impersonation initiation.
                if (sessionContext.getImpersonatedUser() == null) {
                    notifyImpersonation(tokReqMsgCtx);
                }
                sessionContext.setImpersonatedUser(subClaim);
                FrameworkUtils.addSessionContextToCache(iskClaim, sessionContext, tenantDomain, tenantDomain);
            }
        }
    }

    private void notifyImpersonation(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        ImpersonationNotificationRequestDTO impersonationNotificationRequestDTO
                = new ImpersonationNotificationRequestDTO();
        impersonationNotificationRequestDTO.setTokenReqMessageContext(tokReqMsgCtx);
        String impersonatorUserId = (String) tokReqMsgCtx.getProperty(IMPERSONATING_ACTOR);
        impersonationNotificationRequestDTO.setImpersonator(impersonatorUserId);
        AuthenticatedUser impersonatedUser = tokReqMsgCtx.getAuthorizedUser();
        impersonationNotificationRequestDTO.setSubject(impersonatedUser);
        impersonationNotificationRequestDTO.setTenantDomain(tokReqMsgCtx.getAuthorizedUser().getTenantDomain());
        ImpersonationNotificationMgtService notificationMgtService = new ImpersonationNotificationMgtServiceImpl();
        notificationMgtService.notifyImpersonation(impersonationNotificationRequestDTO);
    }

    private Optional<AuthorizationGrantCacheEntry> getAuthzGrantCacheEntryFromDeviceCode(String deviceCode) {

        DeviceAuthorizationGrantCacheKey deviceCodeCacheKey =
                new DeviceAuthorizationGrantCacheKey(deviceCode);
        DeviceAuthorizationGrantCacheEntry cacheEntry =
                DeviceAuthorizationGrantCache.getInstance().getValueFromCache(deviceCodeCacheKey);
        if (cacheEntry != null) {
            Map<ClaimMapping, String> userAttributes = cacheEntry.getUserAttributes();
            AuthorizationGrantCacheEntry authorizationGrantCacheEntry =
                    new AuthorizationGrantCacheEntry(userAttributes);
            if (cacheEntry.getMappedRemoteClaims() != null) {
                authorizationGrantCacheEntry.setMappedRemoteClaims(cacheEntry
                        .getMappedRemoteClaims());
            }
            persistImpersonationInfoToAuthzGrantCacheEntry(cacheEntry, authorizationGrantCacheEntry);
            return Optional.of(authorizationGrantCacheEntry);
        }
        return Optional.empty();
    }

    private void persistImpersonationInfoToAuthzGrantCacheEntry(DeviceAuthorizationGrantCacheEntry cacheEntry,
                                                                AuthorizationGrantCacheEntry
                                                                        authorizationGrantCacheEntry) {

        if (cacheEntry.getImpersonator() != null) {
            authorizationGrantCacheEntry.setImpersonator(cacheEntry.getImpersonator());
        }
    }

    private Optional<AuthorizationGrantCacheEntry> getAuthzGrantCacheEntryFromAuthzCode(OAuth2AccessTokenReqDTO
                                                                                                tokenReqDTO) {

        AuthorizationGrantCacheKey oldCacheKey = new AuthorizationGrantCacheKey(getAuthorizationCode(tokenReqDTO));
        AuthorizationGrantCacheEntry authorizationGrantCacheEntry = null;
        //checking getUserAttributesId value of cacheKey before retrieve entry from cache as it causes to NPE
        if (oldCacheKey.getUserAttributesId() != null) {
            authorizationGrantCacheEntry = AuthorizationGrantCache.getInstance().getValueFromCacheByCode(oldCacheKey);
        }
        if (authorizationGrantCacheEntry != null) {
            return Optional.of(authorizationGrantCacheEntry);
        }
        return Optional.empty();
    }

    private boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        OAuth2AccessTokenReqDTO tokenReqDTO = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        String grantType = tokenReqDTO.getGrantType();
        if (tokReqMsgCtx.isImpersonationRequest() && TOKEN_EXCHANGE.equals(grantType)) {
            /*
             In the impersonation flow, we have already completed scope validation during the /authorize call and
             issued a subject token with the authorized scopes. During the token flow, if the scope body param presented
             then we will take the intersection of scope. This also handled in the token exchange handler. Therefore,
             it does not make sense to go through scope validation again as there won't be any new scopes to validate.
            */
            if (log.isDebugEnabled()) {
                log.debug("Skipping scope validation for impersonation flow as scope validation has already " +
                        "happened in the authorize flow.");
            }
            return true;
        }
        if (GrantType.AUTHORIZATION_CODE.toString().equals(grantType)) {
            /*
             In the authorization code flow, we have already completed scope validation during the /authorize call and
             issued an authorization code with the authorized scopes. During the token flow we only consider the
             scopes bound to the issued authorization code and simply ignore any 'scope' parameter sent in the
             subsequent token request. Therefore, it does not make sense to go through scope validation again as
             there won't be any new scopes to validate.
            */
            if (log.isDebugEnabled()) {
                log.debug("Skipping scope validation for authorization code flow as scope validation has already " +
                        "happened in the authorize flow.");
            }
            return true;
        }
        if (GrantType.REFRESH_TOKEN.toString().equals(grantType)) {
            /*
             In the refresh token flow, we have already completed scope validation during the initial token call and
             issued the token with authorized scopes. Therefore, during the refresh flow we don't need to do the
             internal scope validation again. But we need to call the grant type specific scope validation handler to
             issue the token with only the authorized scopes.
            */
            AuthorizationGrantHandler authzGrantHandler = authzGrantHandlers.get(grantType);
            if (log.isDebugEnabled()) {
                log.debug("Calling grant type specific scope validation handler for the refresh token grant and " +
                        "omitting internal scope validation as internal scope validation already done " +
                        "during the token issuance.");
            }
            boolean isValidScope = authzGrantHandler.validateScope(tokReqMsgCtx);
            if (isValidScope) {
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                            OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                            OAuthConstants.LogConstants.ActionIDs.SCOPE_VALIDATION)
                            .inputParam(LogConstants.InputKeys.CLIENT_ID, tokenReqDTO.getClientId())
                            .inputParam(OAuthConstants.LogConstants.InputKeys.AUTHORIZED_SCOPES,
                                    getScopeList(tokReqMsgCtx.getScope()))
                            .resultMessage("OAuth scope validation is successful.")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.SUCCESS));
                }
            }
            return isValidScope;
        }
        boolean isManagementApp = getServiceProvider(tokenReqDTO).isManagementApp();
        List<String> requestedAllowedScopes = new ArrayList<>();
        String[] authorizedInternalScopes = new String[0];
        String[] requestedScopes = tokReqMsgCtx.getScope();
        List<String> authorizedScopes = null;
        if (AuthzUtil.isLegacyAuthzRuntime() && GrantType.CLIENT_CREDENTIALS.toString().equals(grantType) &&
                !isManagementApp) {
            log.debug("Application is not configured as Management App and the grant type is client credentials. " +
                    "Hence skipping internal scope validation to stop issuing internal scopes for the client : " +
                    tokenReqDTO.getClientId());
        } else {
            if (GrantType.CLIENT_CREDENTIALS.toString().equals(grantType) &&
                    ArrayUtils.contains(requestedScopes, INTERNAL_LOGIN_SCOPE)) {
                /*
                Remove the internal_login scope from the requested scopes as we need to stop issuing self-service
                related scopes for client credentials grant.
                */
                requestedScopes = (String[]) ArrayUtils.removeElement(requestedScopes, INTERNAL_LOGIN_SCOPE);
                tokReqMsgCtx.setScope(requestedScopes);
            }
            List<String> allowedScopes = OAuthServerConfiguration.getInstance().getAllowedScopes();
            List<String> scopesToBeValidated = new ArrayList<>();

            if (ArrayUtils.isNotEmpty(requestedScopes)) {
                for (String scope : requestedScopes) {
                    if (OAuth2Util.isAllowedScope(allowedScopes, scope)) {
                        requestedAllowedScopes.add(scope);
                    } else {
                        scopesToBeValidated.add(scope);
                    }
                }
                tokReqMsgCtx.setScope(scopesToBeValidated.toArray(new String[0]));
            }

            if (log.isDebugEnabled()) {
                log.debug("Handling the internal scope validation.");
            }
            // Switch the scope validators dynamically based on the authorization runtime.
            if (AuthzUtil.isLegacyAuthzRuntime()) {
                // Execute Internal SCOPE Validation.
                JDBCPermissionBasedInternalScopeValidator scopeValidator =
                        new JDBCPermissionBasedInternalScopeValidator();
                authorizedInternalScopes = scopeValidator.validateScope(tokReqMsgCtx);
                // Execute internal console scopes validation.
                if (IdentityUtil.isSystemRolesEnabled()) {
                    RoleBasedInternalScopeValidator roleBasedInternalScopeValidator =
                            new RoleBasedInternalScopeValidator();
                    String[] roleBasedInternalConsoleScopes = roleBasedInternalScopeValidator
                            .validateScope(tokReqMsgCtx);
                    authorizedInternalScopes = (String[]) ArrayUtils
                            .addAll(authorizedInternalScopes, roleBasedInternalConsoleScopes);
                }
            } else {
                // Engage new scope validator
                authorizedScopes = getAuthorizedScopes(tokReqMsgCtx);
                authorizedInternalScopes = authorizedScopes.stream()
                        .filter(scope -> scope.startsWith(INTERNAL_SCOPE_PREFIX) ||
                                scope.startsWith(CONSOLE_SCOPE_PREFIX) ||
                                scope.equalsIgnoreCase(SYSTEM_SCOPE))
                        .toArray(String[]::new);
                // Remove internal scopes from the authorized scopes since internal scopes are handled separately.
                authorizedScopes.removeAll(Arrays.asList(authorizedInternalScopes));
            }
            if (isManagementApp && GrantType.CLIENT_CREDENTIALS.toString().equals(grantType) &&
                    ArrayUtils.contains(requestedScopes, SYSTEM_SCOPE)) {
                List<String> authorizedInternalScopesList = new ArrayList<>(Arrays.asList(authorizedInternalScopes));
                if (authorizedInternalScopesList.contains(INTERNAL_LOGIN_SCOPE)) {
                    /*
                    Remove the internal_login scope from the requested scopes as we need to stop issuing self-service
                    related scopes for client credentials grant.
                    */
                    authorizedInternalScopesList.remove(INTERNAL_LOGIN_SCOPE);
                    authorizedInternalScopes = authorizedInternalScopesList.toArray(new String[0]);
                }
            }
        }

        // Adding the authorized internal scopes to tokReqMsgCtx for any special validators to use.
        tokReqMsgCtx.setAuthorizedInternalScopes(authorizedInternalScopes);

        /*
         Clear the internal scopes. Internal scopes should only handle in JDBCPermissionBasedInternalScopeValidator.
         Those scopes should not send to the other scopes validators. Thus remove the scopes from the tokReqMsgCtx.
         Will be added to the response after executing the other scope validators.
        */
        if (AuthzUtil.isLegacyAuthzRuntime()) {
            removeInternalScopes(tokReqMsgCtx);
        } else {
            removeAuthorizedScopes(tokReqMsgCtx, Arrays.asList(authorizedInternalScopes));
            removeAuthorizedScopes(tokReqMsgCtx, authorizedScopes);
        }

        boolean isDropUnregisteredScopes = OAuthServerConfiguration.getInstance().isDropUnregisteredScopes();
        if (isDropUnregisteredScopes) {
            if (log.isDebugEnabled()) {
                log.debug("DropUnregisteredScopes config is enabled. Attempting to drop unregistered scopes.");
            }
            String[] filteredScopes = OAuth2Util.dropUnregisteredScopes(
                    tokReqMsgCtx.getScope(),
                    tokReqMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain());
            tokReqMsgCtx.setScope(filteredScopes);
        }

        AuthorizationGrantHandler authzGrantHandler = authzGrantHandlers.get(grantType);
        boolean isValidScope = authzGrantHandler.validateScope(tokReqMsgCtx);
        if (isValidScope) {
            // Add authorized internal scopes to the request for sending in the response.
            addAuthorizedInternalScopes(tokReqMsgCtx, tokReqMsgCtx.getAuthorizedInternalScopes());
            if (!AuthzUtil.isLegacyAuthzRuntime()) {
                // Add authorized scopes to the request for sending in the response in new runtime.
                addAuthorizedScopes(tokReqMsgCtx, authorizedScopes);
            }
            addAllowedScopes(tokReqMsgCtx, requestedAllowedScopes.toArray(new String[0]));
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.SCOPE_VALIDATION)
                        .inputParam(LogConstants.InputKeys.CLIENT_ID, tokenReqDTO.getClientId())
                        .inputParam(OAuthConstants.LogConstants.InputKeys.REQUESTED_SCOPES,
                                getScopeList(tokenReqDTO.getScope()))
                        .inputParam(OAuthConstants.LogConstants.InputKeys.AUTHORIZED_SCOPES,
                                getScopeList(tokReqMsgCtx.getScope()))
                        .resultMessage("OAuth scope validation is successful.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.SUCCESS));
            }
        }
        return isValidScope;
    }

    private List<String> getAuthorizedScopes(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        DefaultOAuth2ScopeValidator scopeValidator = new DefaultOAuth2ScopeValidator();
        return scopeValidator.validateScope(tokReqMsgCtx);
    }

    private List<String> getScopeList(String[] scopes) {

        return ArrayUtils.isEmpty(scopes) ? Collections.emptyList() : Arrays.asList(scopes);
    }

    private ServiceProvider getServiceProvider(OAuth2AccessTokenReqDTO tokenReq) throws IdentityOAuth2Exception {

        ServiceProvider serviceProvider;
        try {
            serviceProvider = OAuth2ServiceComponentHolder.getApplicationMgtService().getServiceProviderByClientId(
                    tokenReq.getClientId(), OAuthConstants.Scope.OAUTH2, tokenReq.getTenantDomain());
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityOAuth2Exception("Error occurred while retrieving OAuth2 application data for client id " +
                    tokenReq.getClientId(), e);
        }
        if (serviceProvider == null) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find an application for client id: " + tokenReq.getClientId()
                        + ", scope: " + OAuthConstants.Scope.OAUTH2 + ", tenant: " + tokenReq.getTenantDomain());
            }
            throw new IdentityOAuth2Exception("Service Provider not found");
        }
        if (log.isDebugEnabled()) {
            log.debug("Retrieved service provider: " + serviceProvider.getApplicationName() + " for client: " +
                    tokenReq.getClientId() + ", scope: " + OAuthConstants.Scope.OAUTH2 + ", tenant: " +
                    tokenReq.getTenantDomain());
        }

        return serviceProvider;
    }

    private String getSubjectClaim(ServiceProvider serviceProvider,
                                   AuthenticatedUser authenticatedUser) throws IdentityOAuth2Exception {

        String userTenantDomain = authenticatedUser.getTenantDomain();
        String subject;
        String userStoreDomain = authenticatedUser.getUserStoreDomain();
        String subjectClaimUri = getSubjectClaimUriInLocalDialect(serviceProvider);
        if (StringUtils.isNotBlank(subjectClaimUri)) {
            try {
                subject = getSubjectClaimFromUserStore(subjectClaimUri, authenticatedUser);
                if (StringUtils.isBlank(subject)) {
                    // Set username as the subject claim since we have no other option
                    subject = getDefaultSubject(serviceProvider, authenticatedUser);
                    log.warn("Cannot find subject claim: " + subjectClaimUri + " for user:"
                            + authenticatedUser.getLoggableUserId()
                            + ". Defaulting to username: " + (LoggerUtils.isLogMaskingEnable ?
                            LoggerUtils.getMaskedContent(subject) : subject) + " as the subject identifier.");
                }
                // Get the subject claim in the correct format (ie. tenantDomain or userStoreDomain appended)
                subject = getFormattedSubjectClaim(serviceProvider, subject, userStoreDomain, userTenantDomain);
            } catch (IdentityException e) {
                String error = "Error occurred while getting user claim for user: "
                        + authenticatedUser.getLoggableUserId() + ", claim" +
                        ": " +
                        subjectClaimUri;
                throw new IdentityOAuth2Exception(error, e);
            } catch (org.wso2.carbon.user.core.UserStoreException e) {
                String error = "Error occurred while getting subject claim: " + subjectClaimUri + " for user: "
                        + authenticatedUser.getLoggableUserId();
                throw new IdentityOAuth2Exception(error, e);
            }
        } else {
            try {
                subject = getDefaultSubject(serviceProvider, authenticatedUser);
                subject = getFormattedSubjectClaim(serviceProvider, subject, userStoreDomain, userTenantDomain);
            } catch (UserIdNotFoundException e) {
                throw new IdentityOAuth2Exception("User id not found for user: "
                        + authenticatedUser.getLoggableMaskedUserId(), e);
            }
            if (log.isDebugEnabled()) {
                log.debug("No subject claim defined for service provider: " + serviceProvider.getApplicationName()
                        + ". Using username as the subject claim.");
            }

        }
        return subject;
    }

    private String getDefaultSubject(ServiceProvider serviceProvider, AuthenticatedUser authenticatedUser)
            throws UserIdNotFoundException {

        String subject;
        boolean useUserIdForDefaultSubject = false;
        ServiceProviderProperty[] spProperties = serviceProvider.getSpProperties();
        if (spProperties != null) {
            for (ServiceProviderProperty prop : spProperties) {
                if (IdentityApplicationConstants.USE_USER_ID_FOR_DEFAULT_SUBJECT.equals(prop.getName())) {
                    useUserIdForDefaultSubject = Boolean.parseBoolean(prop.getValue());
                    break;
                }
            }
        }
        boolean useUsernameAsSubClaim = useUsernameAsSubClaim();
        if (useUsernameAsSubClaim) {
            return authenticatedUser.getUserName();
        }

        if (useUserIdForDefaultSubject) {
            subject = authenticatedUser.getUserId();
        } else {
            subject = authenticatedUser.getUserName();
        }
        return subject;
    }

    private String getFormattedSubjectClaim(ServiceProvider serviceProvider, String subjectClaimValue,
                                            String userStoreDomain, String tenantDomain) {

        boolean appendUserStoreDomainToSubjectClaim = serviceProvider.getLocalAndOutBoundAuthenticationConfig()
                .isUseUserstoreDomainInLocalSubjectIdentifier();

        boolean appendTenantDomainToSubjectClaim = serviceProvider.getLocalAndOutBoundAuthenticationConfig()
                .isUseTenantDomainInLocalSubjectIdentifier();

        if (appendTenantDomainToSubjectClaim) {
            subjectClaimValue = UserCoreUtil.addTenantDomainToEntry(subjectClaimValue, tenantDomain);
        }
        if (appendUserStoreDomainToSubjectClaim) {
            subjectClaimValue = IdentityUtil.addDomainToName(subjectClaimValue, userStoreDomain);
        }

        return subjectClaimValue;
    }

    private String getSubjectClaimFromUserStore(String subjectClaimUri, AuthenticatedUser authenticatedUser)
            throws org.wso2.carbon.user.core.UserStoreException, IdentityException {

        AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) IdentityTenantUtil
                .getRealm(authenticatedUser.getTenantDomain(), authenticatedUser.toFullQualifiedUsername())
                .getUserStoreManager();
        if (OAuth2ServiceComponentHolder.getInstance().isOrganizationManagementEnabled() &&
                !userStoreManager.isExistingUserWithID(authenticatedUser.getUserId())) {
            // Fetch the user realm's user store manager corresponds to the tenant domain where the userID exists.
            userStoreManager = getUserStoreManagerFromRealmOfUserResideOrganization(authenticatedUser.getTenantDomain(),
                    authenticatedUser.getUserId()).orElse(userStoreManager);
        }
        return userStoreManager.getUserClaimValueWithID(authenticatedUser.getUserId(), subjectClaimUri, null);
    }

    private String getSubjectClaimUriInLocalDialect(ServiceProvider serviceProvider) {

        String subjectClaimUri = serviceProvider.getLocalAndOutBoundAuthenticationConfig().getSubjectClaimUri();
        if (log.isDebugEnabled()) {
            if (isNotBlank(subjectClaimUri)) {
                log.debug(subjectClaimUri + " is defined as subject claim for service provider: " +
                        serviceProvider.getApplicationName());
            } else {
                log.debug("No subject claim defined for service provider: " + serviceProvider.getApplicationName());
            }
        }
        // Get the local subject claim URI, if subject claim was a SP mapped one
        return getSubjectClaimUriInLocalDialect(serviceProvider, subjectClaimUri);
    }

    private String getSubjectClaimUriInLocalDialect(ServiceProvider serviceProvider, String subjectClaimUri) {

        if (isNotBlank(subjectClaimUri)) {
            ClaimConfig claimConfig = serviceProvider.getClaimConfig();
            if (claimConfig != null) {
                boolean isLocalClaimDialect = claimConfig.isLocalClaimDialect();
                ClaimMapping[] claimMappings = claimConfig.getClaimMappings();
                if (!isLocalClaimDialect && ArrayUtils.isNotEmpty(claimMappings)) {
                    for (ClaimMapping claimMapping : claimMappings) {
                        if (StringUtils.equals(claimMapping.getRemoteClaim().getClaimUri(), subjectClaimUri)) {
                            return claimMapping.getLocalClaim().getClaimUri();
                        }
                    }
                }
            }
        }
        // This means the original subjectClaimUri passed was the subject claim URI.
        return subjectClaimUri;
    }

    private void addAuthorizedInternalScopes(OAuthTokenReqMessageContext tokReqMsgCtx,
                                             String[] authorizedInternalScopes) {

        String[] scopes = tokReqMsgCtx.getScope();
        if (scopes == null) {
            scopes = new String[0];
        }
        if (authorizedInternalScopes == null) {
            authorizedInternalScopes = new String[0];
        }
        tokReqMsgCtx.setScope(Stream.concat(Arrays.stream(scopes), Arrays.stream(authorizedInternalScopes))
                .distinct().toArray(String[]::new));
    }

    private void addAuthorizedScopes(OAuthTokenReqMessageContext tokReqMsgCtx, List<String> authorizedScopes) {

        String[] scopes = tokReqMsgCtx.getScope();
        if (scopes == null) {
            scopes = new String[0];
        }
        if (authorizedScopes == null) {
            authorizedScopes = new ArrayList<>();
        }
        tokReqMsgCtx.setScope(Stream.concat(Arrays.stream(scopes), authorizedScopes.stream())
                .distinct().toArray(String[]::new));
    }

    private void addRequestedOIDCScopes(OAuthTokenReqMessageContext tokReqMsgCtx,
                                        String[] requestedOIDCScopes) {

        if (tokReqMsgCtx.getScope() == null) {
            tokReqMsgCtx.setScope(new String[0]);
        }
        Set<String> scopesToReturn = new HashSet<>(Arrays.asList(tokReqMsgCtx.getScope()));
        scopesToReturn.addAll(Arrays.asList(requestedOIDCScopes));
        String[] scopes = scopesToReturn.toArray(new String[0]);
        tokReqMsgCtx.setScope(scopes);
    }

    private void addAllowedScopes(OAuthTokenReqMessageContext tokReqMsgCtx, String[] allowedScopes) {

        String[] scopes = tokReqMsgCtx.getScope();
        String[] scopesToReturn = (String[]) ArrayUtils.addAll(scopes, allowedScopes);
        tokReqMsgCtx.setScope(scopesToReturn);

    }

    private void removeInternalScopes(OAuthTokenReqMessageContext tokReqMsgCtx) {

        if (tokReqMsgCtx.getScope() == null) {
            return;
        }
        List<String> scopes = new ArrayList<>();
        for (String scope : tokReqMsgCtx.getScope()) {
            if (!scope.startsWith(INTERNAL_SCOPE_PREFIX) && !scope.startsWith(CONSOLE_SCOPE_PREFIX) && !scope
                    .equalsIgnoreCase(SYSTEM_SCOPE)) {
                scopes.add(scope);
            }
        }
        tokReqMsgCtx.setScope(scopes.toArray(new String[0]));
    }

    private void removeAuthorizedScopes(OAuthTokenReqMessageContext tokReqMsgCtx, List<String> authorizedScopes) {

        if (tokReqMsgCtx.getScope() == null || authorizedScopes == null) {
            return;
        }
        List<String> scopes = new ArrayList<>();
        for (String scope : tokReqMsgCtx.getScope()) {
            if (!authorizedScopes.contains(scope) && !scope.equalsIgnoreCase(SYSTEM_SCOPE)) {
                scopes.add(scope);
            }
        }
        tokReqMsgCtx.setScope(scopes.toArray(new String[0]));
    }

    /**
     * Handle token binding for the grant type.
     *
     * @param tokenReqDTO  token request DTO.
     * @param grantType    grant type.
     * @param tokReqMsgCtx token request message context.
     * @param oAuthAppDO   oauth application.
     * @throws IdentityOAuth2Exception in case of failure.
     */
    private void handleTokenBinding(OAuth2AccessTokenReqDTO tokenReqDTO, String grantType,
                                    OAuthTokenReqMessageContext tokReqMsgCtx, OAuthAppDO oAuthAppDO)
            throws IdentityOAuth2Exception {

        if (StringUtils.isBlank(oAuthAppDO.getTokenBindingType())) {
            tokReqMsgCtx.setTokenBinding(null);
            return;
        }

        Optional<TokenBinder> tokenBinderOptional = OAuth2ServiceComponentHolder.getInstance()
                .getTokenBinder(oAuthAppDO.getTokenBindingType());
        if (!tokenBinderOptional.isPresent()) {
            throw new IdentityOAuth2Exception(
                    "Token binder for the binding type: " + oAuthAppDO.getTokenBindingType() + " is not registered.");
        }

        if (REFRESH_TOKEN.equals(grantType)) {
            // Token binding values are already set to the OAuthTokenReqMessageContext.
            return;
        }

        tokReqMsgCtx.setTokenBinding(null);

        TokenBinder tokenBinder = tokenBinderOptional.get();
        if (!tokenBinder.getSupportedGrantTypes().contains(grantType)) {
            return;
        }

        Optional<String> tokenBindingValueOptional = tokenBinder.getTokenBindingValue(tokenReqDTO);
        if (!tokenBindingValueOptional.isPresent()) {
            if (OAuth2Constants.TokenBinderType.CERTIFICATE_BASED_TOKEN_BINDER.equals(tokenBinder.getBindingType())) {
                throw new IdentityOAuth2ClientException(OAuth2ErrorCodes.INVALID_REQUEST,
                        "TLS certificate not found in the request.");
            }
            if (OAuth2Constants.TokenBinderType.CLIENT_REQUEST.equals(tokenBinder.getBindingType())) {
                // Treat as 'None' token binding requests.
                tokReqMsgCtx.setTokenBinding(null);
                return;
            }
            throw new IdentityOAuth2Exception(
                    "Token binding reference cannot be retrieved form the token binder: " + tokenBinder
                            .getBindingType());
        }

        if (OAuth2Constants.TokenBinderType.CLIENT_REQUEST.equals(tokenBinder.getBindingType()) &&
                tokenBindingValueOptional.get().length() >= MAX_ALLOWED_LENGTH) {
            throw new IdentityOAuth2ClientException(OAuth2ErrorCodes.INVALID_REQUEST,
                    "Token binding reference length exceeds limit");
        }

        String tokenBindingValue = tokenBindingValueOptional.get();
        tokReqMsgCtx.setTokenBinding(
                new TokenBinding(tokenBinder.getBindingType(), OAuth2Util.getTokenBindingReference(tokenBindingValue),
                        tokenBindingValue));
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
     * Copies the cache entry against the authorization code/device code and adds an entry against the access token.
     * This is done to reuse the calculated user claims for subsequent usages such as user info calls.
     *
     * @param authorizationGrantCacheEntry
     * @param tokenRespDTO
     */
    private void cacheUserAttributesAgainstAccessToken(AuthorizationGrantCacheEntry authorizationGrantCacheEntry,
                                                       OAuth2AccessTokenRespDTO tokenRespDTO) {

        AuthorizationGrantCacheKey newCacheKey = new AuthorizationGrantCacheKey(tokenRespDTO.getAccessToken());
        if (AuthorizationGrantCache.getInstance().getValueFromCache(newCacheKey) == null) {
            authorizationGrantCacheEntry.setTokenId(tokenRespDTO.getTokenId());
            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug("Adding AuthorizationGrantCache entry for the access token(hashed):" +
                            DigestUtils.sha256Hex(newCacheKey.getUserAttributesId()));
                } else {
                    log.debug("Adding AuthorizationGrantCache entry for the access token");
                }
            }
            authorizationGrantCacheEntry.setValidityPeriod(
                    TimeUnit.MILLISECONDS.toNanos(tokenRespDTO.getExpiresInMillis()));
            AuthorizationGrantCache.getInstance().addToCacheByToken(newCacheKey, authorizationGrantCacheEntry);
        } else {
            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug("AuthorizationGrantCache entry for the access token(hashed):" +
                            DigestUtils.sha256Hex(newCacheKey.getUserAttributesId()) + " already exists.");
                } else {
                    log.debug("AuthorizationGrantCache entry for the access token already exists.");
                }
            }
        }
    }

    private void addUserAttributesAgainstAccessTokenForPasswordGrant(OAuth2AccessTokenRespDTO tokenRespDTO,
                                                                     OAuthTokenReqMessageContext tokReqMsgCtx) {

        if (tokReqMsgCtx.getAuthorizedUser() != null) {
            AuthorizationGrantCacheKey newCacheKey = new AuthorizationGrantCacheKey(tokenRespDTO.getAccessToken());
            AuthorizationGrantCacheEntry authorizationGrantCacheEntry =
                    new AuthorizationGrantCacheEntry(tokReqMsgCtx.getAuthorizedUser().getUserAttributes());
            authorizationGrantCacheEntry.setTokenId(tokenRespDTO.getTokenId());

            authorizationGrantCacheEntry.setValidityPeriod(
                    TimeUnit.MILLISECONDS.toNanos(tokenRespDTO.getExpiresInMillis()));
            AuthorizationGrantCache.getInstance().addToCacheByToken(newCacheKey, authorizationGrantCacheEntry);
        }
    }

    private void persistCustomizedAccessTokenAttributesForRefreshToken(OAuth2AccessTokenRespDTO tokenRespDTO,
                                                                       OAuthTokenReqMessageContext tokReqMsgCtx) {

        /*
          If pre issue access token actions are executed it may have done modifications to the audience list, claims,
          incorporated to the access token which are not persisted in the access token table.
          If so, persist those custom modifications against the token id in the transaction session store
          to populate the authorized access token context back at refresh token flow.
         */
        if (tokReqMsgCtx.isPreIssueAccessTokenActionsExecuted()) {
            AuthorizationGrantCacheKey newCacheKey = new AuthorizationGrantCacheKey(tokenRespDTO.getTokenId());
            AuthorizationGrantCacheEntry authorizationGrantCacheEntry =
                    new AuthorizationGrantCacheEntry();
            authorizationGrantCacheEntry.setTokenId(tokenRespDTO.getTokenId());
            authorizationGrantCacheEntry.setPreIssueAccessTokenActionsExecuted(
                    tokReqMsgCtx.isPreIssueAccessTokenActionsExecuted());
            authorizationGrantCacheEntry.setAudiences(tokReqMsgCtx.getAudiences());
            authorizationGrantCacheEntry.setCustomClaims(tokReqMsgCtx.getAdditionalAccessTokenClaims());

            if (tokReqMsgCtx.getRefreshTokenValidityPeriodInMillis() > 0) {
                authorizationGrantCacheEntry.setValidityPeriod(
                        TimeUnit.MILLISECONDS.toNanos(tokReqMsgCtx.getRefreshTokenValidityPeriodInMillis()));
            } else {
                authorizationGrantCacheEntry.setValidityPeriod(
                        TimeUnit.MILLISECONDS.toNanos(tokReqMsgCtx.getRefreshTokenvalidityPeriod()));
            }
            AuthorizationGrantCache.getInstance().addToCacheByToken(newCacheKey, authorizationGrantCacheEntry);

            log.debug("Customized audience list and access token attributes from pre issue access token actions " +
                            "are persisted in the AuthorizationGrantCache against the token id: " +
                            tokenRespDTO.getTokenId());
        }
    }

    private void clearCacheEntryAgainstAuthorizationCode(String authorizationCode) {

        AuthorizationGrantCacheKey oldCacheKey = new AuthorizationGrantCacheKey(authorizationCode);
        //checking getUserAttributesId value of cacheKey before retrieve entry from cache as it causes to NPE
        if (oldCacheKey.getUserAttributesId() != null) {
            AuthorizationGrantCache.getInstance().clearCacheEntryByCode(oldCacheKey);
        }
    }

    private void clearCacheEntryAgainstDeviceCode(String deviceCode) {

        DeviceAuthorizationGrantCacheKey cacheKey = new DeviceAuthorizationGrantCacheKey(deviceCode);
        DeviceAuthorizationGrantCache.getInstance().clearCacheEntry(cacheKey);
    }

    private String getAuthorizationCode(OAuth2AccessTokenReqDTO tokenReqDTO) {

        return tokenReqDTO.getAuthorizationCode();
    }

    private Optional<String> getDeviceCode(OAuth2AccessTokenReqDTO tokenReqDTO) {

        return Arrays.stream(tokenReqDTO.getRequestParameters())
                .filter(parameter -> Constants.DEVICE_CODE.equals(parameter.getKey())
                        && parameter.getValue() != null
                        && parameter.getValue().length > 0)
                .map(parameter -> parameter.getValue()[0])
                .findFirst();
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
            tokenRespDTO.setResponseHeaders(
                    (ResponseHeader[]) tokReqMsgCtx.getProperty(OAuthConstants.RESPONSE_HEADERS_PROPERTY));
        }
    }

    private OAuthAppDO getOAuthApplication(String consumerKey) throws InvalidOAuthClientException,
            IdentityOAuth2Exception {

        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        String applicationResidentOrgId = PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getApplicationResidentOrganizationId();
        /*
         If the applicationResidentOrgId is not null, resolve the tenant domain from the organization id to get the
         application information by passing the consumer key and the tenant domain.
        */
        if (StringUtils.isNotEmpty(applicationResidentOrgId)) {
            try {
                tenantDomain = OAuthComponentServiceHolder.getInstance().getOrganizationManager()
                        .resolveTenantDomain(applicationResidentOrgId);
            } catch (OrganizationManagementException e) {
                throw new IdentityOAuth2Exception("Error while resolving tenant domain from the organization id: "
                        + applicationResidentOrgId, e);
            }
        }
        OAuthAppDO authAppDO = OAuth2Util.getAppInformationByClientId(consumerKey, tenantDomain);
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

    /**
     * If the user is not found in the given tenant domain, check the user existence from ancestor organizations and
     * provide the correct user store manager from the user realm.
     *
     * @param tenantDomain The tenant domain of the authenticated user.
     * @param userId       The ID of the authenticated user.
     * @return User store manager of the user reside organization.
     */
    private Optional<AbstractUserStoreManager> getUserStoreManagerFromRealmOfUserResideOrganization(String tenantDomain,
                                                                                                    String userId) {

        try {
            String organizationId = OAuth2ServiceComponentHolder.getInstance().getOrganizationManager()
                    .resolveOrganizationId(tenantDomain);
            Optional<String> userResideOrgId = OAuth2ServiceComponentHolder.getOrganizationUserResidentResolverService()
                    .resolveResidentOrganization(userId, organizationId);
            if (!userResideOrgId.isPresent()) {
                return Optional.empty();
            }
            String userResideTenantDomain = OAuth2ServiceComponentHolder.getInstance().getOrganizationManager()
                    .resolveTenantDomain(userResideOrgId.get());
            int tenantId = OAuth2ServiceComponentHolder.getInstance().getRealmService().getTenantManager()
                    .getTenantId(userResideTenantDomain);
            RealmService realmService = OAuth2ServiceComponentHolder.getInstance().getRealmService();
            return Optional.of(
                    (AbstractUserStoreManager) realmService.getTenantUserRealm(tenantId).getUserStoreManager());
        } catch (OrganizationManagementException | UserStoreException e) {
            return Optional.empty();
        }
    }

    /**
     * To get the config value to determine the subject claim value.
     *
     * @return Whether username should be used as the subject claim. If false, userId will be used as the subject claim.
     */
    public static boolean useUsernameAsSubClaim() {

        String useUsernameAsSubClaim = IdentityUtil.getProperty(SERVICE_PROVIDERS_SUB_CLAIM);
        if (!StringUtils.isEmpty(useUsernameAsSubClaim)) {
            return Boolean.parseBoolean(useUsernameAsSubClaim);
        }
        return false;
    }
}

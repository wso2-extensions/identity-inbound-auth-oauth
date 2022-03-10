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
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.owasp.encoder.Encode;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
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
import org.wso2.carbon.identity.oauth2.IDTokenValidationFailureException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.ResponseHeader;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinder;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.JDBCPermissionBasedInternalScopeValidator;
import org.wso2.carbon.identity.oauth2.validators.RoleBasedInternalScopeValidator;
import org.wso2.carbon.identity.openidconnect.IDTokenBuilder;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.CarbonUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static org.apache.commons.lang.StringUtils.isNotBlank;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.GrantTypes.REFRESH_TOKEN;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OauthAppStates.APP_STATE_ACTIVE;
import static org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants.CONSOLE_SCOPE_PREFIX;
import static org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants.INTERNAL_SCOPE_PREFIX;
import static org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants.SYSTEM_SCOPE;
import static org.wso2.carbon.identity.oauth2.util.OAuth2Util.validateRequestTenantDomain;

/**
 * This class is used to issue access tokens and refresh tokens.
 */
public class AccessTokenIssuer {

    private static AccessTokenIssuer instance;
    private static final Log log = LogFactory.getLog(AccessTokenIssuer.class);
    private Map<String, AuthorizationGrantHandler> authzGrantHandlers;
    public static final String OAUTH_APP_DO = "OAuthAppDO";

    /**
     * Private constructor which will not allow to create objects of this class from outside
     */
    private AccessTokenIssuer() throws IdentityOAuth2Exception {

        authzGrantHandlers = OAuthServerConfiguration.getInstance().getSupportedGrantTypes();
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

        triggerPreListeners(tokenReqDTO, tokReqMsgCtx, isRefreshRequest);

        OAuthClientAuthnContext oAuthClientAuthnContext = tokenReqDTO.getoAuthClientAuthnContext();

        if (oAuthClientAuthnContext == null) {
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                Map<String, Object> params = new HashMap<>();
                params.put("clientId", tokenReqDTO.getClientId());
                if (StringUtils.isNotBlank(tokenReqDTO.getClientSecret())) {
                    params.put("clientSecret", tokenReqDTO.getClientSecret().replaceAll(".", "*"));
                }
                LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, params,
                        OAuthConstants.LogConstants.FAILED, "OAuth client authentication failed.", "issue-access-token",
                        null);
            }
            oAuthClientAuthnContext = new OAuthClientAuthnContext();
            oAuthClientAuthnContext.setAuthenticated(false);
            oAuthClientAuthnContext.setErrorMessage("Client Authentication Failed");
            oAuthClientAuthnContext.setErrorCode(OAuthError.TokenResponse.INVALID_REQUEST);
        }

        // Will return an invalid request response if multiple authentication mechanisms are engaged irrespective of
        // whether the grant type is confidential or not.
        if (oAuthClientAuthnContext.isMultipleAuthenticatorsEngaged()) {
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                Map<String, Object> params = new HashMap<>();
                params.put("clientId", tokenReqDTO.getClientId());
                params.put("clientAuthenticators", oAuthClientAuthnContext.getExecutedAuthenticators());
                LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, params,
                        OAuthConstants.LogConstants.FAILED,
                        "The client MUST NOT use more than one authentication method per request.",
                        "issue-access-token", null);
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
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                Map<String, Object> params = new HashMap<>();
                params.put("clientId", tokenReqDTO.getClientId());
                params.put("grantType", grantType);
                LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, params,
                        OAuthConstants.LogConstants.FAILED, "Unsupported grant type.", "issue-access-token", null);
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
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                Map<String, Object> params = new HashMap<>();
                params.put("clientId", tokenReqDTO.getClientId());
                LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, params,
                        OAuthConstants.LogConstants.FAILED, "Unsupported client authentication method.",
                        "issue-access-token", null);
            }
            tokenRespDTO = handleError(
                    OAuth2ErrorCodes.INVALID_CLIENT,
                    "Unsupported Client Authentication Method!", tokenReqDTO);
            setResponseHeaders(tokReqMsgCtx, tokenRespDTO);
            triggerPostListeners(tokenReqDTO, tokenRespDTO, tokReqMsgCtx, isRefreshRequest);
            return tokenRespDTO;
        }
        if (!isAuthenticated) {
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                Map<String, Object> params = new HashMap<>();
                params.put("clientId", tokenReqDTO.getClientId());
                LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, params,
                        OAuthConstants.LogConstants.FAILED,
                        "Client authentication failed. " + oAuthClientAuthnContext.getErrorMessage(),
                        "issue-access-token", null);
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
        validateRequestTenantDomain(tenantDomainOfApp);

        tokenReqDTO.setTenantDomain(tenantDomainOfApp);

        tokReqMsgCtx.addProperty(OAUTH_APP_DO, oAuthAppDO);

        boolean isOfTypeApplicationUser = authzGrantHandler.isOfTypeApplicationUser();

        if (!isOfTypeApplicationUser) {
            tokReqMsgCtx.setAuthorizedUser(oAuthAppDO.getAppOwner());
            tokReqMsgCtx.addProperty(OAuthConstants.UserType.USER_TYPE, OAuthConstants.UserType.APPLICATION);
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
            LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, null,
                    OAuthConstants.LogConstants.FAILED, "System error occurred.", "issue-access-token", null);
            error = e.getMessage();
        }

        if (!isAuthorizedClient) {

            if (log.isDebugEnabled()) {
                log.debug("Client Id: " + tokenReqDTO.getClientId() + " is not authorized to use grant type: " +
                        grantType);
            }
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                Map<String, Object> params = new HashMap<>();
                params.put("clientId", tokenReqDTO.getClientId());
                params.put("grantType", grantType);
                LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, params,
                        OAuthConstants.LogConstants.FAILED, "Client is not authorized to use the requested grant type.",
                        "issue-access-token", null);
            }
            tokenRespDTO = handleError(OAuthError.TokenResponse.UNAUTHORIZED_CLIENT, error, tokenReqDTO);
            setResponseHeaders(tokReqMsgCtx, tokenRespDTO);
            triggerPostListeners(tokenReqDTO, tokenRespDTO, tokReqMsgCtx, isRefreshRequest);
            return tokenRespDTO;
        }
        boolean isValidGrant = false;
        error = "Provided Authorization Grant is invalid";
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

        if (tokReqMsgCtx.getAuthorizedUser() != null && tokReqMsgCtx.getAuthorizedUser().isFederatedUser()) {
            tokReqMsgCtx.getAuthorizedUser().setTenantDomain(tenantDomainOfApp);
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

        List<String> allowedScopes = OAuthServerConfiguration.getInstance().getAllowedScopes();
        List<String> requestedAllowedScopes = new ArrayList<>();
        String[] requestedScopes = tokReqMsgCtx.getScope();
        List<String> scopesToBeValidated = new ArrayList<>();
        if (requestedScopes != null) {
            for (String scope : requestedScopes) {
                if (OAuth2Util.isAllowedScope(allowedScopes, scope)) {
                    requestedAllowedScopes.add(scope);
                } else {
                    scopesToBeValidated.add(scope);
                }
            }
            tokReqMsgCtx.setScope(scopesToBeValidated.toArray(new String[0]));
        }

        String[] authorizedInternalScopes = new String[0];
        boolean isManagementApp = getServiceProvider(tokenReqDTO).isManagementApp();
        if (isManagementApp) {
            if (log.isDebugEnabled()) {
                log.debug("Handling the internal scope validation.");
            }
            // Execute Internal SCOPE Validation.
            JDBCPermissionBasedInternalScopeValidator scopeValidator = new JDBCPermissionBasedInternalScopeValidator();
            authorizedInternalScopes = scopeValidator.validateScope(tokReqMsgCtx);
            // Execute internal console scopes validation.
            if (IdentityUtil.isSystemRolesEnabled()) {
                RoleBasedInternalScopeValidator roleBasedInternalScopeValidator = new RoleBasedInternalScopeValidator();
                String[] roleBasedInternalConsoleScopes = roleBasedInternalScopeValidator.validateScope(tokReqMsgCtx);
                authorizedInternalScopes = (String[]) ArrayUtils
                        .addAll(authorizedInternalScopes, roleBasedInternalConsoleScopes);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Skipping the internal scope validation as the application is not" +
                        " configured as Management App");
            }
        }

        // Clear the internal scopes. Internal scopes should only handle in JDBCPermissionBasedInternalScopeValidator.
        // Those scopes should not send to the other scopes validators.
        // Thus remove the scopes from the tokReqMsgCtx. Will be added to the response after executing
        // the other scope validators.
        removeInternalScopes(tokReqMsgCtx);

        // Adding the authorized internal scopes to tokReqMsgCtx for any special validators to use.
        tokReqMsgCtx.setAuthorizedInternalScopes(authorizedInternalScopes);

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

        boolean isValidScope = authzGrantHandler.validateScope(tokReqMsgCtx);
        if (isValidScope) {
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                Map<String, Object> params = new HashMap<>();
                params.put("clientId", tokenReqDTO.getClientId());
                if (ArrayUtils.isNotEmpty(tokenReqDTO.getScope())) {
                    params.put("scope", Arrays.asList(tokenReqDTO.getScope()));
                }
                LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, params,
                        OAuthConstants.LogConstants.SUCCESS, "OAuth scope validation is successful.", "validate-scope",
                        null);
            }
            // Add authorized internal scopes to the request for sending in the response.
            addAuthorizedInternalScopes(tokReqMsgCtx, tokReqMsgCtx.getAuthorizedInternalScopes());
            addAllowedScopes(tokReqMsgCtx, requestedAllowedScopes.toArray(new String[0]));
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Invalid scope provided by client Id: " + tokenReqDTO.getClientId());
            }
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                Map<String, Object> params = new HashMap<>();
                params.put("clientId", tokenReqDTO.getClientId());
                if (ArrayUtils.isNotEmpty(tokenReqDTO.getScope())) {
                    params.put("scope", Arrays.asList(tokenReqDTO.getScope()));
                }
                LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, params,
                        OAuthConstants.LogConstants.FAILED, "Invalid scope provided in the request.", "validate-scope",
                        null);
            }
            tokenRespDTO = handleError(OAuthError.TokenResponse.INVALID_SCOPE, "Invalid Scope!", tokenReqDTO);
            setResponseHeaders(tokReqMsgCtx, tokenRespDTO);
            triggerPostListeners(tokenReqDTO, tokenRespDTO, tokReqMsgCtx, isRefreshRequest);
            return tokenRespDTO;
        }

        handleTokenBinding(tokenReqDTO, grantType, tokReqMsgCtx, oAuthAppDO);

        try {
            // set the token request context to be used by downstream handlers. This is introduced as a fix for
            // IDENTITY-4111.
            OAuth2Util.setTokenRequestContext(tokReqMsgCtx);

            AuthenticatedUser authorizedUser = tokReqMsgCtx.getAuthorizedUser();
            if (authorizedUser.getAuthenticatedSubjectIdentifier() == null) {
                authorizedUser.setAuthenticatedSubjectIdentifier(
                        getSubjectClaim(getServiceProvider(tokReqMsgCtx.getOauth2AccessTokenReqDTO()), authorizedUser));
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
            Map<String, Object> params = new HashMap<>();
            params.put("clientId", tokenReqDTO.getClientId());
            LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, params,
                    OAuthConstants.LogConstants.SUCCESS, "Access token issued for the application.",
                    "issue-access-token", null);
        }

        if (GrantType.AUTHORIZATION_CODE.toString().equals(grantType)) {
            // Should add user attributes to the cache before building the ID token.
            addUserAttributesAgainstAccessToken(tokenReqDTO, tokenRespDTO);
        }
        if (tokReqMsgCtx.getScope() != null && OAuth2Util.isOIDCAuthzRequest(tokReqMsgCtx.getScope())) {
            if (log.isDebugEnabled()) {
                log.debug("Issuing ID token for client: " + tokenReqDTO.getClientId());
            }
            IDTokenBuilder builder = OAuthServerConfiguration.getInstance().getOpenIDConnectIDTokenBuilder();
            try {
                String idToken = builder.buildIDToken(tokReqMsgCtx, tokenRespDTO);
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    Map<String, Object> params = new HashMap<>();
                    params.put("clientId", tokenReqDTO.getClientId());
                    LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, params,
                            OAuthConstants.LogConstants.SUCCESS, "ID token issued for the application.",
                            "issue-id-token", null);
                }
                tokenRespDTO.setIDToken(idToken);
            } catch (IDTokenValidationFailureException e) {
                log.error(e.getMessage());
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    Map<String, Object> params = new HashMap<>();
                    params.put("clientId", tokenReqDTO.getClientId());
                    LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, params,
                            OAuthConstants.LogConstants.FAILED, "System error occurred.", "issue-id-token", null);
                }
                tokenRespDTO = handleError(OAuth2ErrorCodes.SERVER_ERROR, "Server Error", tokenReqDTO);
                return tokenRespDTO;
            }
        }

        if (GrantType.AUTHORIZATION_CODE.toString().equals(grantType)) {
            // Cache entry against the authorization code has no value beyond the token request.
            clearCacheEntryAgainstAuthorizationCode(getAuthorizationCode(tokenReqDTO));
        }

        return tokenRespDTO;
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
                            + ". Defaulting to username: " + subject + " as the subject identifier.");
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
                        + authenticatedUser.getLoggableUserId(), e);
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

        return userStoreManager
                .getUserClaimValueWithID(authenticatedUser.getUserId(), subjectClaimUri, null);
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
        String[] scopesToReturn = (String[]) ArrayUtils.addAll(scopes, authorizedInternalScopes);
        tokReqMsgCtx.setScope(scopesToReturn);
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
            throw new IdentityOAuth2Exception(
                    "Token binding reference cannot be retrieved form the token binder: " + tokenBinder
                            .getBindingType());
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
            tokenRespDTO.setResponseHeaders(
                    (ResponseHeader[]) tokReqMsgCtx.getProperty(OAuthConstants.RESPONSE_HEADERS_PROPERTY));
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

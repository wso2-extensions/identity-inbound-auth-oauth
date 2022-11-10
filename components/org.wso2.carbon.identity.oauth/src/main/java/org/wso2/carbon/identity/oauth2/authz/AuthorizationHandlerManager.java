/*
 * Copyright (c) 2022, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.authz;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.dto.OAuthErrorDTO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeValidationException;
import org.wso2.carbon.identity.oauth2.authz.handlers.ResponseTypeHandler;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.JDBCPermissionBasedInternalScopeValidator;
import org.wso2.carbon.identity.oauth2.validators.RoleBasedInternalScopeValidator;
import org.wso2.carbon.utils.CarbonUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.apache.oltu.oauth2.common.error.OAuthError.CodeResponse.INVALID_SCOPE;
import static org.apache.oltu.oauth2.common.error.OAuthError.CodeResponse.UNAUTHORIZED_CLIENT;
import static org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants.CONSOLE_SCOPE_PREFIX;
import static org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants.INTERNAL_SCOPE_PREFIX;
import static org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants.SYSTEM_SCOPE;

/**
 * Authorization handler manager.
 */
public class AuthorizationHandlerManager {

    public static final String OAUTH_APP_PROPERTY = "OAuthAppDO";
    private static final Log log = LogFactory.getLog(AuthorizationHandlerManager.class);

    private static AuthorizationHandlerManager instance;

    private Map<String, ResponseTypeHandler> responseHandlers;

    private AuthorizationHandlerManager() throws IdentityOAuth2Exception {
        responseHandlers = OAuthServerConfiguration.getInstance().getSupportedResponseTypes();

        if (AppInfoCache.getInstance() != null) {
            if (log.isDebugEnabled() && AppInfoCache.getInstance().isEnabled()) {
                log.debug("Successfully enabled AppInfoCache under " + OAuthConstants.OAUTH_CACHE_MANAGER);
            }
        } else {
            log.error("Error while creating AppInfoCache");
        }
    }

    public static AuthorizationHandlerManager getInstance() throws IdentityOAuth2Exception {

        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (AuthorizationHandlerManager.class) {
                if (instance == null) {
                    instance = new AuthorizationHandlerManager();
                }
            }
        }
        return instance;
    }
    /**
     * Handle authorization request before consent page.
     *
     * @param authzReqDTO authzReqDTO
     * @return OAuthAuthzReqMessageContext
     */
    public OAuthAuthzReqMessageContext handleAuthorizationBeforeConsent(OAuth2AuthorizeReqDTO authzReqDTO)
            throws IdentityOAuth2Exception, InvalidOAuthClientException, IdentityOAuth2ScopeValidationException {

        OAuthAuthzReqMessageContext authzReqMsgCtx = getOAuthAuthzReqMessageContext(authzReqDTO);
        ResponseTypeHandler authzHandler = getResponseHandler(authzReqDTO);

        //validate requested scopes
        validateRequestedScopes(authzReqMsgCtx, authzHandler);

        return authzReqMsgCtx;
    }

    /**
     * Handle authorization request after consent page.
     *
     * @param authzReqMsgCtx authzReqMsgCtx
     * @return OAuth2AuthorizeRespDTO
     */
    public OAuth2AuthorizeRespDTO handleAuthorization(OAuthAuthzReqMessageContext authzReqMsgCtx)
            throws IdentityOAuth2Exception {

        OAuth2AuthorizeReqDTO authzReqDTO =  authzReqMsgCtx.getAuthorizationReqDTO();
        ResponseTypeHandler authzHandler = getResponseHandler(authzReqDTO);

        OAuth2AuthorizeRespDTO authorizeRespDTO = new OAuth2AuthorizeRespDTO();

        if (isInvalidAccessDelegation(authzReqDTO, authorizeRespDTO, authzReqMsgCtx, authzHandler)) {
            return authorizeRespDTO;
        }
        if (isErrorResponseFound(authorizeRespDTO)) {
            if (log.isDebugEnabled()) {
                log.debug("Error response received for authorization request by user : " + authzReqDTO.getUser() +
                        ", client : " + authzReqDTO.getConsumerKey() + ", scope : " +
                        OAuth2Util.buildScopeString(authzReqDTO.getScopes()));
            }
            return authorizeRespDTO;
        }
        try {
            // set the authorization request context to be used by downstream handlers. This is introduced as a fix for
            // IDENTITY-4111
            OAuth2Util.setAuthzRequestContext(authzReqMsgCtx);
            authorizeRespDTO = authzHandler.issue(authzReqMsgCtx);
        } finally {
            // clears authorization request context
            OAuth2Util.clearAuthzRequestContext();
        }
        return authorizeRespDTO;
    }

    private ResponseTypeHandler getResponseHandler(OAuth2AuthorizeReqDTO authzReqDTO) {
        return responseHandlers.get(authzReqDTO.getResponseType());
    }

    /**
     * validated requested scopes.
     *
     * @param authzReqMsgCtx authzReqMsgCtx
     * @param authzHandler ResponseTypeHandler
     */
    private void validateRequestedScopes(OAuthAuthzReqMessageContext authzReqMsgCtx,
                                            ResponseTypeHandler authzHandler) throws IdentityOAuth2Exception,
            IdentityOAuth2ScopeValidationException {

        // Get OIDC scopes from requested scopes
        String[] requestedOIDCScopes = getOIDCScopesFromRequestedScopes(authzReqMsgCtx);

        // Get scopes that specified in the allowed scopes list.
        List<String> requestedAllowedScopes = getAllowedScopesFromRequestedScopes(authzReqMsgCtx);

        // Validate internal scopes.
        String[] authorizedInternalScopes = new String[0];
        boolean isManagementApp = isManagementApp(authzReqMsgCtx.getAuthorizationReqDTO());
        if (isManagementApp) {
            if (log.isDebugEnabled()) {
                log.debug("Handling the internal scope validation.");
            }
            authorizedInternalScopes = getAuthorizedInternalScopes(authzReqMsgCtx);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Skipping the internal scope validation as the application is not" +
                        " configured as Management App");
            }
        }

        // Remove the internal scopes from requested scopes for further validation.
        removeInternalScopesFromRequestedScopes(authzReqMsgCtx);

        // Adding the authorized internal scopes to tokReqMsgCtx for any special validators to use.
        authzReqMsgCtx.setAuthorizedInternalScopes(authorizedInternalScopes);

        boolean isDropUnregisteredScopes = OAuthServerConfiguration.getInstance().isDropUnregisteredScopes();
        if (isDropUnregisteredScopes) {
            if (log.isDebugEnabled()) {
                log.debug("DropUnregisteredScopes config is enabled. Attempting to drop unregistered scopes.");
            }
            dropUnregisteredScopeFromRequestedScopes(authzReqMsgCtx);
        }

        //validate scopes using global scope validators
        boolean valid = validateScopes(authzReqMsgCtx, authzHandler);

        if (valid) {
            // Add authorized internal scopes to the request for sending in the response.
            addAuthorizedInternalScopes(authzReqMsgCtx, authzReqMsgCtx.getAuthorizedInternalScopes());
            // Add OIDC scopes back to the request
            addRequestedOIDCScopes(authzReqMsgCtx, requestedOIDCScopes);
            // Add scopes that filtered from the allowed scopes list.
            addAllowedScopes(authzReqMsgCtx, requestedAllowedScopes.toArray(new String[0]));
        } else {
            throw new IdentityOAuth2ScopeValidationException(INVALID_SCOPE, "Invalid Scopes");
        }
    }

    /**
     * get OIDC scopes from requested scopes.
     *
     * @param authzReqMsgCtx authzReqMsgCtx
     * @return - requestedOIDCScopes
     */
    private String[] getOIDCScopesFromRequestedScopes(OAuthAuthzReqMessageContext authzReqMsgCtx) {
        String[] requestedOIDCScopes = new String[0];
        try {
            requestedOIDCScopes = OAuth2Util.getRequestedOIDCScopes(authzReqMsgCtx.getRequestedScopes());
        } catch (IdentityOAuthAdminException e) {
            log.error("Unable to retrieve OIDC Scopes." + e.getMessage());
        }
        return requestedOIDCScopes;
    }

    /**
     * get scopes that specified in the allowed scopes list.
     *
     * @param authzReqMsgCtx authzReqMsgCtx
     * @return - requestedOIDCScopes
     */
    private List<String> getAllowedScopesFromRequestedScopes(OAuthAuthzReqMessageContext authzReqMsgCtx) {
        List<String> allowedScopes = OAuthServerConfiguration.getInstance().getAllowedScopes();
        String[] requestedScopes = authzReqMsgCtx.getRequestedScopes();
        List<String> requestedAllowedScopes = new ArrayList<>();
        if (requestedScopes != null) {
            for (String scope : requestedScopes) {
                if (OAuth2Util.isAllowedScope(allowedScopes, scope)) {
                    requestedAllowedScopes.add(scope);
                }
            }
        }
        return requestedAllowedScopes;
    }

    /**
     * get authorized internal scopes.
     *
     * @param authzReqMsgCtx authzReqMsgCtx scopes list
     * @return - authorizedInternalScopes
     */
    private String[] getAuthorizedInternalScopes(OAuthAuthzReqMessageContext authzReqMsgCtx)
            throws IdentityOAuth2Exception {
        String[] authorizedInternalScopes;
        JDBCPermissionBasedInternalScopeValidator scopeValidator = new JDBCPermissionBasedInternalScopeValidator();
        authorizedInternalScopes = scopeValidator.validateScope(authzReqMsgCtx);
        // Execute internal console scopes validation.
        if (IdentityUtil.isSystemRolesEnabled()) {
            RoleBasedInternalScopeValidator roleBasedInternalScopeValidator = new RoleBasedInternalScopeValidator();
            String[] roleBasedInternalConsoleScopes = roleBasedInternalScopeValidator.validateScope(authzReqMsgCtx);
            authorizedInternalScopes = (String[]) ArrayUtils
                    .addAll(authorizedInternalScopes, roleBasedInternalConsoleScopes);
        }
        return authorizedInternalScopes;
    }
    /**
     * remove internal scopes from requested scopes.
     *
     * @param authzReqMsgCtx authzReqMsgCtx scopes list
     */
    private void removeInternalScopesFromRequestedScopes(OAuthAuthzReqMessageContext authzReqMsgCtx) {

        if (authzReqMsgCtx.getAuthorizationReqDTO().getScopes() == null) {
            return;
        }
        List<String> scopes = new ArrayList<>();
        for (String scope : authzReqMsgCtx.getRequestedScopes()) {
            if (!scope.startsWith(INTERNAL_SCOPE_PREFIX) && !scope.startsWith(CONSOLE_SCOPE_PREFIX) && !scope
                    .equalsIgnoreCase(SYSTEM_SCOPE)) {
                scopes.add(scope);
            }
        }
        authzReqMsgCtx.setRequestedScopes(scopes.toArray(new String[0]));
    }

    /**
     * drop unregistered from requested scopes.
     *
     * @param authzReqMsgCtx authzReqMsgCtx scopes list
     */
    private void dropUnregisteredScopeFromRequestedScopes(OAuthAuthzReqMessageContext authzReqMsgCtx)
            throws IdentityOAuth2Exception {
        String[] filteredScopes = OAuth2Util.dropUnregisteredScopes(
                authzReqMsgCtx.getRequestedScopes(),
                authzReqMsgCtx.getAuthorizationReqDTO().getTenantDomain());
        authzReqMsgCtx.setRequestedScopes(filteredScopes);
    }

    private boolean isManagementApp(OAuth2AuthorizeReqDTO authzReqDTO) throws IdentityOAuth2Exception {

        try {
            ServiceProvider application = OAuth2ServiceComponentHolder.getApplicationMgtService()
                    .getServiceProviderByClientId(authzReqDTO.getConsumerKey(), OAuthConstants.Scope.OAUTH2,
                            authzReqDTO.getTenantDomain());
            return application.isManagementApp();
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityOAuth2Exception("Error occurred while retrieving OAuth2 application data for " +
                    "client id " + authzReqDTO.getConsumerKey(), e);
        }
    }

    private void addAuthorizedInternalScopes(OAuthAuthzReqMessageContext authzReqMsgCtx,
                                             String[] authorizedInternalScopes) {

        String[] scopes = authzReqMsgCtx.getApprovedScope();
        String[] scopesToReturn = (String[]) ArrayUtils.addAll(scopes, authorizedInternalScopes);
        authzReqMsgCtx.setApprovedScope(scopesToReturn);
    }

    private void addRequestedOIDCScopes(OAuthAuthzReqMessageContext authzReqMsgCtx,
                                             String[] requestedOIDCScopes) {
        Set<String> scopesToReturn = new HashSet<>(Arrays.asList(authzReqMsgCtx.getApprovedScope()));
        for (String scope : requestedOIDCScopes) {
            scopesToReturn.add(scope);
        }
        String[] scopes = scopesToReturn.toArray(new String[scopesToReturn.size()]);
        authzReqMsgCtx.setApprovedScope(scopes);
    }

    private void addAllowedScopes(OAuthAuthzReqMessageContext authzReqMsgCtx, String[] allowedScopes) {

        String[] scopes = authzReqMsgCtx.getApprovedScope();
        String[] scopesToReturn = (String[]) ArrayUtils.addAll(scopes, allowedScopes);
        authzReqMsgCtx.setApprovedScope(scopesToReturn);
    }

    private void removeInternalScopes(OAuthAuthzReqMessageContext authzReqMsgCtx) {

        if (authzReqMsgCtx.getAuthorizationReqDTO().getScopes() == null) {
            return;
        }
        List<String> scopes = new ArrayList<>();
        for (String scope : authzReqMsgCtx.getAuthorizationReqDTO().getScopes()) {
            if (!scope.startsWith(INTERNAL_SCOPE_PREFIX) && !scope.startsWith(CONSOLE_SCOPE_PREFIX) && !scope
                    .equalsIgnoreCase(SYSTEM_SCOPE)) {
                scopes.add(scope);
            }
        }
        authzReqMsgCtx.getAuthorizationReqDTO().setScopes(scopes.toArray(new String[0]));
    }
    /**
     * validate scope using global scope validators.
     *
     * @param authzReqMsgCtx authzReqMsgCtx
     * @param authzHandler responseTypeHandler
     * @return boolean scopes are validated or no
     */
    private boolean validateScopes(OAuthAuthzReqMessageContext authzReqMsgCtx, ResponseTypeHandler authzHandler)
            throws IdentityOAuth2Exception {
        boolean scopeValidationStatus = authzHandler.validateScope(authzReqMsgCtx);
        if (!scopeValidationStatus) {
            return false;
        }
        if (log.isDebugEnabled()) {
            log.debug("Approved scope(s) : " + OAuth2Util.buildScopeString(authzReqMsgCtx.getApprovedScope()));
        }
        return true;
    }

    private boolean approvedScopeNotSetByTheCallbackHandler(OAuthAuthzReqMessageContext authzReqMsgCtx) {
        return authzReqMsgCtx.getApprovedScope() == null || authzReqMsgCtx.getApprovedScope().length == 0;
    }

    private boolean isInvalidAccessDelegation(OAuth2AuthorizeReqDTO authzReqDTO,
                                              OAuth2AuthorizeRespDTO authorizeRespDTO,
                                              OAuthAuthzReqMessageContext authzReqMsgCtx,
                                              ResponseTypeHandler authzHandler) throws IdentityOAuth2Exception {

        boolean accessDelegationAuthzStatus = authzHandler.validateAccessDelegation(authzReqMsgCtx);
        if (!accessDelegationAuthzStatus) {
            handleErrorRequest(authorizeRespDTO, UNAUTHORIZED_CLIENT, "Authorization Failure!");
            authorizeRespDTO.setCallbackURI(authzReqDTO.getCallbackUrl());
            if (log.isDebugEnabled()) {
                log.debug("User : " + authzReqDTO.getUser() +
                        " doesn't have necessary rights to grant access to the resource(s) : " +
                        OAuth2Util.buildScopeString(authzReqDTO.getScopes()));
            }
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                Map<String, Object> params = new HashMap<>();
                params.put("clientId", authzReqDTO.getConsumerKey());
                if (authzReqDTO.getUser() != null) {
                    try {
                        params.put("user", authzReqDTO.getUser().getUserId());
                    } catch (UserIdNotFoundException e) {
                        if (StringUtils.isNotBlank(authzReqDTO.getUser().getAuthenticatedSubjectIdentifier())) {
                            params.put("user", authzReqDTO.getUser().getAuthenticatedSubjectIdentifier().replaceAll(".",
                                    "*"));
                        }
                    }
                }
                params.put("requestedScopes", OAuth2Util.buildScopeString(authzReqDTO.getScopes()));
                LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, params,
                        OAuthConstants.LogConstants.FAILED,
                        "User doesn't have necessary rights to grant access to the requested resource(s).",
                        "validate-authz-request", null);
            }
            return true;
        }
        return false;
    }

    private boolean isInvalidClient(OAuth2AuthorizeReqDTO authzReqDTO,
                                    OAuthAuthzReqMessageContext authzReqMsgCtx, ResponseTypeHandler authzHandler)
            throws IdentityOAuth2Exception {
        boolean isAuthorizedClient = authzHandler.isAuthorizedClient(authzReqMsgCtx);
        if (!isAuthorizedClient) {
            if (log.isDebugEnabled()) {
                log.debug("Client validation failed for user : " + authzReqDTO.getUser() +
                        ", for client : " + authzReqDTO.getConsumerKey());
            }
            return true;
        }
        return false;
    }

    private OAuthAuthzReqMessageContext getOAuthAuthzReqMessageContext(OAuth2AuthorizeReqDTO authzReqDTO)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {
        OAuthAuthzReqMessageContext authorizeRequestMessageContext = new OAuthAuthzReqMessageContext(authzReqDTO);
        // loading the stored application data
        OAuthAppDO oAuthAppDO = getAppInformation(authzReqDTO);
        authorizeRequestMessageContext.addProperty(OAUTH_APP_PROPERTY, oAuthAppDO);

        // load the SP tenant domain from the OAuth App info
        authorizeRequestMessageContext.getAuthorizationReqDTO()
                .setTenantDomain(OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO));

        // load requested scopes
        authorizeRequestMessageContext.setRequestedScopes(authzReqDTO.getScopes());

        return authorizeRequestMessageContext;
    }

    private boolean isErrorResponseFound(OAuth2AuthorizeRespDTO authorizeRespDTO) {
        return authorizeRespDTO.getErrorMsg() != null;
    }

    private boolean isInvalidResponseType(OAuth2AuthorizeReqDTO authzReqDTO) {
        if (!responseHandlers.containsKey(authzReqDTO.getResponseType())) {
            if (log.isDebugEnabled()) {
                log.debug("Unsupported Response Type : " + authzReqDTO.getResponseType() +
                        " provided for user : " + authzReqDTO.getUser() +
                        ", for client :" + authzReqDTO.getConsumerKey());
            }
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                Map<String, Object> params = new HashMap<>();
                params.put("clientId", authzReqDTO.getConsumerKey());
                params.put("response_type", authzReqDTO.getResponseType());

                LoggerUtils.triggerDiagnosticLogEvent(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE, params,
                        OAuthConstants.LogConstants.FAILED, "Un-supported response type.", "validate-authz-request",
                        null);
            }
            return true;
        }
        return false;
    }

    private OAuthAppDO getAppInformation(OAuth2AuthorizeReqDTO authzReqDTO) throws IdentityOAuth2Exception,
            InvalidOAuthClientException {
        OAuthAppDO oAuthAppDO = AppInfoCache.getInstance().getValueFromCache(authzReqDTO.getConsumerKey());
        if (oAuthAppDO != null) {
            return oAuthAppDO;
        } else {
            oAuthAppDO = new OAuthAppDAO().getAppInformation(authzReqDTO.getConsumerKey());
            AppInfoCache.getInstance().addToCache(authzReqDTO.getConsumerKey(), oAuthAppDO);
            return oAuthAppDO;
        }
    }

    private void handleErrorRequest(OAuth2AuthorizeRespDTO respDTO, String errorCode,
                                    String errorMsg) {
        respDTO.setErrorCode(errorCode);
        respDTO.setErrorMsg(errorMsg);
    }

    /**
     * Handles the authorization request denied by user.
     *
     * @param oAuth2Parameters OAuth parameters.
     * @return OAuthErrorDTO Error Data Transfer Object.
     */
    public OAuthErrorDTO handleUserConsentDenial(OAuth2Parameters oAuth2Parameters) {

        ResponseTypeHandler responseTypeHandler = responseHandlers.get(oAuth2Parameters.getResponseType());
        return responseTypeHandler.handleUserConsentDenial(oAuth2Parameters);
    }

    /**
     * Handles the authentication failures.
     *
     * @param oAuth2Parameters OAuth parameters.
     * @return OAuth2AuthorizeRespDTO Error Data Transfer Object.
     */
    public OAuthErrorDTO handleAuthenticationFailure(OAuth2Parameters oAuth2Parameters) {

        ResponseTypeHandler responseTypeHandler = responseHandlers.get(oAuth2Parameters.getResponseType());
        return responseTypeHandler.handleAuthenticationFailure(oAuth2Parameters);
    }
}

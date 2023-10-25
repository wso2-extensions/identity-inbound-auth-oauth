/*
 * Copyright (c) 2013, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.authz;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
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
import org.wso2.carbon.identity.oauth2.IdentityOAuth2UnauthorizedScopeException;
import org.wso2.carbon.identity.oauth2.authz.handlers.ResponseTypeHandler;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.AuthzUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.DefaultOAuth2ScopeValidator;
import org.wso2.carbon.identity.oauth2.validators.JDBCPermissionBasedInternalScopeValidator;
import org.wso2.carbon.identity.oauth2.validators.RoleBasedInternalScopeValidator;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.apache.oltu.oauth2.common.error.OAuthError.CodeResponse.INVALID_SCOPE;
import static org.apache.oltu.oauth2.common.error.OAuthError.CodeResponse.UNAUTHORIZED_CLIENT;
import static org.apache.oltu.oauth2.common.error.OAuthError.CodeResponse.UNSUPPORTED_RESPONSE_TYPE;
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

    @Deprecated
    /**
     * @deprecated Avoid using this, use {@link #handleAuthorization(OAuthAuthzReqMessageContext)
     * handleAuthorization}
     * method instead.
     */
    public OAuth2AuthorizeRespDTO handleAuthorization(OAuth2AuthorizeReqDTO authzReqDTO)
            throws IdentityOAuth2Exception, IdentityOAuthAdminException, InvalidOAuthClientException {

        OAuthAuthzReqMessageContext authzReqMsgCtx = getOAuthAuthzReqMessageContext(authzReqDTO);
        ResponseTypeHandler authzHandler = getResponseHandler(authzReqDTO);
        OAuth2AuthorizeRespDTO authorizeRespDTO = validateAuthzRequest(authzReqDTO, authzReqMsgCtx, authzHandler);
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

    private OAuth2AuthorizeRespDTO validateAuthzRequest(OAuth2AuthorizeReqDTO authzReqDTO,
                                                        OAuthAuthzReqMessageContext authzReqMsgCtx,
                                                        ResponseTypeHandler authzHandler)
            throws IdentityOAuth2Exception {
        OAuth2AuthorizeRespDTO authorizeRespDTO = new OAuth2AuthorizeRespDTO();
        if (isInvalidResponseType(authzReqDTO, authorizeRespDTO)) {
            return authorizeRespDTO;
        }
        if (isInvalidClient(authzReqDTO, authorizeRespDTO, authzReqMsgCtx, authzHandler)) {
            return authorizeRespDTO;
        }
        if (isInvalidAccessDelegation(authzReqDTO, authorizeRespDTO, authzReqMsgCtx, authzHandler)) {
            return authorizeRespDTO;
        }

        List<String> allowedScopes = OAuthServerConfiguration.getInstance().getAllowedScopes();
        List<String> requestedAllowedScopes = new ArrayList<>();
        String[] requestedScopes = authzReqMsgCtx.getAuthorizationReqDTO().getScopes();
        List<String> scopesToBeValidated = new ArrayList<>();
        if (requestedScopes != null) {
            for (String scope : requestedScopes) {
                if (OAuth2Util.isAllowedScope(allowedScopes, scope)) {
                    requestedAllowedScopes.add(scope);
                } else {
                    scopesToBeValidated.add(scope);
                }
            }
            authzReqMsgCtx.getAuthorizationReqDTO().setScopes(scopesToBeValidated.toArray(
                    new String[0]));
        }

        // Execute Internal SCOPE Validation.
        String[] authorizedInternalScopes = new String[0];
        log.debug("Handling the internal scope validation.");
        JDBCPermissionBasedInternalScopeValidator scopeValidator = new JDBCPermissionBasedInternalScopeValidator();
        authorizedInternalScopes = scopeValidator.validateScope(authzReqMsgCtx);
        // Execute internal console scopes validation.
        if (IdentityUtil.isSystemRolesEnabled()) {
            RoleBasedInternalScopeValidator roleBasedInternalScopeValidator = new RoleBasedInternalScopeValidator();
            String[] roleBasedInternalConsoleScopes = roleBasedInternalScopeValidator.validateScope(authzReqMsgCtx);
            authorizedInternalScopes = (String[]) ArrayUtils
                    .addAll(authorizedInternalScopes, roleBasedInternalConsoleScopes);
        }

        // Clear the internal scopes. Internal scopes should only handle in JDBCPermissionBasedInternalScopeValidator.
        // Those scopes should not send to the other scopes validators.
        // Thus remove the scopes from the authzReqMsgCtx. Will be added to the response after executing
        // the other scope validators.
        removeInternalScopes(authzReqMsgCtx);

        // Adding the authorized internal scopes to tokReqMsgCtx for any special validators to use.
        authzReqMsgCtx.setAuthorizedInternalScopes(authorizedInternalScopes);

        boolean isDropUnregisteredScopes = OAuthServerConfiguration.getInstance().isDropUnregisteredScopes();
        if (isDropUnregisteredScopes) {
            if (log.isDebugEnabled()) {
                log.debug("DropUnregisteredScopes config is enabled. Attempting to drop unregistered scopes.");
            }
            String[] filteredScopes = OAuth2Util.dropUnregisteredScopes(
                    authzReqMsgCtx.getAuthorizationReqDTO().getScopes(),
                    authzReqMsgCtx.getAuthorizationReqDTO().getTenantDomain());
            authzReqMsgCtx.getAuthorizationReqDTO().setScopes(filteredScopes);
        }

        boolean valid = validateScope(authzReqDTO, authorizeRespDTO, authzReqMsgCtx, authzHandler);
        if (valid) {
            // Add authorized internal scopes to the request for sending in the response.
            addAuthorizedInternalScopes(authzReqMsgCtx, authzReqMsgCtx.getAuthorizedInternalScopes());
            addAllowedScopes(authzReqMsgCtx, requestedAllowedScopes.toArray(new String[0]));
        }
        return authorizeRespDTO;
    }

    /**
     * Handle authorization request (validate requested scopes) before the consent page.
     *
     * @param authzReqDTO OAuth2AuthorizeReqDTO
     * @return OAuthAuthzReqMessageContext
     */
    public OAuthAuthzReqMessageContext validateScopesBeforeConsent(OAuth2AuthorizeReqDTO authzReqDTO)
            throws IdentityOAuth2Exception, InvalidOAuthClientException, IdentityOAuth2UnauthorizedScopeException {

        OAuthAuthzReqMessageContext authzReqMsgCtx = getOAuthAuthzReqMessageContext(authzReqDTO);
        ResponseTypeHandler authzHandler = getResponseHandler(authzReqDTO);
        validateRequestedScopes(authzReqMsgCtx, authzHandler);
        return authzReqMsgCtx;
    }

    /**
     * Handle authorization request after the consent page.
     *
     * @param authzReqMsgCtx OAuthAuthzReqMessageContext
     * @return OAuth2AuthorizeRespDTO
     */
    public OAuth2AuthorizeRespDTO handleAuthorization(OAuthAuthzReqMessageContext authzReqMsgCtx)
            throws IdentityOAuth2Exception {

        OAuth2AuthorizeReqDTO authzReqDTO =  authzReqMsgCtx.getAuthorizationReqDTO();
        ResponseTypeHandler authzHandler = getResponseHandler(authzReqDTO);

        OAuth2AuthorizeRespDTO authorizeRespDTO = new OAuth2AuthorizeRespDTO();
        if (isInvalidClient(authzReqDTO, authorizeRespDTO, authzReqMsgCtx, authzHandler)) {
            return authorizeRespDTO;
        }
        if (isInvalidAccessDelegation(authzReqDTO, authorizeRespDTO, authzReqMsgCtx, authzHandler)) {
            return authorizeRespDTO;
        }
        if (isErrorResponseFound(authorizeRespDTO)) {
            if (log.isDebugEnabled()) {
                log.debug("Error response received for authorization request by user : " + authzReqDTO.getUser() +
                        ", client : " + authzReqDTO.getConsumerKey() + ", scopes: " +
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


    /**
     * validated requested scopes.
     *
     * @param authzReqMsgCtx OAuthAuthzReqMessageContext
     * @param authzHandler   ResponseTypeHandler
     */
    private void validateRequestedScopes(OAuthAuthzReqMessageContext authzReqMsgCtx,
                                         ResponseTypeHandler authzHandler) throws IdentityOAuth2Exception,
            IdentityOAuth2UnauthorizedScopeException {

        // Get allowed scopes that are specified in the server level.
        List<String> requestedAllowedScopes = getAllowedScopesFromRequestedScopes(authzReqMsgCtx);
        // Remove the system level allowed scopes from requested scopes for further validation.
        removeAllowedScopesFromRequestedScopes(authzReqMsgCtx, requestedAllowedScopes);
        List<String> authorizedScopes = null;
        // Switch the scope validators dynamically based on the authorization runtime.
        if (AuthzUtil.isLegacyAuthzRuntime()) {
            // If it is management app, we validate internal scopes in the requested scopes.
            String[] authorizedInternalScopes = new String[0];
            log.debug("Handling the internal scope validation.");
            authorizedInternalScopes = getAuthorizedInternalScopes(authzReqMsgCtx);

            // Remove the internal scopes from requested scopes for further validation.
            removeInternalScopesFromRequestedScopes(authzReqMsgCtx);
            // Adding the authorized internal scopes to tokReqMsgCtx for any special validators to use.
            authzReqMsgCtx.setAuthorizedInternalScopes(authorizedInternalScopes);
        } else {
            // Engage new scope validator
            authorizedScopes = getAuthorizedScopes(authzReqMsgCtx);
            removeAuthorizedScopesFromRequestedScopes(authzReqMsgCtx, authorizedScopes);
        }
        boolean isDropUnregisteredScopes = OAuthServerConfiguration.getInstance().isDropUnregisteredScopes();
        if (isDropUnregisteredScopes) {
            if (log.isDebugEnabled()) {
                log.debug("DropUnregisteredScopes config is enabled. Attempting to drop unregistered scopes.");
            }
            dropUnregisteredScopeFromRequestedScopes(authzReqMsgCtx);
        }
        //Validate scopes using global scope validators.
        boolean isValid = validateScopes(authzReqMsgCtx, authzHandler);
        boolean isValidatedScopesContainsInRequestedScopes = isValidatedScopesContainsInRequestedScopes(authzReqMsgCtx);
        if (isValid && isValidatedScopesContainsInRequestedScopes) {
            if (AuthzUtil.isLegacyAuthzRuntime()) {
                // Add authorized internal scopes to the request for sending in the response.
                addAuthorizedInternalScopes(authzReqMsgCtx, authzReqMsgCtx.getAuthorizedInternalScopes());
            } else {
                addAuthorizedScopes(authzReqMsgCtx, authorizedScopes);
            }
            // Add scopes that filtered from the allowed scopes list.
            addAllowedScopes(authzReqMsgCtx, requestedAllowedScopes.toArray(new String[0]));
        } else {
            throw new IdentityOAuth2UnauthorizedScopeException(INVALID_SCOPE, "Scope validation failed.");
        }
    }

    private boolean isValidatedScopesContainsInRequestedScopes(OAuthAuthzReqMessageContext authzReqMsgCtx) {

        if (ArrayUtils.isEmpty(authzReqMsgCtx.getApprovedScope())) {
            return true;
        }

        Set<String> validatedScopesSet = new HashSet<>(Arrays.asList(authzReqMsgCtx.getApprovedScope()));
        Set<String> requestedScopesSet = new HashSet<>(Arrays.asList(authzReqMsgCtx.getRequestedScopes()));
        return requestedScopesSet.containsAll(validatedScopesSet);
    }

    /**
     * Get scopes that specified in the allowed scopes list.
     *
     * @param authzReqMsgCtx authzReqMsgCtx
     * @return - allowed scopes list
     */
    private List<String> getAllowedScopesFromRequestedScopes(OAuthAuthzReqMessageContext authzReqMsgCtx) {

        List<String> allowedScopes = OAuthServerConfiguration.getInstance().getAllowedScopes();
        String[] requestedScopes = authzReqMsgCtx.getAuthorizationReqDTO().getScopes();
        List<String> requestedAllowedScopes = new ArrayList<>();
        if (!ArrayUtils.isEmpty(requestedScopes)) {
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
     * @param authzReqMsgCtx authzReqMsgCtx
     * @return - authorizedInternalScopes scopes list
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
     * get authorized scopes.
     *
     * @param authzReqMsgCtx authzReqMsgCtx
     * @return - authorizedInternalScopes scopes list
     */
    private List<String> getAuthorizedScopes(OAuthAuthzReqMessageContext authzReqMsgCtx)
            throws IdentityOAuth2Exception {

        DefaultOAuth2ScopeValidator scopeValidator = new DefaultOAuth2ScopeValidator();
        return scopeValidator.validateScope(authzReqMsgCtx);
    }

    /**
     * Eemove internal scopes from requested scopes.
     *
     * @param authzReqMsgCtx authzReqMsgCtx
     */
    private void removeInternalScopesFromRequestedScopes(OAuthAuthzReqMessageContext authzReqMsgCtx) {

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
     * Remove authorized scopes from requested scopes.
     *
     * @param authzReqMsgCtx authzReqMsgCtx
     * @param authorizedScopes Authorized Scopes
     */
    private void removeAuthorizedScopesFromRequestedScopes(OAuthAuthzReqMessageContext authzReqMsgCtx,
                                                           List<String> authorizedScopes) {

        if (authzReqMsgCtx.getAuthorizationReqDTO().getScopes() == null) {
            return;
        }
        List<String> scopes = new ArrayList<>();
        for (String scope : authzReqMsgCtx.getAuthorizationReqDTO().getScopes()) {
            if (!authorizedScopes.contains(scope) && !scope.equalsIgnoreCase(SYSTEM_SCOPE)) {
                scopes.add(scope);
            }
        }
        authzReqMsgCtx.getAuthorizationReqDTO().setScopes(scopes.toArray(new String[0]));
    }

    /**
     * Remove the system level allowed scopes from requested scopes.
     *
     * @param authzReqMsgCtx         authzReqMsgCtx
     * @param requestedAllowedScopes Requested allowed scopes
     */
    private void removeAllowedScopesFromRequestedScopes(OAuthAuthzReqMessageContext authzReqMsgCtx, List<String>
            requestedAllowedScopes) {
        if (authzReqMsgCtx.getAuthorizationReqDTO().getScopes() == null) {
            return;
        }
        List<String> scopes = new ArrayList<>();
        for (String scope : authzReqMsgCtx.getAuthorizationReqDTO().getScopes()) {
            if (!requestedAllowedScopes.contains(scope)) {
                scopes.add(scope);
            }
        }
        authzReqMsgCtx.getAuthorizationReqDTO().setScopes(scopes.toArray(new String[0]));
    }

    /**
     * Drop unregistered from requested scopes.
     *
     * @param authzReqMsgCtx authzReqMsgCtx
     */
    private void dropUnregisteredScopeFromRequestedScopes(OAuthAuthzReqMessageContext authzReqMsgCtx)
            throws IdentityOAuth2Exception {
        String[] filteredScopes = OAuth2Util.dropUnregisteredScopes(authzReqMsgCtx.getAuthorizationReqDTO().getScopes(),
                authzReqMsgCtx.getAuthorizationReqDTO().getTenantDomain());
        authzReqMsgCtx.getAuthorizationReqDTO().setScopes(filteredScopes);
    }

    private void addAuthorizedInternalScopes(OAuthAuthzReqMessageContext authzReqMsgCtx,
                                             String[] authorizedInternalScopes) {

        String[] scopes = authzReqMsgCtx.getApprovedScope();
        String[] scopesToReturn = (String[]) ArrayUtils.addAll(scopes, authorizedInternalScopes);
        authzReqMsgCtx.setApprovedScope(scopesToReturn);
    }

    private void addAuthorizedScopes(OAuthAuthzReqMessageContext authzReqMsgCtx, List<String> authorizedScopes) {

        String[] scopes = authzReqMsgCtx.getApprovedScope();
        String[] scopesToReturn = (String[]) ArrayUtils.addAll(scopes, authorizedScopes.toArray());
        authzReqMsgCtx.setApprovedScope(scopesToReturn);
    }


    private void addRequestedOIDCScopes(OAuthAuthzReqMessageContext authzReqMsgCtx,
                                        String[] requestedOIDCScopes) {
        Set<String> scopesToReturn = new HashSet<>(Arrays.asList(authzReqMsgCtx.getApprovedScope()));
        scopesToReturn.addAll(Arrays.asList(requestedOIDCScopes));
        String[] scopes = scopesToReturn.toArray(new String[0]);
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

    private boolean validateScope(OAuth2AuthorizeReqDTO authzReqDTO, OAuth2AuthorizeRespDTO authorizeRespDTO,
                                  OAuthAuthzReqMessageContext authzReqMsgCtx, ResponseTypeHandler authzHandler)
            throws IdentityOAuth2Exception {
        boolean scopeValidationStatus = authzHandler.validateScope(authzReqMsgCtx);
        if (!scopeValidationStatus) {
            handleErrorRequest(authorizeRespDTO, INVALID_SCOPE, "Invalid Scope!");
            authorizeRespDTO.setCallbackURI(authzReqDTO.getCallbackUrl());
            if (log.isDebugEnabled()) {
                log.debug("Scope validation failed for user : " + authzReqDTO.getUser() + ", for the scope(s) : "
                        + OAuth2Util.buildScopeString(authzReqDTO.getScopes()));
            }
            return false;
        } else if (approvedScopeNotSetByTheCallbackHandler(authzReqMsgCtx)) {
            // We are here because the call-back handler has approved the scope.
            // If call-back handler set the approved scope - then we respect that. If not we take
            // the approved scope as the provided scope.
            authzReqMsgCtx.setApprovedScope(authzReqMsgCtx.getAuthorizationReqDTO().getScopes());
        }
        if (log.isDebugEnabled()) {
            log.debug("Approved scope(s) : " + OAuth2Util.buildScopeString(authzReqMsgCtx.getApprovedScope()));
        }
        return true;
    }

    /**
     * Engage global scope validators.
     *
     * @param authzReqMsgCtx OAuthAuthzReqMessageContext
     * @param authzHandler   ResponseTypeHandler
     * @return scopes are validated or not
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
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.VALIDATE_AUTHZ_REQUEST);
                diagnosticLogBuilder.inputParam(LogConstants.InputKeys.CLIENT_ID, authzReqDTO.getConsumerKey());
                if (authzReqDTO.getUser() != null) {
                    try {
                        diagnosticLogBuilder.inputParam(LogConstants.InputKeys.USER_ID,
                                authzReqDTO.getUser().getUserId());
                    } catch (UserIdNotFoundException e) {
                        if (StringUtils.isNotBlank(authzReqDTO.getUser().getAuthenticatedSubjectIdentifier())) {
                            diagnosticLogBuilder.inputParam(LogConstants.InputKeys.USER,
                                    LoggerUtils.isLogMaskingEnable ? LoggerUtils.getMaskedContent(
                                    authzReqDTO.getUser().getAuthenticatedSubjectIdentifier()) : authzReqDTO.getUser()
                                    .getAuthenticatedSubjectIdentifier());
                        }
                    }
                }
                diagnosticLogBuilder.inputParam(OAuthConstants.LogConstants.InputKeys.REQUESTED_SCOPES,
                        OAuth2Util.buildScopeString(authzReqDTO.getScopes()))
                        .resultMessage("User doesn't have necessary rights to grant access to the requested " +
                                "resource(s).")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            return true;
        }
        return false;
    }

    private boolean isInvalidClient(OAuth2AuthorizeReqDTO authzReqDTO, OAuth2AuthorizeRespDTO authorizeRespDTO,
                                    OAuthAuthzReqMessageContext authzReqMsgCtx, ResponseTypeHandler authzHandler)
            throws IdentityOAuth2Exception {
        boolean isAuthorizedClient = authzHandler.isAuthorizedClient(authzReqMsgCtx);
        if (!isAuthorizedClient) {
            handleErrorRequest(authorizeRespDTO, UNAUTHORIZED_CLIENT,
                    "The authenticated client is not authorized to use this authorization grant type");
            authorizeRespDTO.setCallbackURI(authzReqDTO.getCallbackUrl());
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

    private boolean isInvalidResponseType(OAuth2AuthorizeReqDTO authzReqDTO, OAuth2AuthorizeRespDTO authorizeRespDTO) {
        if (!responseHandlers.containsKey(authzReqDTO.getResponseType())) {
            handleErrorRequest(authorizeRespDTO, UNSUPPORTED_RESPONSE_TYPE,
                    "Unsupported Response Type!");
            authorizeRespDTO.setCallbackURI(authzReqDTO.getCallbackUrl());
            if (log.isDebugEnabled()) {
                log.debug("Unsupported Response Type : " + authzReqDTO.getResponseType() +
                        " provided for user : " + authzReqDTO.getUser() +
                        ", for client :" + authzReqDTO.getConsumerKey());
            }
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                        OAuthConstants.LogConstants.ActionIDs.VALIDATE_AUTHZ_REQUEST)
                        .inputParam(LogConstants.InputKeys.CLIENT_ID, authzReqDTO.getConsumerKey())
                        .inputParam("response type", authzReqDTO.getResponseType())
                        .resultMessage("Un-supported response type.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED));
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
            String tenantDomain = authzReqDTO.getTenantDomain();
            if (StringUtils.isNotEmpty(tenantDomain)) {
                oAuthAppDO = new OAuthAppDAO().getAppInformation(
                        authzReqDTO.getConsumerKey(), IdentityTenantUtil.getTenantId(tenantDomain));
            } else {
                oAuthAppDO = new OAuthAppDAO().getAppInformation(authzReqDTO.getConsumerKey());
            }
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

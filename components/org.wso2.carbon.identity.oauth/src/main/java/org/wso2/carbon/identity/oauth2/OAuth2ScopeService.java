/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.oauth2;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.BooleanUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.cache.OAuthScopeCache;
import org.wso2.carbon.identity.oauth.cache.OAuthScopeCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.model.OAuth2ScopeConsentResponse;
import org.wso2.carbon.identity.oauth2.model.UserApplicationScopeConsentDO;
import org.wso2.carbon.identity.oauth2.scopeservice.OAuth2Resource;
import org.wso2.carbon.identity.oauth2.scopeservice.ScopeMetadata;
import org.wso2.carbon.identity.oauth2.scopeservice.ScopeMetadataService;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.util.Oauth2ScopeUtils;
import org.wso2.carbon.identity.openidconnect.cache.OIDCScopeClaimCache;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants.ErrorMessages.ERROR_CODE_BAD_REQUEST_SCOPE_NAME_NOT_SATIFIED_THE_REGEX;

/**
 * OAuth2ScopeService use for scope handling
 */
public class OAuth2ScopeService implements ScopeMetadataService {

    private static final Log log = LogFactory.getLog(OAuth2ScopeService.class);
    private static final String SCOPE_VALIDATION_REGEX = "^[^?#/()]*$";

    private static final String OAuth2ScopeResourceName = "OAuth 2.0 Scopes";

    /**
     * Register a scope with the bindings
     *
     * @param scope details of the scope to be registered
     * @throws IdentityOAuth2ScopeServerException
     */
    public Scope registerScope(Scope scope) throws IdentityOAuth2ScopeException {

        addScopePreValidation(scope);

        // Check whether a scope exists with the provided scope name or not regardless of scope type. We don't allow
        // to register same scope name across OAuth2 and OIDC scope endpoints. We keep the scope name as unique.
        boolean isScopeExists = isScopeExists(scope.getName(), true);
        if (isScopeExists) {
            // Rechecking to see if the existing scope is an OIDC scope to improve error response.
            if (isScopeExists(scope.getName(), false)) {
                throw Oauth2ScopeUtils.generateClientException(Oauth2ScopeConstants.ErrorMessages.
                        ERROR_CODE_CONFLICT_REQUEST_EXISTING_SCOPE, scope.getName());
            } else {
                throw Oauth2ScopeUtils.generateClientException(Oauth2ScopeConstants.ErrorMessages.
                        ERROR_CODE_CONFLICT_REQUEST_EXISTING_SCOPE_OIDC, scope.getName());
            }
        }

        int tenantID = Oauth2ScopeUtils.getTenantID();
        try {
            OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO().addScope(scope, tenantID);
            if (log.isDebugEnabled()) {
                log.debug("Scope is added to the database. \n" + scope.toString());
            }
        } catch (IdentityOAuth2ScopeServerException e) {
            throw Oauth2ScopeUtils.generateServerException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_FAILED_TO_REGISTER_SCOPE, scope.toString(), e);
        }

        OAuthScopeCache.getInstance().addToCache(new OAuthScopeCacheKey(scope.getName()), scope, tenantID);
        return scope;
    }

    /**
     * Retrieve the available scope list
     *
     * @param startIndex Start Index of the result set to enforce pagination
     * @param count      Number of elements in the result set to enforce pagination
     * @return Scope list
     * @throws IdentityOAuth2ScopeServerException
     * @deprecated use {@link #getScopes(Integer, Integer, Boolean, String)} instead.
     */
    public Set<Scope> getScopes(Integer startIndex, Integer count)
            throws IdentityOAuth2ScopeServerException {

        return getScopes(startIndex, count, false, null);
    }

    /**
     * Retrieve the available scope list.
     *
     * @param startIndex        Start Index of the result set to enforce pagination.
     * @param count             Number of elements in the result set to enforce pagination.
     * @param includeOIDCScopes Include OIDC scopes as well.
     * @param requestedScopes   Requested set of scopes to be return in the response.
     * @return Scope list.
     * @throws IdentityOAuth2ScopeServerException
     */
    public Set<Scope> getScopes(Integer startIndex, Integer count, Boolean includeOIDCScopes, String requestedScopes)
            throws IdentityOAuth2ScopeServerException {

        int tenantId = Oauth2ScopeUtils.getTenantID();
        return getTenantScopes(startIndex, count, includeOIDCScopes, requestedScopes, tenantId);
    }

    /**
     * Retrieve the available scope list.
     *
     * @param startIndex        Start Index of the result set to enforce pagination.
     * @param count             Number of elements in the result set to enforce pagination.
     * @param includeOIDCScopes Include OIDC scopes as well.
     * @param requestedScopes   Requested set of scopes to be return in the response.
     * @param clientId   clientId of Oauth app .
     * @return Scope list.
     */
    public Set<Scope> getScopes(Integer startIndex, Integer count, Boolean includeOIDCScopes, String requestedScopes,
                                String clientId) throws IdentityOAuth2ScopeServerException {

        String tenantDomain;
        try {
            OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
            tenantDomain = OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            log.error("Error while getting oauth app for client Id: " + clientId, e);
            throw Oauth2ScopeUtils.generateServerException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_FAILED_TO_GET_ALL_SCOPES, e);
        }
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        return getTenantScopes(startIndex, count, includeOIDCScopes, requestedScopes, tenantId);

    }

    /**
     * Retrieve the available scope list of given tenant domain.
     *
     * @param startIndex        Start Index of the result set to enforce pagination.
     * @param count             Number of elements in the result set to enforce pagination.
     * @param includeOIDCScopes Include OIDC scopes as well.
     * @param requestedScopes   Requested set of scopes to be return in the response.
     * @param tenantId          tenantId.
     * @return Scope list.
     * @throws IdentityOAuth2ScopeServerException
     */
    public Set<Scope> getTenantScopes(Integer startIndex, Integer count, Boolean includeOIDCScopes,
                                      String requestedScopes, int tenantId)
            throws IdentityOAuth2ScopeServerException {

        Set<Scope> scopes;

        // includeOIDCScopes can be null.
        boolean includeOIDCScopesState = BooleanUtils.isTrue(includeOIDCScopes);

        // If the requested scopes are provided we won't honour pagination. Will return requested scopes only.
        if (StringUtils.isNotBlank(requestedScopes)) {
            try {
                scopes = OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO()
                        .getRequestedScopesOnly(tenantId, includeOIDCScopesState,
                                requestedScopes);
            } catch (IdentityOAuth2ScopeServerException e) {
                throw Oauth2ScopeUtils.generateServerException(Oauth2ScopeConstants.ErrorMessages.
                        ERROR_CODE_FAILED_TO_GET_REQUESTED_SCOPES, e);
            }
        } else {
            // Check for pagination query params.
            if (startIndex == null && count == null) {
                try {
                    scopes = OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO()
                            .getAllScopes(tenantId, includeOIDCScopesState);
                } catch (IdentityOAuth2ScopeServerException e) {
                    throw Oauth2ScopeUtils.generateServerException(Oauth2ScopeConstants.ErrorMessages.
                            ERROR_CODE_FAILED_TO_GET_ALL_SCOPES, e);
                }
            } else {
                // Check if it is a pagination request.
                scopes = listScopesWithPagination(startIndex, count, includeOIDCScopesState);
            }
        }
        return scopes;
    }

    /**
     * @param name Name of the scope which need to get retrieved
     * @return Retrieved Scope
     * @throws IdentityOAuth2ScopeException
     */
    public Scope getScope(String name) throws IdentityOAuth2ScopeException {

        Scope scope;
        int tenantID = Oauth2ScopeUtils.getTenantID();

        validateScopeName(name);

        scope = OAuthScopeCache.getInstance().getValueFromCache(new OAuthScopeCacheKey(name), tenantID);

        if (scope == null) {
            try {
                scope = OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO().getScopeByName(name, tenantID);
                if (scope != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Scope is getting from the database. \n" + scope.toString());
                    }
                    OAuthScopeCache.getInstance().addToCache(new OAuthScopeCacheKey(name), scope, tenantID);
                }

            } catch (IdentityOAuth2ScopeServerException e) {
                throw Oauth2ScopeUtils.generateServerException(Oauth2ScopeConstants.ErrorMessages.
                        ERROR_CODE_FAILED_TO_GET_SCOPE_BY_NAME, name, e);
            }
        }

        if (scope == null) {
            throw Oauth2ScopeUtils.generateClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_NOT_FOUND_SCOPE, name);
        }

        return scope;
    }

    /**
     * Check the existence of a scope
     *
     * @param name Name of the scope
     * @return true if scope with the given scope name exists
     * @throws IdentityOAuth2ScopeException
     */
    public boolean isScopeExists(String name) throws IdentityOAuth2ScopeException {

        boolean isScopeExists;
        int tenantID = Oauth2ScopeUtils.getTenantID();

        if (name == null) {
            throw Oauth2ScopeUtils.generateClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_NAME_NOT_SPECIFIED, null);
        }

        Scope scopeFromCache = OAuthScopeCache.getInstance()
                .getValueFromCache(new OAuthScopeCacheKey(name), tenantID);

        if (scopeFromCache != null) {
            isScopeExists = true;
        } else {
            try {
                isScopeExists = OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO().isScopeExists(name,
                        tenantID);
            } catch (IdentityOAuth2ScopeServerException e) {
                throw Oauth2ScopeUtils.generateServerException(Oauth2ScopeConstants.ErrorMessages.
                        ERROR_CODE_FAILED_TO_GET_SCOPE_BY_NAME, name, e);
            }
        }

        return isScopeExists;
    }

    /**
     * Check the existence of a scope depends on scope type. Type can be OAUTH2 scopes or OIDC scopes.
     *
     * @param name              Name of the scope.
     * @param includeOIDCScopes Include OIDC scopes as well.
     * @return True if scope with the given scope name exists.
     * @throws IdentityOAuth2ScopeException
     */
    public boolean isScopeExists(String name, boolean includeOIDCScopes) throws IdentityOAuth2ScopeException {

        boolean isScopeExists;
        int tenantID = Oauth2ScopeUtils.getTenantID();

        if (name == null) {
            throw Oauth2ScopeUtils.generateClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_NAME_NOT_SPECIFIED, null);
        }

        Scope scopeFromCache = OAuthScopeCache.getInstance()
                .getValueFromCache(new OAuthScopeCacheKey(name), tenantID);

        if (scopeFromCache != null) {
            isScopeExists = true;
        } else {
            try {
                isScopeExists = OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO().isScopeExists(name,
                        tenantID, includeOIDCScopes);
            } catch (IdentityOAuth2ScopeServerException e) {
                throw Oauth2ScopeUtils.generateServerException(Oauth2ScopeConstants.ErrorMessages.
                        ERROR_CODE_FAILED_TO_GET_SCOPE_BY_NAME, name, e);
            }
        }

        return isScopeExists;
    }

    /**
     * Delete the scope for the given scope ID
     *
     * @param name Scope ID of the scope which need to get deleted
     * @throws IdentityOAuth2ScopeException
     */
    public void deleteScope(String name) throws IdentityOAuth2ScopeException {

        validateScopeName(name);
        // Check whether a scope exists with the provided scope name which to be deleted.
        validateScopeExistence(name);

        int tenantID = Oauth2ScopeUtils.getTenantID();
        OAuthScopeCache.getInstance().clearCacheEntry(new OAuthScopeCacheKey(name), tenantID);

        try {
            OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO().deleteScopeByName(name, tenantID);
            if (log.isDebugEnabled()) {
                log.debug("Scope: " + name + " is deleted from the database.");
            }
        } catch (IdentityOAuth2ScopeServerException e) {
            throw Oauth2ScopeUtils.generateServerException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_FAILED_TO_DELETE_SCOPE_BY_NAME, name, e);
        }
    }

    /**
     * Update the scope of the given scope ID
     *
     * @param updatedScope details of updated scope
     * @return updated scope
     * @throws IdentityOAuth2ScopeException
     */
    public Scope updateScope(Scope updatedScope) throws IdentityOAuth2ScopeException {

        updateScopePreValidation(updatedScope);
        // Check whether a scope exists with the provided scope name which to be deleted.
        validateScopeExistence(updatedScope.getName());

        int tenantID = Oauth2ScopeUtils.getTenantID();
        try {
            OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO().updateScopeByName(updatedScope, tenantID);
        } catch (IdentityOAuth2ScopeServerException e) {
            throw Oauth2ScopeUtils.generateServerException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_FAILED_TO_UPDATE_SCOPE_BY_NAME, updatedScope.getName(), e);
        }

        OAuthScopeCache.getInstance().addToCache(new OAuthScopeCacheKey(updatedScope.getName()), updatedScope,
                tenantID);
        OIDCScopeClaimCache.getInstance().clearScopeClaimMap(tenantID);
        return updatedScope;
    }

    /**
     * Get OAuth scope consent given for an application by the user.
     *
     * @param userId        User Id.
     * @param appId         Application Id.
     * @param userTenantId  Tenant Id.
     * @return  {@link OAuth2ScopeConsentResponse}.
     * @throws IdentityOAuth2ScopeException
     */
    public OAuth2ScopeConsentResponse getUserConsentForApp(String userId, String appId, int userTenantId)
            throws IdentityOAuth2ScopeException {

        validateUserId(userId);
        validateAppId(appId);
        try {
             UserApplicationScopeConsentDO userConsent = OAuthTokenPersistenceFactory.getInstance()
                     .getOAuthUserConsentedScopesDAO()
                    .getUserConsentForApplication(userId, appId, userTenantId);
             OAuth2ScopeConsentResponse consentResponse = new OAuth2ScopeConsentResponse(userId, appId, userTenantId,
                     userConsent.getApprovedScopes(), userConsent.getDeniedScopes());
             if (log.isDebugEnabled()) {
                 log.debug("Successfully retrieved the user consent for userId : " + userId + " and appId: "
                         + appId + " as approved scopes : " +
                         userConsent.getApprovedScopes().stream().collect(Collectors.joining(" ")) +
                         " and denied scopes : " +
                         userConsent.getDeniedScopes().stream().collect(Collectors.joining(" ")));
             }
             return consentResponse;
        } catch (IdentityOAuth2ScopeConsentException e) {
            Oauth2ScopeConstants.ErrorMessages error = Oauth2ScopeConstants.ErrorMessages
                    .ERROR_CODE_FAILED_TO_RETRIEVE_USER_CONSENTS_FOR_APP;
            String msg = String.format(error.getMessage(), userId, appId, userTenantId);
            throw new IdentityOAuth2ScopeServerException(error.getCode(), msg, e);
        }
    }

    /**
     * Get list of scope consents given by user for all the applications.
     *
     * @param userId        User Id.
     * @param userTenantId  Tenant Id.
     * @return  List of {@link OAuth2ScopeConsentResponse} objects.
     * @throws IdentityOAuth2ScopeException
     */
    public List<OAuth2ScopeConsentResponse> getUserConsents(String userId, int userTenantId)
            throws IdentityOAuth2ScopeException {

        validateUserId(userId);
        try {
            List<UserApplicationScopeConsentDO> userConsents = OAuthTokenPersistenceFactory.getInstance()
                    .getOAuthUserConsentedScopesDAO()
                    .getUserConsents(userId, userTenantId);
            if (log.isDebugEnabled()) {
                log.debug("Successfully retrieved the user consents for userId : " + userId);
            }
            return userConsents.stream()
                    .map(consent -> new OAuth2ScopeConsentResponse(userId, consent.getAppId(), userTenantId,
                            consent.getApprovedScopes(), consent.getDeniedScopes()))
                    .collect(Collectors.toList());
        } catch (IdentityOAuth2ScopeConsentException e) {
            Oauth2ScopeConstants.ErrorMessages error = Oauth2ScopeConstants.ErrorMessages
                    .ERROR_CODE_FAILED_TO_RETRIEVE_USER_CONSENTS;
            String msg = String.format(error.getMessage(), userId, userTenantId);
            throw new IdentityOAuth2ScopeServerException(error.getCode(), msg, e);
        }
    }

    /**
     * Add an OAuth scope consent given for an application by an user.
     *
     * @param userId            User Id.
     * @param appId             Application Id.
     * @param userTenantId      Tenant Id.
     * @param approvedScopes    List of approved scopes.
     * @param deniedScopes      List of denied scopes.
     * @throws IdentityOAuth2ScopeException
     */
    public void addUserConsentForApplication(String userId, String appId, int userTenantId,
                                             List<String> approvedScopes, List<String> deniedScopes)
            throws IdentityOAuth2ScopeException {

        validateUserId(userId);
        validateAppId(appId);
        try {
            UserApplicationScopeConsentDO userApplicationScopeConsents =
                    new UserApplicationScopeConsentDO(appId, approvedScopes, deniedScopes);
            OAuthTokenPersistenceFactory.getInstance().getOAuthUserConsentedScopesDAO()
                    .addUserConsentForApplication(userId, userTenantId, userApplicationScopeConsents);
            if (log.isDebugEnabled()) {
                log.debug("Successfully added the user consent for OAuth scopes for user : " + userId +
                        " and application name : " + appId + " in tenant with id : " + userTenantId);
            }
        } catch (IdentityOAuth2ScopeConsentException e) {
            Oauth2ScopeConstants.ErrorMessages error = Oauth2ScopeConstants.ErrorMessages
                    .ERROR_CODE_FAILED_TO_ADD_USER_CONSENT_FOR_APP;
            String msg = String.format(error.getMessage(), userId, appId, userTenantId);
            throw new IdentityOAuth2ScopeServerException(error.getCode(), msg, e);
        }
    }

    /**
     * Update consent given for OAuth scopes by a user for a given application.
     *
     * @param userId            User Id.
     * @param appId             Application Id.
     * @param userTenantId      Tenant Id.
     * @param approvedScopes    List of approved scopes.
     * @param deniedScopes      List of denied scopes.
     * @throws IdentityOAuth2ScopeException
     */
    public void updateUserConsentForApplication(String userId, String appId, int userTenantId,
                                                List<String> approvedScopes, List<String> deniedScopes)
            throws IdentityOAuth2ScopeException {

        validateUserId(userId);
        validateAppId(appId);
        try {
            UserApplicationScopeConsentDO updatedUserApplicationScopeConsents =
                    new UserApplicationScopeConsentDO(appId, approvedScopes, deniedScopes);
            UserApplicationScopeConsentDO existingConsent = OAuthTokenPersistenceFactory.getInstance()
                    .getOAuthUserConsentedScopesDAO()
                    .getUserConsentForApplication(userId, updatedUserApplicationScopeConsents.getAppId(), userTenantId);
            UserApplicationScopeConsentDO consentsToBeUpdated =
                    getConsentsToBeUpdated(existingConsent, updatedUserApplicationScopeConsents);
            UserApplicationScopeConsentDO consentsToBeAdded =
                    getConsentsToBeAdded(consentsToBeUpdated, updatedUserApplicationScopeConsents);
            OAuthTokenPersistenceFactory.getInstance().getOAuthUserConsentedScopesDAO()
                    .updateExistingConsentForApplication(userId, appId, userTenantId, consentsToBeAdded,
                            consentsToBeUpdated);
            if (log.isDebugEnabled()) {
                log.debug("Successfully updated the user consent for OAuth scopes for user : " + userId +
                        " and application : " + appId + " in tenant with Id : " + userTenantId);
            }
        } catch (IdentityOAuth2ScopeConsentException e) {
            Oauth2ScopeConstants.ErrorMessages error = Oauth2ScopeConstants.ErrorMessages
                    .ERROR_CODE_FAILED_TO_UPDATE_USER_CONSENT_FOR_APP;
            String msg = String.format(error.getMessage(), userId, appId, userTenantId);
            throw new IdentityOAuth2ScopeServerException(error.getCode(), msg, e);
        }
    }

    /**
     * Revoke scope consents of a given user for a given application.
     *
     * @param userId        User Id.
     * @param appId         Application Id.
     * @param userTenantId  Tenant Id.
     * @throws IdentityOAuth2ScopeException
     */
    public void revokeUserConsentForApplication(String userId, String appId, int userTenantId)
            throws IdentityOAuth2ScopeException {

        validateUserId(userId);
        validateAppId(appId);
        try {
            OAuthTokenPersistenceFactory.getInstance().getOAuthUserConsentedScopesDAO()
                    .deleteUserConsentOfApplication(userId, appId, userTenantId);
            if (log.isDebugEnabled()) {
                log.debug("Successfully revoked the user consents for OAuth scopes for user : " + userId +
                        " and application : " + appId + " for tenant with Id : " + userTenantId);
            }
        } catch (IdentityOAuth2ScopeConsentException e) {
            Oauth2ScopeConstants.ErrorMessages error = Oauth2ScopeConstants.ErrorMessages
                    .ERROR_CODE_FAILED_TO_REVOKE_USER_CONSENT_FOR_APP;
            String msg = String.format(error.getMessage(), userId, appId, userTenantId);
            throw new IdentityOAuth2ScopeServerException(error.getCode(), msg, e);
        }
    }

    /**
     * Revoke all scope consents for the user.
     *
     * @param userId        User Id.
     * @param userTenantId  Tenant Id.
     * @throws IdentityOAuth2ScopeException
     */
    public void revokeUserConsents(String userId, int userTenantId)
            throws IdentityOAuth2ScopeException {

        validateUserId(userId);
        try {
            OAuthTokenPersistenceFactory.getInstance().getOAuthUserConsentedScopesDAO()
                    .deleteUserConsents(userId, userTenantId);
            if (log.isDebugEnabled()) {
                log.debug("Successfully deleted the user consents OAuth scopes for user : " + userId +
                        " in tenant with Id : " + userTenantId);
            }
        } catch (IdentityOAuth2ScopeConsentException e) {
            Oauth2ScopeConstants.ErrorMessages error = Oauth2ScopeConstants.ErrorMessages
                    .ERROR_CODE_FAILED_TO_REVOKE_USER_CONSENT;
            String msg = String.format(error.getMessage(), userId, userTenantId);
            throw new IdentityOAuth2ScopeServerException(error.getCode(), msg, e);
        }
    }

    /**
     * Check if user has already consented for requested scopes.
     *
     * @param userId                            User Id.
     * @param appId                             Application Id.
     * @param userTenantId                      Tenant Id.
     * @param consentRequiredScopes     List of consent required approved scopes.
     * @return true if user has already provided the consent.
     * @throws IdentityOAuth2ScopeException
     */
    public boolean hasUserProvidedConsentForAllRequestedScopes(String userId, String appId,
                                                               int userTenantId,
                                                               List<String> consentRequiredScopes)
            throws IdentityOAuth2ScopeException {

        validateUserId(userId);
        validateAppId(appId);
        try {
            if (CollectionUtils.isNotEmpty(consentRequiredScopes)) {
                UserApplicationScopeConsentDO existingConsent = OAuthTokenPersistenceFactory.getInstance()
                        .getOAuthUserConsentedScopesDAO()
                        .getUserConsentForApplication(userId, appId, userTenantId);
                consentRequiredScopes.removeAll(existingConsent.getApprovedScopes());
                consentRequiredScopes.removeAll(existingConsent.getDeniedScopes());
                return consentRequiredScopes.isEmpty();
            }
            return true;
        } catch (IdentityOAuth2ScopeConsentException e) {
            Oauth2ScopeConstants.ErrorMessages error = Oauth2ScopeConstants.ErrorMessages
                    .ERROR_CODE_FAILED_TO_CHECK_ALREADY_USER_CONSENTED;
            String msg = String.format(error.getMessage(), userId, appId,
                    userTenantId);
            throw new IdentityOAuth2ScopeServerException(error.getCode(), msg, e);
        }
    }

    /**
     * Check if the user already has an existing consent for the application.
     *
     * @param userId        User id.
     * @param appId         Application id.
     * @param userTenantId  Tenant id.
     * @return  True if user already has an existing consent.
     * @throws IdentityOAuth2ScopeException
     */
    public boolean isUserHasAnExistingConsentForApp(String userId, String appId, int userTenantId)
            throws IdentityOAuth2ScopeException {

        validateUserId(userId);
        validateAppId(appId);
        try {
            boolean consentExists = false;
            UserApplicationScopeConsentDO existingConsents = OAuthTokenPersistenceFactory.getInstance()
                    .getOAuthUserConsentedScopesDAO()
                    .getUserConsentForApplication(userId, appId, userTenantId);
            if (CollectionUtils.isNotEmpty(existingConsents.getApprovedScopes()) ||
                    CollectionUtils.isNotEmpty(existingConsents.getDeniedScopes())) {
                consentExists = true;
            }
            if (log.isDebugEnabled()) {
                log.debug("Existing consent status : " + consentExists + " for user : " + userId +
                        ", app : " + appId + " in tenant with id : " + userTenantId);
            }
            return consentExists;
        } catch (IdentityOAuth2ScopeConsentException e) {
            Oauth2ScopeConstants.ErrorMessages error = Oauth2ScopeConstants.ErrorMessages
                    .ERROR_CODE_FAILED_TO_CHECK_EXISTING_CONSENTS_FOR_USER;
            String msg = String.format(error.getMessage(), userId, appId, userTenantId);
            throw new IdentityOAuth2ScopeServerException(error.getCode(), msg, e);
        }
    }

    /**
     * Valida user id parameter.
     *
     * @param userId  User Id.
     * @throws IdentityOAuth2ScopeClientException
     */
    private void validateUserId(String userId) throws IdentityOAuth2ScopeClientException {

        if (StringUtils.isBlank(userId)) {
            throw new IdentityOAuth2ScopeClientException("User ID can't be null/empty.");
        }
    }

    /**
     * Validate application Id parameter.
     *
     * @param appId   Application Id.
     * @throws IdentityOAuth2ScopeClientException
     */
    private void validateAppId(String appId) throws IdentityOAuth2ScopeClientException {

        if (StringUtils.isBlank(appId)) {
            throw new IdentityOAuth2ScopeClientException("Application ID can't be null/empty.");
        }
    }

    /**
     * List scopes with filtering
     *
     * @param startIndex Start Index of the result set to enforce pagination
     * @param count      Number of elements in the result set to enforce pagination
     * @param includeOIDCScopes Include OIDC scopes as well.
     * @return List of available scopes
     * @throws IdentityOAuth2ScopeServerException
     */
    private Set<Scope> listScopesWithPagination(Integer startIndex, Integer count, boolean includeOIDCScopes)
            throws IdentityOAuth2ScopeServerException {

        Set<Scope> scopes;

        if (count == null || count < 0) {
            count = Oauth2ScopeConstants.MAX_FILTER_COUNT;
        }

        if (startIndex == null || startIndex < 1) {
            startIndex = 1;
        }

        // Database handles start index as 0
        if (startIndex > 0) {
            startIndex--;
        }

        try {
            scopes = OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO()
                    .getScopesWithPagination(startIndex, count, Oauth2ScopeUtils.getTenantID(), includeOIDCScopes);
        } catch (IdentityOAuth2ScopeServerException e) {
            throw Oauth2ScopeUtils.generateServerException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_FAILED_TO_GET_ALL_SCOPES_PAGINATION, e);
        }
        return scopes;
    }

    /**
     * Scope validation before adding the scope.
     *
     * @param scope Scope.
     * @throws IdentityOAuth2ScopeClientException
     */
    private void addScopePreValidation(Scope scope) throws IdentityOAuth2ScopeClientException {

        validateScopeName(scope.getName());
        validateRegex(scope.getName());
        validateDisplayName(scope.getDisplayName());
    }

    /**
     * Do the validation before updating the scope.
     *
     * @param updatedScope Updated scope.
     * @throws IdentityOAuth2ScopeClientException
     */
    private void updateScopePreValidation(Scope updatedScope) throws IdentityOAuth2ScopeClientException {

        validateScopeName(updatedScope.getName());
        validateDisplayName(updatedScope.getDisplayName());
    }

    /**
     * Check whether scope name is provided or not.
     *
     * @param scopeName Scope name.
     * @throws IdentityOAuth2ScopeClientException
     */
    private void validateScopeName(String scopeName) throws IdentityOAuth2ScopeClientException {

        // Check whether the scope name is provided.
        if (StringUtils.isBlank(scopeName)) {
            throw Oauth2ScopeUtils.generateClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_NAME_NOT_SPECIFIED, null);
        }
        validateWhiteSpaces(scopeName);
    }

    private void validateRegex(String scopeName) throws IdentityOAuth2ScopeClientException {

        Pattern regexPattern = Pattern.compile(SCOPE_VALIDATION_REGEX);
        if (!regexPattern.matcher(scopeName).matches()) {
            throw Oauth2ScopeUtils.generateClientException
                    (ERROR_CODE_BAD_REQUEST_SCOPE_NAME_NOT_SATIFIED_THE_REGEX, scopeName);
        }
    }

    /**
     * Check whether scope name contains any white spaces.
     *
     * @param scopeName Scope name.
     * @throws IdentityOAuth2ScopeClientException
     */
    private void validateWhiteSpaces(String scopeName) throws IdentityOAuth2ScopeClientException {

        // Check whether the scope name contains any white spaces.
        Pattern pattern = Pattern.compile("\\s");
        Matcher matcher = pattern.matcher(scopeName);
        boolean foundWhiteSpace = matcher.find();

        if (foundWhiteSpace) {
            throw Oauth2ScopeUtils.generateClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_NAME_CONTAINS_WHITESPACES, scopeName);
        }
    }

    /**
     * Check whether display name is provided or empty.
     *
     * @param displayName Display name.
     * @throws IdentityOAuth2ScopeClientException
     */
    private void validateDisplayName(String displayName) throws IdentityOAuth2ScopeClientException {

        // Check whether the scope display name is provided.
        if (StringUtils.isBlank(displayName)) {
            throw Oauth2ScopeUtils.generateClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_BAD_REQUEST_SCOPE_DISPLAY_NAME_NOT_SPECIFIED, null);
        }
    }

    /**
     * Check whether scope exist or not, if scope does not exist trow not found error.
     *
     * @param scopeName Scope name.
     * @throws IdentityOAuth2ScopeException
     */
    private void validateScopeExistence(String scopeName) throws IdentityOAuth2ScopeException {

        // Check whether a scope exists with the provided scope name which to be updated.
        boolean isScopeExists = isScopeExists(scopeName);
        if (!isScopeExists) {
            throw Oauth2ScopeUtils.generateClientException(Oauth2ScopeConstants.ErrorMessages.
                    ERROR_CODE_NOT_FOUND_SCOPE, scopeName);
        }
    }

    private UserApplicationScopeConsentDO getConsentsToBeUpdated(UserApplicationScopeConsentDO existingConsent,
                                                                 UserApplicationScopeConsentDO updatedConsent) {
        UserApplicationScopeConsentDO consentToBeUpdated =
                new UserApplicationScopeConsentDO(updatedConsent.getAppId());
        List<String> approvedScopes = new ArrayList<>();
        List<String> disapprovedScopes = new ArrayList<>();
        approvedScopes.addAll(updatedConsent.getApprovedScopes().stream()
                .filter(scope -> existingConsent.getDeniedScopes().contains(scope))
                .collect(Collectors.toSet()));
        disapprovedScopes.addAll(updatedConsent.getDeniedScopes().stream()
                .filter(scope -> existingConsent.getApprovedScopes().contains(scope))
                .collect(Collectors.toSet()));
        consentToBeUpdated.setApprovedScopes(approvedScopes);
        consentToBeUpdated.setDeniedScopes(disapprovedScopes);
        return consentToBeUpdated;
    }

    private UserApplicationScopeConsentDO getConsentsToBeAdded(UserApplicationScopeConsentDO consentToBeUpdated,
                                                               UserApplicationScopeConsentDO updatedConsent) {

        UserApplicationScopeConsentDO consentToBeAdded =
                new UserApplicationScopeConsentDO(updatedConsent.getAppId());
        List<String> approvedScopes = new ArrayList<String>() {{
            addAll(updatedConsent.getApprovedScopes());
        }};
        List<String> disapprovedScopes = new ArrayList<String>() {{
            addAll(updatedConsent.getDeniedScopes());
        }};
        approvedScopes.removeAll(consentToBeUpdated.getApprovedScopes());
        disapprovedScopes.removeAll(consentToBeUpdated.getDeniedScopes());
        consentToBeAdded.setApprovedScopes(approvedScopes);
        consentToBeAdded.setDeniedScopes(disapprovedScopes);
        return consentToBeAdded;
    }

    @Override
    public List<OAuth2Resource> getMetadata(List<String> scopes) throws IdentityOAuth2ScopeServerException {

        List<ScopeMetadata> scopesArray = new ArrayList<>();
        for (String scopeName : scopes) {
            try {
                Scope scope = getScope(scopeName);
                ScopeMetadata scopeMetadata = new ScopeMetadata(scope.getName(), scope.getDisplayName(),
                        scope.getDescription());
                scopesArray.add(scopeMetadata);
            } catch (IdentityOAuth2ScopeException e) {
                if (e instanceof IdentityOAuth2ScopeServerException) {
                    throw Oauth2ScopeUtils.generateServerException(Oauth2ScopeConstants.ErrorMessages.
                            ERROR_CODE_FAILED_TO_GET_SCOPE_METADATA, e);
                }
                if (log.isDebugEnabled()) {
                    log.debug("No scope found with name: " + scopeName);
                }
                if (LoggerUtils.isDiagnosticLogsEnabled()) {
                    DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new
                            DiagnosticLog.DiagnosticLogBuilder(OAuthConstants.LogConstants.OAUTH_INBOUND_SERVICE,
                            OAuthConstants.LogConstants.ActionIDs.SCOPE_VALIDATION);
                    diagnosticLogBuilder.inputParam(LogConstants.InputKeys.SCOPE, scopeName)
                            .resultMessage("No scope found for the provided scope name.")
                            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                            .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                    LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
                }
            }
        }
        if (scopesArray.isEmpty()) {
            return new ArrayList<>();
        } else {
            OAuth2Resource resource = new OAuth2Resource(OAuth2ScopeResourceName, OAuth2ScopeResourceName, scopesArray);
            return Collections.singletonList(resource);
        }
    }
}

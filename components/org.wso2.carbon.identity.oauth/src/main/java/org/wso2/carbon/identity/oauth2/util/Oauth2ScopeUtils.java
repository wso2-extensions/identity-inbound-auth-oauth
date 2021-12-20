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

package org.wso2.carbon.identity.oauth2.util;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.RoleMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.OAuthScopeBindingCache;
import org.wso2.carbon.identity.oauth.cache.OAuthScopeBindingCacheKey;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeServerException;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.bean.ScopeBinding;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.validators.OAuth2ScopeValidator;
import org.wso2.carbon.user.api.AuthorizationManager;
import org.wso2.carbon.user.api.UserStoreException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants.INTERNAL_SCOPE_PREFIX;
import static org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants.SYSTEM_SCOPE;

/**
 * Utility functions related to OAuth 2 scopes.
 */
public class Oauth2ScopeUtils {

    private static final Log log = LogFactory.getLog(Oauth2ScopeUtils.class);
    public static final String OAUTH_APP_DO_PROPERTY_NAME = "OAuthAppDO";
    private static final String OAUTH_ENABLE_SYSTEM_LEVEL_INTERNAL_SYSTEM_SCOPE_MANAGEMENT =
            "OAuth.EnableSystemLevelInternalSystemScopeManagement";
    private static final String PERMISSION_ROOT = "/permission";
    private static final String PERMISSION_BINDING_TYPE = "PERMISSION";
    private static final String ROOT = "/";
    private static final String ADMIN_PERMISSION_ROOT = "/permission/admin";
    private static final String EVERYONE_PERMISSION = "everyone_permission";
    private static final String ATTRIBUTE_SEPARATOR = FrameworkUtils.getMultiAttributeSeparator();

    public static IdentityOAuth2ScopeServerException generateServerException(Oauth2ScopeConstants.ErrorMessages
                                                                                error, String data)
            throws IdentityOAuth2ScopeServerException {

        String errorDescription;
        if (StringUtils.isNotBlank(data)) {
            errorDescription = String.format(error.getMessage(), data);
        } else {
            errorDescription = error.getMessage();
        }

        return IdentityException.error(
                IdentityOAuth2ScopeServerException.class, error.getCode(), errorDescription);
    }

    public static IdentityOAuth2ScopeServerException generateServerException(Oauth2ScopeConstants.ErrorMessages
                                                                                     error, String data, Throwable e)
            throws IdentityOAuth2ScopeServerException {

        String errorDescription;
        if (StringUtils.isNotBlank(data)) {
            errorDescription = String.format(error.getMessage(), data);
        } else {
            errorDescription = error.getMessage();
        }

        return IdentityException.error(
                IdentityOAuth2ScopeServerException.class, error.getCode(), errorDescription, e);
    }

    public static IdentityOAuth2ScopeServerException generateServerException(Oauth2ScopeConstants.ErrorMessages
                                                                                   error, Throwable e)
            throws IdentityOAuth2ScopeServerException {

        return IdentityException.error(
                IdentityOAuth2ScopeServerException.class, error.getCode(), error.getMessage(), e);
    }

    public static IdentityOAuth2ScopeClientException generateClientException(Oauth2ScopeConstants.ErrorMessages
                                                                                error, String data)
            throws IdentityOAuth2ScopeClientException {

        String errorDescription;
        if (StringUtils.isNotBlank(data)) {
            errorDescription = String.format(error.getMessage(), data);
        } else {
            errorDescription = error.getMessage();
        }

        return IdentityException.error(IdentityOAuth2ScopeClientException.class, error.getCode(), errorDescription);
    }

    public static IdentityOAuth2ScopeClientException generateClientException(Oauth2ScopeConstants.ErrorMessages error,
                                                                             String data,
                                                                             Throwable e)
            throws IdentityOAuth2ScopeClientException {

        String errorDescription;
        if (StringUtils.isNotBlank(data)) {
            errorDescription = String.format(error.getMessage(), data);
        } else {
            errorDescription = error.getMessage();
        }

        return IdentityException.error(IdentityOAuth2ScopeClientException.class, error.getCode(), errorDescription, e);
    }

    public static int getTenantID() {
        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
    }

    /**
     * Validate the scopes in the request using application scope validators.
     *
     * @param tokenReqMsgContext     If a token request, can pass an OAuthTokenReqMessageContext object.
     * @param authzReqMessageContext If an authorization request, can pass an OAuthAuthzReqMessageContext object.
     * @return TRUE if the validation successful, FALSE otherwise.
     * @throws IdentityOAuth2Exception
     */
    public static boolean validateByApplicationScopeValidator(OAuthTokenReqMessageContext tokenReqMsgContext,
                                                               OAuthAuthzReqMessageContext authzReqMessageContext)
            throws IdentityOAuth2Exception {

        String[] scopeValidators;
        OAuthAppDO oAuthAppDO;

        if (isATokenRequest(tokenReqMsgContext)) {
            oAuthAppDO = getOAuthAppDO(tokenReqMsgContext);
        } else {
            oAuthAppDO = getOAuthAppDO(authzReqMessageContext);
        }

        scopeValidators = oAuthAppDO.getScopeValidators();

        if (ArrayUtils.isEmpty(scopeValidators)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("There is no scope validator registered for %s@%s",
                        oAuthAppDO.getApplicationName(), OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO)));
            }
            return true;
        }

        List<String> appScopeValidators = new ArrayList<>(Arrays.asList(scopeValidators));
        // Return false only if iterateOAuth2ScopeValidators returned false. One more validation to do if it was true.
        if (isATokenRequest(tokenReqMsgContext)) {
            if (hasScopeValidationFailed(tokenReqMsgContext, appScopeValidators, null)) {
                return false;
            }
        } else {
            if (hasScopeValidationFailed(null, appScopeValidators, authzReqMessageContext)) {
                return false;
            }
        }

        if (!appScopeValidators.isEmpty()) {
            throw new IdentityOAuth2Exception(String.format("The scope validators %s registered for application " +
                    "%s@%s are not found in the server configuration ", StringUtils.join(appScopeValidators,
                    ", "), oAuthAppDO.getApplicationName(), OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO)));
        }
        return true;
    }

    private static boolean isATokenRequest(OAuthTokenReqMessageContext tokenReqMsgContext) {

        return tokenReqMsgContext != null;
    }

    private static OAuthAppDO getOAuthAppDO(OAuthTokenReqMessageContext tokenReqMsgContext)
            throws IdentityOAuth2Exception {

        OAuthAppDO oAuthAppDO =
                (OAuthAppDO) tokenReqMsgContext.getProperty(OAUTH_APP_DO_PROPERTY_NAME);

        if (oAuthAppDO == null) {
            try {
                if (tokenReqMsgContext.getOauth2AccessTokenReqDTO() != null) {
                    throw new IdentityOAuth2Exception("OAuth2 Access Token Request Object was null when obtaining" +
                            " OAuth Application.");
                } else {
                    oAuthAppDO = OAuth2Util.getAppInformationByClientId(
                            tokenReqMsgContext.getOauth2AccessTokenReqDTO().getClientId());
                }
            } catch (InvalidOAuthClientException e) {
                throw new IdentityOAuth2Exception("Error while retrieving OAuth application for client id: " +
                        tokenReqMsgContext.getOauth2AccessTokenReqDTO().getClientId(), e);
            }
        }
        return oAuthAppDO;
    }

    private static OAuthAppDO getOAuthAppDO(OAuthAuthzReqMessageContext authzReqMessageContext)
            throws IdentityOAuth2Exception {

        OAuthAppDO oAuthAppDO =
                (OAuthAppDO) authzReqMessageContext.getProperty(OAUTH_APP_DO_PROPERTY_NAME);

        if (oAuthAppDO == null) {
            try {
                if (authzReqMessageContext.getAuthorizationReqDTO() != null) {
                    throw new IdentityOAuth2Exception("Authorization Request Object was null when obtaining" +
                            " OAuth Application.");
                } else {
                    oAuthAppDO = OAuth2Util.getAppInformationByClientId(
                            authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey());
                }
            } catch (InvalidOAuthClientException e) {
                throw new IdentityOAuth2Exception("Error while retrieving OAuth application for client id: " +
                        authzReqMessageContext.getAuthorizationReqDTO().getConsumerKey(), e);
            }
        }
        return oAuthAppDO;
    }

    /**
     * Inverting iterateOAuth2ScopeValidators method for better readability.
     */
    private static boolean hasScopeValidationFailed(OAuthTokenReqMessageContext tokenReqMsgContext,
                                                    List<String> appScopeValidators,
                                                    OAuthAuthzReqMessageContext authzReqMessageContext)
            throws IdentityOAuth2Exception {

        return !iterateOAuth2ScopeValidators(authzReqMessageContext, tokenReqMsgContext, appScopeValidators);
    }

    /**
     * Iterate through the set of OAuth2ScopeValidators and validate the scopes in the request, considering only the
     * validators added in the OAuth App.
     *
     * @param authzReqMessageContext OAuthAuthzReqMessageContext object. tokenReqMsgContext should be null.
     * @param tokenReqMsgContext     OAuthTokenReqMessageContext object. authzReqMessageContext should be null.
     * @param appScopeValidators     Validators to be considered.
     * @return True if scopes are valid according to all the validators sent, false otherwise.
     * @throws IdentityOAuth2Exception
     */
    private static boolean iterateOAuth2ScopeValidators(OAuthAuthzReqMessageContext authzReqMessageContext,
                                                        OAuthTokenReqMessageContext tokenReqMsgContext,
                                                        List<String> appScopeValidators)
            throws IdentityOAuth2Exception {

        Set<OAuth2ScopeValidator> oAuth2ScopeValidators = OAuthServerConfiguration.getInstance()
                .getOAuth2ScopeValidators();
        // Iterate through all available scope validators.
        for (OAuth2ScopeValidator validator : oAuth2ScopeValidators) {
            // Validate the scopes from the validator only if it's configured in the OAuth app.
            if (validator != null && appScopeValidators.contains(validator.getValidatorName())) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Validating scope of token request using %s",
                            validator.getValidatorName()));
                }
                boolean isValid;
                try {
                    if (authzReqMessageContext != null) {
                        isValid = validator.validateScope(authzReqMessageContext);
                    } else {
                        isValid = validator.validateScope(tokenReqMsgContext);
                    }
                } catch (UserStoreException e) {
                    throw new IdentityOAuth2Exception("Error while validating scopes from application scope " +
                            "validator", e);
                }
                appScopeValidators.remove(validator.getValidatorName());
                if (!isValid) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Configuration to maintain backward compatibility to manage the internal system scope - permission
     * binding per tenant. By default this will be System level.
     *
     * @return  The internal scopes maintained at System level or not (maintained at tenant level).
     */
    public static boolean isSystemLevelInternalSystemScopeManagementEnabled() {

        String property = IdentityUtil.getProperty(OAUTH_ENABLE_SYSTEM_LEVEL_INTERNAL_SYSTEM_SCOPE_MANAGEMENT);
        if (StringUtils.isNotEmpty(property)) {
            return Boolean.parseBoolean(property);
        }
        return true;
    }

    public static List<Scope> getUserAllowedScopes(AuthenticatedUser authenticatedUser, String[] requestedScopes,
                                                   String clientId) {
        List<Scope> userAllowedScopes = new ArrayList<>();

        try {
            if (requestedScopes == null) {
                return new ArrayList<>();
            }
            boolean isSystemScope = ArrayUtils.contains(requestedScopes, SYSTEM_SCOPE);
            int tenantId = IdentityTenantUtil.getTenantId(authenticatedUser.getTenantDomain());
            startTenantFlow(authenticatedUser.getTenantDomain());
            AuthorizationManager authorizationManager = OAuthComponentServiceHolder.getInstance().getRealmService()
                    .getTenantUserRealm(tenantId).getAuthorizationManager();
            String[] allowedUIResourcesForUser;
            /*
            Here we handle scope validation for federated user and local user separately.
            For local users - user store is used to get user roles.
            For federated user - get user roles from user attributes.
            Note that if there is association between a federated user and local user () 'Assert identity using
            mapped local subject identifier' flag will be set as true. So authenticated user will be associated
            local user not federated user.
             */
            if (authenticatedUser.isFederatedUser()) {
                /*
                There is a flow where 'Assert identity using mapped local subject identifier' flag enabled but the
                federated user doesn't have any association in localIDP, to handle this case we check for 'Assert
                identity using mapped local subject identifier' flag and get roles from userStore.
                 */
                if (isSPAlwaysSendMappedLocalSubjectId(clientId)) {
                    allowedUIResourcesForUser = getAllowedUIResourcesOfUser(authenticatedUser, authorizationManager);
                } else {
                    // Handle not account associated federated users.
                    allowedUIResourcesForUser =
                            getAllowedUIResourcesForNotAssociatedFederatedUser(authenticatedUser, authorizationManager);
                }
            } else {
                allowedUIResourcesForUser = getAllowedUIResourcesOfUser(authenticatedUser, authorizationManager);
            }
            Set<Scope> allScopes = getScopesOfPermissionType(tenantId);
            if (ArrayUtils.contains(allowedUIResourcesForUser, ROOT) || ArrayUtils.contains(allowedUIResourcesForUser,
                    PERMISSION_ROOT)) {
                return new ArrayList<>(allScopes);
            } else if (ArrayUtils.contains(allowedUIResourcesForUser, ADMIN_PERMISSION_ROOT)) {
                return new ArrayList<>(getAdminAllowedScopes(allScopes, requestedScopes));
            }

            for (Scope scope : allScopes) {
                if (!isSystemScope && !ArrayUtils.contains(requestedScopes, scope.getName())) {
                    continue;
                }
                List<ScopeBinding> bindings = scope.getScopeBindings();
                boolean isScopeAllowed = true;
                for (ScopeBinding scopeBinding : bindings) {
                    if (PERMISSION_BINDING_TYPE.equalsIgnoreCase(scopeBinding.getBindingType())) {
                        for (String binding : scopeBinding.getBindings()) {
                            boolean isAllowed = false;
                            for (String allowedScope : allowedUIResourcesForUser) {
                                if ((binding + "/").startsWith(allowedScope + "/")) {
                                    isAllowed = true;
                                    break;
                                }
                            }
                            if (!isAllowed) {
                                isScopeAllowed = false;
                                break;
                            }
                        }
                    }
                }

                if (isScopeAllowed) {
                    userAllowedScopes.add(scope);
                }
            }
        } catch (UserStoreException e) {
            log.error("Error while accessing Authorization Manager.", e);
        } catch (IdentityOAuth2Exception e) {
            log.error("Error while accessing identity provider manager.", e);
        } catch (IdentityOAuth2ScopeServerException e) {
            log.error("Error while retrieving oAuth2 scopes.", e);
        } catch (UserIdNotFoundException e) {
            log.error("User id not available for user: " + authenticatedUser.getLoggableUserId(), e);
        } finally {
            endTenantFlow();
        }
        return userAllowedScopes;
    }

    private static void startTenantFlow(String tenantDomain) {

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(IdentityTenantUtil.getTenantId(tenantDomain));
    }

    private static void endTenantFlow() {

        PrivilegedCarbonContext.endTenantFlow();
    }

    private static boolean isSPAlwaysSendMappedLocalSubjectId(String clientId) throws IdentityOAuth2Exception {

        ServiceProvider serviceProvider = OAuth2Util.getServiceProvider(clientId);
        if (serviceProvider != null) {
            ClaimConfig claimConfig = serviceProvider.getClaimConfig();
            if (claimConfig != null) {
                return claimConfig.isAlwaysSendMappedLocalSubjectId();
            }
            throw new IdentityOAuth2Exception(
                    "Unable to find claim configuration for service provider of client id " + clientId);
        }
        throw new IdentityOAuth2Exception("Unable to find service provider for client id " + clientId);
    }

    private static String[] getAllowedUIResourcesOfUser(AuthenticatedUser authenticatedUser,
                                                        AuthorizationManager authorizationManager)
            throws UserStoreException, UserIdNotFoundException {

        String username = authenticatedUser.getUserName();
        if (username == null) {
            username = OAuth2Util
                    .resolveUsernameFromUserId(authenticatedUser.getTenantDomain(), authenticatedUser.getUserId());
        }
        String[] allowedUIResourcesForUser =
                authorizationManager.getAllowedUIResourcesForUser(username, "/");
        return (String[]) ArrayUtils.add(allowedUIResourcesForUser, EVERYONE_PERMISSION);
    }

    private static Set<Scope> getScopesOfPermissionType(int tenantId) throws IdentityOAuth2ScopeServerException {

        if (Oauth2ScopeUtils.isSystemLevelInternalSystemScopeManagementEnabled()) {
            List<Scope> oauthScopeBinding = OAuth2ServiceComponentHolder.getInstance().getOauthScopeBinding();
            return new HashSet<>(oauthScopeBinding);
        }
        Scope[] scopesFromCache = OAuthScopeBindingCache.getInstance()
                .getValueFromCache(new OAuthScopeBindingCacheKey(PERMISSION_BINDING_TYPE), tenantId);
        Set<Scope> allScopes;
        if (scopesFromCache != null) {
            allScopes = Arrays.stream(scopesFromCache).collect(Collectors.toSet());
        } else {
            allScopes = OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO().getScopes(tenantId,
                    PERMISSION_BINDING_TYPE);
            if (CollectionUtils.isNotEmpty(allScopes)) {
                OAuthScopeBindingCache.getInstance().addToCache(new OAuthScopeBindingCacheKey(PERMISSION_BINDING_TYPE
                ), allScopes.toArray(new Scope[0]), tenantId);
            }
        }
        return allScopes;
    }

    private static Set<Scope> getAdminAllowedScopes(Set<Scope> allScopes, String[] requestedScopes) {

        Set<Scope> adminAllowedScopes = new HashSet<>(allScopes);
        for (Scope scope : allScopes) {
            if (!ArrayUtils.contains(requestedScopes, scope.getName())) {
                continue;
            }
            List<ScopeBinding> scopeBindings = scope.getScopeBindings();
            for (ScopeBinding scopeBinding : scopeBindings) {
                if (PERMISSION_BINDING_TYPE.equalsIgnoreCase(scopeBinding.getBindingType())) {
                    List<String> bindings = scopeBinding.getBindings();
                    for (String binding : bindings) {
                        if (!binding.startsWith(ADMIN_PERMISSION_ROOT) && !binding.equals(EVERYONE_PERMISSION)) {
                            adminAllowedScopes.remove(scope);
                            break;
                        }
                    }
                }
            }
        }
        return adminAllowedScopes;
    }

    /**
     * Method user to get list of federated users permissions using idp role mapping for not account associated
     * federated users.
     * @param authenticatedUser    FederatedAuthenticatedUser
     * @param authorizationManager AuthorizationManager
     * @return List of permissions
     * @throws UserStoreException      UserStoreException
     * @throws IdentityOAuth2Exception IdentityOAuth2Exception
     */
    private static String[] getAllowedUIResourcesForNotAssociatedFederatedUser(AuthenticatedUser authenticatedUser,
            AuthorizationManager authorizationManager) throws UserStoreException, IdentityOAuth2Exception {

        List<String> userRolesList = new ArrayList<>();
        List<String> allowedUIResourcesListForUser = new ArrayList<>();
        IdentityProvider identityProvider =
                OAuth2Util.getIdentityProvider(authenticatedUser.getFederatedIdPName(),
                        authenticatedUser.getTenantDomain());
        /*
        Values of Groups consists mapped local roles and Internal/everyone corresponding to
        authenticated user.
        Role mapping consists mapped federated roles with local roles corresponding to IDP.
        By cross checking role mapped local roles and values of groups we can filter valid local roles which mapped
        to a federated role of authenticated user.
         */
        List<String> valuesOfGroups = getValuesOfGroupsFromUserAttributes(authenticatedUser.getUserAttributes());
        if (CollectionUtils.isNotEmpty(valuesOfGroups)) {
            for (RoleMapping roleMapping : identityProvider.getPermissionAndRoleConfig().getRoleMappings()) {
                if (roleMapping != null && roleMapping.getLocalRole() != null) {
                    if (valuesOfGroups.contains(roleMapping.getLocalRole().getLocalRoleName())) {
                        userRolesList.add(roleMapping.getLocalRole().getLocalRoleName());
                    }
                }
            }
        }
        // Loop through each local role and get permissions.
        for (String userRole : userRolesList) {
            for (String allowedUIResource : authorizationManager.getAllowedUIResourcesForRole(userRole, "/")) {
                if (!allowedUIResourcesListForUser.contains(allowedUIResource)) {
                    allowedUIResourcesListForUser.add(allowedUIResource);
                }
            }
        }
        // Add everyone permission to allowed permission.
        allowedUIResourcesListForUser.add(EVERYONE_PERMISSION);

        return allowedUIResourcesListForUser.toArray(new String[0]);
    }

    /**
     * Get groups params Roles from User attributes.
     *
     * @param userAttributes User Attributes
     * @return User attribute map
     */
    private static List<String> getValuesOfGroupsFromUserAttributes(Map<ClaimMapping, String> userAttributes) {

        if (MapUtils.isNotEmpty(userAttributes)) {
            for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                if (entry.getKey().getRemoteClaim() != null) {
                    if (StringUtils.equals(entry.getKey().getRemoteClaim().getClaimUri(), OAuth2Constants.GROUPS)) {
                        return Arrays.asList(entry.getValue().split(Pattern.quote(ATTRIBUTE_SEPARATOR)));
                    }
                }
            }
        }
        return null;
    }

    public static String[] getScopes(List<Scope> scopes) {

        return scopes.stream()
                .map(Scope::getName).toArray(String[]::new);
    }

    public static String[] getRequestedScopes(String[] scopes) {

        List<String> requestedScopes = new ArrayList<>();
        if (scopes == null) {
            return null;
        }
        for (String scope : scopes) {
            if (scope.startsWith(INTERNAL_SCOPE_PREFIX) || scope.equalsIgnoreCase(SYSTEM_SCOPE)) {
                requestedScopes.add(scope);
            }
        }
        return requestedScopes.toArray(new String[0]);
    }
}
